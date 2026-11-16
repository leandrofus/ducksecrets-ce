package dynamic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var (
	unixUsernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	unixShellRe    = regexp.MustCompile(`^/[a-zA-Z0-9._/-]+$`)
	unixGroupsRe   = regexp.MustCompile(`^[a-zA-Z0-9_,-]+$`)
)

type PAMConfig struct {
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	// Mode can be "tunnel" (remote SSH TCP relay, no host scripts), "local" (uses host useradd/userdel), "command" (runs custom script/hook), or "simulated"
	Mode         string `json:"mode"`
	DefaultShell string `json:"default_shell,omitempty"`
	Groups       string `json:"groups,omitempty"` // Comma-separated groups e.g. "developers,docker"
	SudoAccess   bool   `json:"sudo_access,omitempty"`
	// ProvisionCmd overrides useradd with a custom command (template: {{username}}, {{password}}, {{expiry}})
	ProvisionCmd string `json:"provision_cmd,omitempty"`
	// RevokeCmd overrides userdel with a custom command (template: {{username}})
	RevokeCmd string `json:"revoke_cmd,omitempty"`
}

type PAMDriver struct{}

func init() {
	RegisterDriver(&PAMDriver{})
}

func (d *PAMDriver) Engine() string {
	return "pam"
}

func (d *PAMDriver) ValidateConfig(configJSON []byte) error {
	var cfg PAMConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return fmt.Errorf("parsing PAM config: %w", err)
	}
	if cfg.Mode == "" {
		cfg.Mode = "local"
	}
	switch cfg.Mode {
	case "tunnel", "local", "command", "simulated":
		if cfg.DefaultShell != "" && !unixShellRe.MatchString(cfg.DefaultShell) {
			return fmt.Errorf("invalid default_shell %q", cfg.DefaultShell)
		}
		if cfg.Groups != "" && !unixGroupsRe.MatchString(cfg.Groups) {
			return fmt.Errorf("invalid groups %q", cfg.Groups)
		}
		return nil
	default:
		return fmt.Errorf("unsupported PAM mode %q (must be 'tunnel', 'local', 'command', or 'simulated')", cfg.Mode)
	}
}

func (d *PAMDriver) Test(ctx context.Context, configJSON []byte) error {
	var cfg PAMConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return err
	}
	if cfg.Mode == "" {
		cfg.Mode = "local"
	}
	if cfg.Mode == "local" {
		if _, err := exec.LookPath("useradd"); err != nil {
			return fmt.Errorf("useradd not found for local PAM mode: %w", err)
		}
	}
	return nil
}

func (d *PAMDriver) IssueLease(ctx context.Context, configJSON []byte, roleTemplate, username, password string, ttl time.Duration) (*LeaseCredentials, error) {
	var cfg PAMConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, err
	}
	if cfg.Mode == "" {
		cfg.Mode = "local"
	}

	expiryDate := time.Now().Add(ttl).Format("2006-01-02")
	shell := cfg.DefaultShell
	if shell == "" {
		shell = "/bin/bash"
	}

	switch cfg.Mode {
	case "command":
		if !unixUsernameRe.MatchString(username) {
			return nil, fmt.Errorf("invalid unix username %q", username)
		}
		if cfg.ProvisionCmd == "" {
			return nil, fmt.Errorf("mode 'command' requires provision_cmd")
		}
		cmdStr := cfg.ProvisionCmd
		cmdStr = strings.ReplaceAll(cmdStr, "{{username}}", "$DUCKSECRETS_PAM_USERNAME")
		cmdStr = strings.ReplaceAll(cmdStr, "{{password}}", "$DUCKSECRETS_PAM_PASSWORD")
		cmdStr = strings.ReplaceAll(cmdStr, "{{expiry}}", "$DUCKSECRETS_PAM_EXPIRY")
		cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
		cmd.Env = append(cmd.Environ(),
			"DUCKSECRETS_PAM_USERNAME="+username,
			"DUCKSECRETS_PAM_PASSWORD="+password,
			"DUCKSECRETS_PAM_EXPIRY="+expiryDate,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("running PAM provision command: %s (%w)", string(out), err)
		}

	case "local":
		if !unixUsernameRe.MatchString(username) {
			return nil, fmt.Errorf("invalid unix username %q", username)
		}
		if cfg.DefaultShell != "" && !unixShellRe.MatchString(cfg.DefaultShell) {
			return nil, fmt.Errorf("invalid default_shell %q", cfg.DefaultShell)
		}
		if cfg.Groups != "" && !unixGroupsRe.MatchString(cfg.Groups) {
			return nil, fmt.Errorf("invalid groups %q", cfg.Groups)
		}
		useraddPath, err := exec.LookPath("useradd")
		if err != nil {
			return nil, fmt.Errorf("useradd not found for local PAM mode: %w", err)
		}
		args := []string{"-M", "-s", shell, "-e", expiryDate}
		if cfg.Groups != "" {
			args = append(args, "-G", cfg.Groups)
		}
		args = append(args, username)
		cmd := exec.CommandContext(ctx, useraddPath, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("useradd failed: %s (%w)", string(out), err)
		}
		passCmd := exec.CommandContext(ctx, "chpasswd")
		passCmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s\n", username, password))
		if out, err := passCmd.CombinedOutput(); err != nil {
			_ = exec.CommandContext(context.Background(), "userdel", "-f", username).Run()
			return nil, fmt.Errorf("chpasswd failed: %s (%w)", string(out), err)
		}

	case "tunnel":
		// Remote SSH TCP tunnel relay (no local host OS script execution)

	case "simulated":
		// Pure simulated mode for testing or mock server environments
	}

	authType := "pam_unix"
	if cfg.Mode == "tunnel" {
		authType = "ssh_tunnel"
	}
	extra := map[string]string{
		"auth_type":   authType,
		"expiry_date": expiryDate,
		"shell":       shell,
	}
	if cfg.Groups != "" {
		extra["groups"] = cfg.Groups
	}
	if cfg.SudoAccess {
		extra["sudo"] = "true"
	}

	connString := ""
	if cfg.Host != "" {
		port := cfg.Port
		if port == 0 {
			port = 22
		}
		if port == 22 {
			connString = fmt.Sprintf("ssh %s@%s", username, cfg.Host)
		} else {
			connString = fmt.Sprintf("ssh -p %d %s@%s", port, username, cfg.Host)
		}
	}

	return &LeaseCredentials{
		Username:   username,
		Password:   password,
		ConnString: connString,
		Engine:     d.Engine(),
		Extra:      extra,
	}, nil
}

func (d *PAMDriver) RevokeLease(ctx context.Context, configJSON []byte, username string) error {
	var cfg PAMConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return err
	}
	if cfg.Mode == "" {
		cfg.Mode = "local"
	}

	switch cfg.Mode {
	case "command":
		if !unixUsernameRe.MatchString(username) {
			return fmt.Errorf("invalid unix username %q", username)
		}
		if cfg.RevokeCmd != "" {
			cmdStr := strings.ReplaceAll(cfg.RevokeCmd, "{{username}}", "$DUCKSECRETS_PAM_USERNAME")
			cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
			cmd.Env = append(cmd.Environ(), "DUCKSECRETS_PAM_USERNAME="+username)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("running PAM revoke command: %s (%w)", string(out), err)
			}
		}
	case "local":
		if !unixUsernameRe.MatchString(username) {
			return fmt.Errorf("invalid unix username %q", username)
		}
		// Terminate any active sessions for the user (exit code 1 means no matching processes)
		if _, err := exec.LookPath("pkill"); err == nil {
			if out, err := exec.CommandContext(ctx, "pkill", "-u", username).CombinedOutput(); err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
					return fmt.Errorf("pkill failed: %s (%w)", string(out), err)
				}
			}
		}
		// Delete user
		userdelPath, err := exec.LookPath("userdel")
		if err != nil {
			return fmt.Errorf("userdel not found for local PAM mode: %w", err)
		}
		if out, err := exec.CommandContext(ctx, userdelPath, "-f", "-r", username).CombinedOutput(); err != nil {
			if !strings.Contains(string(out), "does not exist") {
				return fmt.Errorf("userdel failed: %s (%w)", string(out), err)
			}
		}
	case "simulated", "tunnel":
		// No-op for simulated and tunnel relay modes
	}

	return nil
}
