// Command ducksecrets is the lightweight client CLI for developers and CI/CD.
// It connects to a DuckSecrets daemon to inject or export secrets.
//
// Strictly decoupled from the server: imports NO database, server, or web packages.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"golang.org/x/crypto/pbkdf2"
)

var version = "dev"

const (
	defaultServerURL = "http://127.0.0.1:5179"
	configFileName   = "config.json"
)

type cliConfig struct {
	ServerURL      string `json:"server_url"`
	Username       string `json:"username,omitempty"`
	Token          string `json:"token"`
	Project        string `json:"project,omitempty"`
	Env            string `json:"env,omitempty"`
	CACert         string `json:"ca_cert,omitempty"`
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
	InsecureTLS    bool   `json:"insecure_tls,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "version", "--version", "-v":
		fmt.Printf("ducksecrets cli version %s\n", version)
	case "login":
		runLogin(args)
	case "connect":
		runConnect(args)
	case "run":
		runExec(args)
	case "export":
		runExport(args)
	case "share":
		runShare(args)
	case "dynamic":
		runDynamic(args)
	case "creds", "cred", "credentials":
		runCreds(args)
	case "site":
		runSite(args)
	case "rotate":
		runRotate(args)
	case "wrap":
		runWrap(args)
	case "update", "self-update":
		runUpdate(args)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\nRun 'ducksecrets --help' for usage.\n", cmd)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`DuckSecrets CLI — Lightweight Secret Injection & Management

Usage:
  ducksecrets <command> [arguments]

Commands:
  connect   Open a managed localhost tunnel to a database (Postgres, MySQL, Redis)
  site      Manage and run Site Connectors for reverse tunnels to isolated private networks
  run       Execute a command with secrets injected into its environment
  export    Export secrets to stdout (.env, json, yaml)
  share     Create or reveal zero-knowledge ephemeral one-time secrets (burn-after-reading)
  creds     Manage structured credentials (get, set, list, connect, delete) for SSH, TLS, OAuth, and Logins
  dynamic   Request, inspect, or revoke ephemeral dynamic credentials (Postgres, MySQL, Redis, PAM)
  rotate    Trigger automated secret rotation with rollback verification probe
  wrap      Wrap an existing container image with DuckSecrets runtime injection
  update    Self-update CLI from the latest public release on GitHub
  login     Authenticate with username/password or service token
  version   Print CLI version

Global flags can be passed via environment variables:
  DUCKSECRETS_SERVER           Daemon URL (default: http://127.0.0.1:5179)
  DUCKSECRETS_TOKEN            Service token or machine identity (duck_st_*)
  DUCKSECRETS_PROJECT          Default project slug
  DUCKSECRETS_ENV              Default environment (dev, staging, prod)
  DUCKSECRETS_CA_CERT          Path to custom CA or pinned server certificate PEM
  DUCKSECRETS_TLS_FINGERPRINT  Expected leaf TLS certificate SHA-256 hex fingerprint
  DUCKSECRETS_INSECURE         Set to 1/true to skip TLS certificate verification

Run 'ducksecrets <command> --help' for details on a specific command.
`)
}

func configPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".ducksecrets", configFileName)
}

func parseEnvBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func applyDefaultsFile(cfg *cliConfig, envServer string, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var fileCfg cliConfig
	if err := json.Unmarshal(data, &fileCfg); err != nil {
		return
	}
	if envServer == "" && cfg.ServerURL == defaultServerURL && fileCfg.ServerURL != "" {
		cfg.ServerURL = fileCfg.ServerURL
	}
	sameServer := strings.TrimRight(cfg.ServerURL, "/") == strings.TrimRight(fileCfg.ServerURL, "/")
	if sameServer || fileCfg.ServerURL == "" {
		if cfg.CACert == "" && fileCfg.CACert != "" {
			cfg.CACert = fileCfg.CACert
		}
		if cfg.TLSFingerprint == "" && fileCfg.TLSFingerprint != "" {
			cfg.TLSFingerprint = fileCfg.TLSFingerprint
		}
	}
}

func loadConfig() cliConfig {
	var cfg cliConfig
	envServer := os.Getenv("DUCKSECRETS_SERVER")
	cfg.ServerURL = envServer
	if cfg.ServerURL == "" {
		cfg.ServerURL = defaultServerURL
	}
	cfg.Token = os.Getenv("DUCKSECRETS_TOKEN")
	cfg.Project = os.Getenv("DUCKSECRETS_PROJECT")
	cfg.Env = os.Getenv("DUCKSECRETS_ENV")
	cfg.CACert = os.Getenv("DUCKSECRETS_CA_CERT")
	cfg.TLSFingerprint = os.Getenv("DUCKSECRETS_TLS_FINGERPRINT")
	cfg.InsecureTLS = parseEnvBool(os.Getenv("DUCKSECRETS_INSECURE"))

	path := configPath()
	if data, err := os.ReadFile(path); err == nil {
		var fileCfg cliConfig
		if err := json.Unmarshal(data, &fileCfg); err == nil {
			if cfg.ServerURL == defaultServerURL && fileCfg.ServerURL != "" {
				cfg.ServerURL = fileCfg.ServerURL
			}
			if cfg.Token == "" {
				cfg.Token = fileCfg.Token
			}
			if cfg.Project == "" {
				cfg.Project = fileCfg.Project
			}
			if cfg.Env == "" {
				cfg.Env = fileCfg.Env
			}
			if cfg.CACert == "" {
				cfg.CACert = fileCfg.CACert
			}
			if cfg.TLSFingerprint == "" {
				cfg.TLSFingerprint = fileCfg.TLSFingerprint
			}
			if !cfg.InsecureTLS && os.Getenv("DUCKSECRETS_INSECURE") == "" {
				cfg.InsecureTLS = fileCfg.InsecureTLS
			}
		}
	}

	// Fallback to installer-managed CLI server/TLS defaults (user first, then system-wide)
	applyDefaultsFile(&cfg, envServer, filepath.Join(filepath.Dir(path), "cli.json"))
	applyDefaultsFile(&cfg, envServer, "/etc/ducksecrets/cli.json")

	return cfg
}

func saveConfig(cfg cliConfig) error {
	path := configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

type tlsFlagValues struct {
	caCert      *string
	fingerprint *string
	insecure    *bool
}

func registerTLSFlags(fs *flag.FlagSet) tlsFlagValues {
	return tlsFlagValues{
		caCert:      fs.String("ca-cert", "", "Path to custom CA or pinned server certificate PEM"),
		fingerprint: fs.String("tls-fingerprint", "", "Expected leaf TLS certificate SHA-256 hex fingerprint"),
		insecure:    fs.Bool("insecure", false, "Skip TLS certificate verification (not recommended)"),
	}
}

func applyTLSFlags(cfg *cliConfig, tf tlsFlagValues) {
	if tf.caCert != nil && *tf.caCert != "" {
		cfg.CACert = *tf.caCert
	}
	if tf.fingerprint != nil && *tf.fingerprint != "" {
		cfg.TLSFingerprint = *tf.fingerprint
	}
	if tf.insecure != nil && *tf.insecure {
		cfg.InsecureTLS = true
	}
}

// buildTLSConfig constructs custom TLS verification settings when the user provides
// --ca-cert, --tls-fingerprint, --insecure, or installer-managed cli.json trust defaults.
// Returns nil to use system defaults.
func buildTLSConfig(cfg cliConfig) (*tls.Config, error) {
	if cfg.CACert == "" && cfg.TLSFingerprint == "" && !cfg.InsecureTLS && cfg.ServerURL != "" {
		path := configPath()
		applyDefaultsFile(&cfg, cfg.ServerURL, filepath.Join(filepath.Dir(path), "cli.json"))
		applyDefaultsFile(&cfg, cfg.ServerURL, "/etc/ducksecrets/cli.json")
	}
	if cfg.CACert == "" && cfg.TLSFingerprint == "" && !cfg.InsecureTLS {
		return nil, nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.InsecureTLS {
		tlsCfg.InsecureSkipVerify = true
		return tlsCfg, nil
	}
	if cfg.TLSFingerprint != "" {
		expected := strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(cfg.TLSFingerprint)))
		if len(expected) != 64 {
			return nil, fmt.Errorf("invalid TLS SHA-256 fingerprint %q (expected 64 hex chars)", cfg.TLSFingerprint)
		}
		if _, err := hex.DecodeString(expected); err != nil {
			return nil, fmt.Errorf("invalid TLS SHA-256 fingerprint %q: %w", cfg.TLSFingerprint, err)
		}
		// Leaf-cert SHA-256 pinning verifies exact server key identity even over NAT/Tailscale IPs.
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("server presented no TLS certificates")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if got != expected {
				return fmt.Errorf("TLS certificate fingerprint mismatch: got %s, want %s", got, expected)
			}
			return nil
		}
		return tlsCfg, nil
	}

	pemBytes, err := os.ReadFile(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate %q: %w", cfg.CACert, err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no valid PEM certificates found in %q", cfg.CACert)
	}
	tlsCfg.RootCAs = pool
	return tlsCfg, nil
}

func newHTTPClient(cfg cliConfig, timeout time.Duration) (*http.Client, error) {
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	if tlsCfg == nil {
		return &http.Client{Timeout: timeout}, nil
	}
	var tr *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok && base != nil {
		tr = base.Clone()
	} else {
		tr = &http.Transport{}
	}
	tr.TLSClientConfig = tlsCfg
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

func dialWebSocket(ctx context.Context, wsURL string, cfg cliConfig, header http.Header) (*websocket.Conn, *http.Response, error) {
	client, err := newHTTPClient(cfg, 0)
	if err != nil {
		return nil, nil, err
	}
	return websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: header,
		HTTPClient: client,
	})
}

func applyAuthHeaders(req *http.Request, token string) {
	if token == "" {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.AddCookie(&http.Cookie{Name: "ducksecrets_session", Value: token})
}

func readLinePrompt(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func readPasswordPrompt(prompt string) string {
	fmt.Print(prompt)
	if info, err := os.Stdin.Stat(); err == nil && (info.Mode()&os.ModeCharDevice) != 0 {
		tty, ttyErr := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if ttyErr == nil {
			defer tty.Close()
			off := exec.Command("stty", "-echo")
			off.Stdin = tty
			_ = off.Run()
			defer func() {
				on := exec.Command("stty", "echo")
				on.Stdin = tty
				_ = on.Run()
				fmt.Println()
			}()
			line, _ := bufio.NewReader(tty).ReadString('\n')
			return strings.TrimRight(line, "\r\n")
		}
	}
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func loginWithCredentials(cfg cliConfig, username, password string) (string, error) {
	payload, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		return "", err
	}
	loginURL := strings.TrimRight(cfg.ServerURL, "/") + "/api/v1/auth/login"
	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ducksecrets-Request", "1")

	client, err := newHTTPClient(cfg, 15*time.Second)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("authentication failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	for _, c := range resp.Cookies() {
		if c.Name == "ducksecrets_session" && c.Value != "" {
			return c.Value, nil
		}
	}
	return "", fmt.Errorf("server returned 200 OK without ducksecrets_session cookie")
}

func runLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "", "DuckSecrets daemon server URL")
	userFlag := fs.String("user", "", "Username for password authentication")
	usernameFlag := fs.String("username", "", "Alias for --user")
	passFlag := fs.String("password", "", "Password for user authentication (prompted hidden if omitted)")
	token := fs.String("token", "", "Service token or user API token (duck_st_*)")
	tf := registerTLSFlags(fs)
	fs.Parse(args)

	cfg := loadConfig()
	if *server != "" {
		cfg.ServerURL = strings.TrimRight(*server, "/")
	}
	applyTLSFlags(&cfg, tf)

	username := strings.TrimSpace(*userFlag)
	if username == "" {
		username = strings.TrimSpace(*usernameFlag)
	}

	if *token != "" {
		cfg.Token = strings.TrimSpace(*token)
		cfg.Username = ""
	} else {
		if username == "" && *passFlag == "" {
			username = readLinePrompt("Username (leave empty for token auth): ")
		}
		if username != "" || *passFlag != "" {
			if username == "" {
				username = readLinePrompt("Username: ")
			}
			password := *passFlag
			if password == "" {
				password = readPasswordPrompt("Password: ")
			}
			if username == "" || password == "" {
				fmt.Fprintln(os.Stderr, "error: username and password cannot be empty")
				os.Exit(1)
			}
			sessionTok, err := loginWithCredentials(cfg, username, password)
			if err != nil {
				fmt.Fprintf(os.Stderr, "login error: %v\n", err)
				os.Exit(1)
			}
			cfg.Token = sessionTok
			cfg.Username = username
		} else {
			cfg.Token = readLinePrompt("Enter DuckSecrets token (duck_st_*): ")
			cfg.Username = ""
		}
	}

	if cfg.Token == "" {
		fmt.Fprintln(os.Stderr, "error: token or credentials cannot be empty")
		os.Exit(1)
	}

	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "failed to save configuration: %v\n", err)
		os.Exit(1)
	}
	if cfg.Username != "" {
		fmt.Printf("Signed in as '%s' against %s (saved to %s)\n", cfg.Username, cfg.ServerURL, configPath())
	} else {
		fmt.Printf("Authenticated successfully with token against %s (saved to %s)\n", cfg.ServerURL, configPath())
	}
}

func resolveProjectEnv(cfg *cliConfig, projectFlag, envFlag string) {
	if projectFlag != "" {
		cfg.Project = projectFlag
	}
	if cfg.Project == "" {
		cfg.Project = "default"
	}
	if envFlag != "" {
		cfg.Env = envFlag
	}
	if cfg.Env == "" {
		cfg.Env = "dev"
	}
}

func escapeExportValue(val string) string {
	escaped := strings.ReplaceAll(val, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, "\r", `\r`)
	escaped = strings.ReplaceAll(escaped, "\n", `\n`)
	return escaped
}

func formatExportSecrets(secrets map[string]string, format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		b, err := json.MarshalIndent(secrets, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	case "yaml", "yml":
		keys := make([]string, 0, len(secrets))
		for k := range secrets {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%s: \"%s\"\n", k, escapeExportValue(secrets[k]))
		}
		return b.String(), nil
	case "dotenv", "env", "":
		fallthrough
	default:
		keys := make([]string, 0, len(secrets))
		for k := range secrets {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%s=\"%s\"\n", k, escapeExportValue(secrets[k]))
		}
		return b.String(), nil
	}
}

func sameOriginURL(a, b string) bool {
	ua, errA := url.Parse(strings.TrimSpace(a))
	ub, errB := url.Parse(strings.TrimSpace(b))
	if errA != nil || errB != nil || ua.Host == "" || ub.Host == "" {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

func runExec(args []string) {
	// Look for the "--" separator
	var cliArgs, cmdArgs []string
	sepIdx := -1
	for i, arg := range args {
		if arg == "--" {
			sepIdx = i
			break
		}
	}
	if sepIdx != -1 {
		cliArgs = args[:sepIdx]
		cmdArgs = args[sepIdx+1:]
	} else {
		cliArgs = args
	}

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	project := fs.String("project", "", "Project slug")
	envName := fs.String("env", "", "Environment slug (default from config/DUCKSECRETS_ENV or dev)")
	folder := fs.String("path", "/", "Secret folder path")
	tf := registerTLSFlags(fs)
	fs.Parse(cliArgs)

	if len(cmdArgs) == 0 && fs.NArg() > 0 {
		cmdArgs = fs.Args()
	}
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: no command specified to run. Usage: ducksecrets run -- <command> [args...]")
		os.Exit(1)
	}

	cfg := loadConfig()
	applyTLSFlags(&cfg, tf)
	resolveProjectEnv(&cfg, *project, *envName)

	secrets, err := fetchSecrets(cfg, *folder)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load secrets from %s: %v\n", cfg.ServerURL, err)
		os.Exit(1)
	}

	// Prepare child process environment
	childEnv := os.Environ()
	for k, v := range secrets {
		childEnv = append(childEnv, fmt.Sprintf("%s=%s", k, v))
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = childEnv
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "command execution failed: %v\n", err)
		os.Exit(1)
	}
}

func runExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	project := fs.String("project", "", "Project slug")
	envName := fs.String("env", "", "Environment slug (default from config/DUCKSECRETS_ENV or dev)")
	folder := fs.String("path", "/", "Secret folder path")
	format := fs.String("format", "dotenv", "Output format: dotenv, json, yaml")
	tf := registerTLSFlags(fs)
	fs.Parse(args)

	cfg := loadConfig()
	applyTLSFlags(&cfg, tf)
	resolveProjectEnv(&cfg, *project, *envName)

	secrets, err := fetchSecrets(cfg, *folder)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to export secrets: %v\n", err)
		os.Exit(1)
	}

	out, err := formatExportSecrets(secrets, *format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to format secrets: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(out)
}

func fetchSecrets(cfg cliConfig, folder string) (map[string]string, error) {
	resolveProjectEnv(&cfg, "", "")
	targetURL := fmt.Sprintf("%s/api/v1/projects/%s/environments/%s/secrets/export?format=json&path=%s",
		strings.TrimRight(cfg.ServerURL, "/"), url.PathEscape(cfg.Project), url.PathEscape(cfg.Env), url.QueryEscape(folder))

	client, err := newHTTPClient(cfg, 10*time.Second)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	applyAuthHeaders(req, cfg.Token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func runShare(args []string) {
	if len(args) > 0 && args[0] == "get" {
		runShareGet(args[1:])
		return
	}

	fs := flag.NewFlagSet("share", flag.ExitOnError)
	filePath := fs.String("file", "", "File path containing secret content to share")
	ttlStr := fs.String("ttl", "24h", "Time-to-live before expiration (e.g. 5m, 1h, 24h, 7d)")
	views := fs.Int("views", 1, "Max views before burning (default 1: burn after reading)")
	passphrase := fs.String("passphrase", "", "Optional passphrase required to decrypt")
	serverURL := fs.String("server", "", "Server daemon URL")

	// Allow flags to appear before or after positional arguments
	var flagArgs, nonFlagArgs []string
	flagWithVal := map[string]bool{
		"-file": true, "--file": true,
		"-ttl": true, "--ttl": true,
		"-views": true, "--views": true,
		"-passphrase": true, "--passphrase": true,
		"-server": true, "--server": true,
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if flagWithVal[arg] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			nonFlagArgs = append(nonFlagArgs, arg)
		}
	}
	fs.Parse(flagArgs)

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}

	var secretContent []byte
	var err error

	if *filePath != "" {
		secretContent, err = os.ReadFile(*filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read file: %v\n", err)
			os.Exit(1)
		}
	} else if len(nonFlagArgs) > 0 {
		secretContent = []byte(nonFlagArgs[0])
	} else {
		// Try reading from stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			secretContent, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to read from stdin: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintln(os.Stderr, "error: please provide secret text, use --file, or pipe via stdin.\nUsage: ducksecrets share <text> [--ttl=1h] [--views=1]")
			os.Exit(1)
		}
	}

	if len(secretContent) == 0 {
		fmt.Fprintln(os.Stderr, "error: secret content cannot be empty")
		os.Exit(1)
	}

	// Parse TTL
	ttlSeconds := parseTTL(*ttlStr)

	// Encrypt client-side (normalize whitespace passphrase consistently)
	trimmedPassphrase := strings.TrimSpace(*passphrase)
	c64, n64, keyUrlSafe, s64, err := encryptShareData(secretContent, trimmedPassphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client-side encryption failed: %v\n", err)
		os.Exit(1)
	}

	reqBody := map[string]any{
		"ciphertext":      c64,
		"nonce":           n64,
		"ttl_seconds":     ttlSeconds,
		"max_views":       *views,
		"has_passphrase":  trimmedPassphrase != "",
		"passphrase_salt": s64,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	apiURL := fmt.Sprintf("%s/api/v1/shares", strings.TrimRight(cfg.ServerURL, "/"))
	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ducksecrets-Request", "1")
	applyAuthHeaders(req, cfg.Token)

	client, err := newHTTPClient(cfg, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tls configuration error: %v\n", err)
		os.Exit(1)
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection error to %s: %v\n", cfg.ServerURL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "server error (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(respBody)))
		os.Exit(1)
	}

	var res struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expires_at"`
		MaxViews  int       `json:"max_views"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		fmt.Fprintf(os.Stderr, "decoding response failed: %v\n", err)
		os.Exit(1)
	}

	shareURL := fmt.Sprintf("%s/#/share/%s?k=%s", strings.TrimRight(cfg.ServerURL, "/"), res.ID, keyUrlSafe)

	fmt.Println("🔥 Ephemeral Secret Share Created!")
	fmt.Printf("Link:     %s\n", shareURL)
	if *views == 1 {
		fmt.Printf("Views:    1 (Burns immediately upon first view)\n")
	} else {
		fmt.Printf("Views:    %d max\n", *views)
	}
	fmt.Printf("Expires:  %s\n", res.ExpiresAt.Local().Format(time.RFC1123))
	if trimmedPassphrase != "" {
		fmt.Println("Protected: Passphrase required to decrypt")
	}
	fmt.Println("\nZero-Knowledge: Decryption key is in the link fragment; server cannot read your secret.")
}

func runShareGet(args []string) {
	fs := flag.NewFlagSet("share get", flag.ExitOnError)
	keyFlag := fs.String("key", "", "Decryption key (if not in URL)")
	passphrase := fs.String("passphrase", "", "Passphrase to unlock")
	serverURL := fs.String("server", "", "Server daemon URL")

	// Allow flags to appear before or after positional arguments
	var flagArgs, nonFlagArgs []string
	flagWithVal := map[string]bool{
		"-key": true, "--key": true,
		"-passphrase": true, "--passphrase": true,
		"-server": true, "--server": true,
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if flagWithVal[arg] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			nonFlagArgs = append(nonFlagArgs, arg)
		}
	}
	fs.Parse(flagArgs)

	if len(nonFlagArgs) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: ducksecrets share get <share-id-or-url> [--key=<key>] [--passphrase=<passphrase>]")
		os.Exit(1)
	}

	input := nonFlagArgs[0]
	shareID := input
	keyUrlSafe := *keyFlag

	cfg := loadConfig()
	configuredOrigin := cfg.ServerURL
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
		configuredOrigin = *serverURL
	}

	// If input is a full URL, extract ID and key
	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err == nil {
			if u.Scheme != "" && u.Host != "" {
				cfg.ServerURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
			}
			// Check fragment (hash) e.g. #/share/sh_123?k=...
			frag := u.Fragment
			if strings.HasPrefix(frag, "/") {
				fragParts := strings.Split(strings.TrimPrefix(frag, "/"), "?")
				pathParts := strings.Split(fragParts[0], "/")
				if len(pathParts) >= 2 && pathParts[0] == "share" {
					shareID = pathParts[1]
				}
				if len(fragParts) > 1 {
					vals, _ := url.ParseQuery(fragParts[1])
					if k := vals.Get("k"); k != "" {
						keyUrlSafe = k
					}
				}
			}
			// Also check query param if present
			if k := u.Query().Get("k"); k != "" && keyUrlSafe == "" {
				keyUrlSafe = k
			}
		}
	}

	if keyUrlSafe == "" {
		fmt.Fprintln(os.Stderr, "error: decryption key is required (either in URL fragment ?k=... or --key=<key>)")
		os.Exit(1)
	}

	apiURL := fmt.Sprintf("%s/api/v1/shares/%s/reveal", strings.TrimRight(cfg.ServerURL, "/"), url.PathEscape(shareID))
	req, err := http.NewRequest("POST", apiURL, bytes.NewReader([]byte("{}")))
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ducksecrets-Request", "1")
	if cfg.Token != "" && sameOriginURL(configuredOrigin, cfg.ServerURL) {
		applyAuthHeaders(req, cfg.Token)
	}

	client, err := newHTTPClient(cfg, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tls configuration error: %v\n", err)
		os.Exit(1)
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		fmt.Fprintln(os.Stderr, "error: this secret has already been burned and destroyed, or it expired.")
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "server error (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(respBody)))
		os.Exit(1)
	}

	var data struct {
		ID             string `json:"id"`
		Ciphertext     string `json:"ciphertext"`
		Nonce          string `json:"nonce"`
		HasPassphrase  bool   `json:"has_passphrase"`
		PassphraseSalt string `json:"passphrase_salt"`
		Burned         bool   `json:"burned"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		fmt.Fprintf(os.Stderr, "decoding failed: %v\n", err)
		os.Exit(1)
	}

	plain, err := decryptShareData(data.Ciphertext, data.Nonce, keyUrlSafe, *passphrase, data.PassphraseSalt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decryption failed: %v\n", err)
		os.Exit(1)
	}

	// Output plain secret directly to stdout
	os.Stdout.Write(plain)
	if !strings.HasSuffix(string(plain), "\n") {
		fmt.Println()
	}
}

func parseTTL(s string) int {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		var d int
		if _, err := fmt.Sscanf(daysStr, "%d", &d); err == nil && d > 0 {
			return d * 86400
		}
	}
	dur, err := time.ParseDuration(s)
	if err == nil && dur > 0 {
		return int(dur.Seconds())
	}
	return 86400 // default 24h
}

func encryptShareData(secret []byte, passphrase string) (ciphertextBase64, nonceBase64, keyUrlSafe, saltBase64 string, err error) {
	rawKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rawKey); err != nil {
		return "", "", "", "", err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", "", "", err
	}

	trimmedPass := strings.TrimSpace(passphrase)
	var encKey []byte
	if trimmedPass != "" {
		salt := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return "", "", "", "", err
		}
		saltBase64 = base64.StdEncoding.EncodeToString(salt)
		combined := append(rawKey, []byte(trimmedPass)...)
		encKey = pbkdf2.Key(combined, salt, 100000, 32, sha256.New)
	} else {
		encKey = rawKey
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", "", "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", "", err
	}

	ciphertext := gcm.Seal(nil, nonce, secret, nil)
	return base64.StdEncoding.EncodeToString(ciphertext),
		base64.StdEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString(rawKey),
		saltBase64,
		nil
}

func decryptShareData(ciphertextBase64, nonceBase64, keyUrlSafe, passphrase, saltBase64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}
	rawKey, err := base64.RawURLEncoding.DecodeString(keyUrlSafe)
	if err != nil {
		rawKey, err = base64.URLEncoding.DecodeString(keyUrlSafe)
		if err != nil {
			return nil, fmt.Errorf("invalid key: %w", err)
		}
	}

	trimmedPass := strings.TrimSpace(passphrase)
	var decKey []byte
	if saltBase64 != "" {
		if trimmedPass == "" {
			return nil, fmt.Errorf("passphrase required to decrypt this secret")
		}
		salt, err := base64.StdEncoding.DecodeString(saltBase64)
		if err != nil {
			return nil, fmt.Errorf("invalid salt: %w", err)
		}
		combined := append(rawKey, []byte(trimmedPass)...)
		decKey = pbkdf2.Key(combined, salt, 100000, 32, sha256.New)
	} else {
		decKey = rawKey
	}

	block, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func authedRequest(cfg cliConfig, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}

	url := strings.TrimRight(cfg.ServerURL, "/") + path
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Ducksecrets-Request", "1")
	applyAuthHeaders(req, cfg.Token)

	client, err := newHTTPClient(cfg, 20*time.Second)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

type dynamicProviderItem struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Engine            string `json:"engine"`
	RoleTemplate      string `json:"role_template"`
	DefaultTTLSeconds int    `json:"default_ttl_seconds"`
	MaxTTLSeconds     int    `json:"max_ttl_seconds"`
	EnforcedPort      int    `json:"enforced_port"`
}

type issuedLeaseItem struct {
	LeaseID      string    `json:"lease_id"`
	Username     string    `json:"username"`
	Password     string    `json:"password"`
	ConnString   string    `json:"connection_string"`
	ExpiresAt    time.Time `json:"expires_at"`
	Engine       string    `json:"engine"`
	Database     string    `json:"database"`
	EnforcedPort int       `json:"enforced_port"`
}

type dynamicLeaseItem struct {
	ID        string     `json:"id"`
	Username  string     `json:"username"`
	IssuedTo  string     `json:"issued_to"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func runDynamic(args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Print(`ducksecrets dynamic — Manage on-demand ephemeral credentials

Usage:
  ducksecrets dynamic <subcommand> [flags]

Subcommands:
  request <provider>    Request temporary database/server credentials
  leases [provider]     List active dynamic credential leases
  revoke <lease-id>     Immediately drop and revoke temporary credentials

Flags:
  --project string      Project slug (default from config or DUCKSECRETS_PROJECT)
  --env string          Environment slug (default: dev)
  --ttl string          Lease duration (e.g. 15m, 1h, 8h; default: 1h)
  --format string       Output format for request: text, env, json (default: text)
  --server string       DuckSecrets server URL
`)
		os.Exit(0)
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "request":
		runDynamicRequest(subargs)
	case "leases", "list":
		runDynamicLeases(subargs)
	case "revoke":
		runDynamicRevoke(subargs)
	default:
		fmt.Fprintf(os.Stderr, "unknown dynamic subcommand: %s. Run 'ducksecrets dynamic --help' for usage.\n", subcmd)
		os.Exit(1)
	}
}

func runDynamicRequest(args []string) {
	fs := flag.NewFlagSet("dynamic request", flag.ExitOnError)
	project := fs.String("project", "", "Project slug")
	envName := fs.String("env", "", "Environment slug (default from config/DUCKSECRETS_ENV or dev)")
	ttlStr := fs.String("ttl", "1h", "Lease TTL duration (e.g. 30m, 1h, 24h)")
	format := fs.String("format", "text", "Output format: text, env, json")
	serverURL := fs.String("server", "", "Server daemon URL")

	// Filter flags and positional args
	var flagArgs, posArgs []string
	valFlags := map[string]bool{"-project": true, "--project": true, "-env": true, "--env": true, "-ttl": true, "--ttl": true, "-format": true, "--format": true, "-server": true, "--server": true}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if valFlags[arg] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: provider name or ID is required. Usage: ducksecrets dynamic request <provider> [--ttl=1h]")
		os.Exit(1)
	}
	targetProvider := posArgs[0]

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	if *project != "" {
		cfg.Project = *project
	}
	if cfg.Project == "" {
		cfg.Project = "default"
	}
	if *envName != "" {
		cfg.Env = *envName
	}
	if cfg.Env == "" {
		cfg.Env = "dev"
	}

	// 1. Fetch dynamic providers for project/env
	listPath := fmt.Sprintf("/api/v1/projects/%s/environments/%s/dynamic", cfg.Project, cfg.Env)
	resp, err := authedRequest(cfg, "GET", listPath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "failed to list providers (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
		os.Exit(1)
	}

	var providers []dynamicProviderItem
	if err := json.NewDecoder(resp.Body).Decode(&providers); err != nil {
		fmt.Fprintf(os.Stderr, "error decoding providers: %v\n", err)
		os.Exit(1)
	}

	var matched *dynamicProviderItem
	for _, p := range providers {
		if strings.EqualFold(p.Name, targetProvider) || p.ID == targetProvider {
			matched = &p
			break
		}
	}

	if matched == nil {
		fmt.Fprintf(os.Stderr, "error: dynamic provider '%s' not found in project '%s' (%s).\n", targetProvider, cfg.Project, cfg.Env)
		if len(providers) > 0 {
			fmt.Fprintln(os.Stderr, "Available providers:")
			for _, p := range providers {
				fmt.Fprintf(os.Stderr, "  - %s (engine: %s, id: %s)\n", p.Name, p.Engine, p.ID)
			}
		}
		os.Exit(1)
	}

	ttlSec := parseTTL(*ttlStr)
	leaseReq := map[string]any{
		"ttl_seconds": ttlSec,
	}

	leasePath := fmt.Sprintf("/api/v1/projects/%s/environments/%s/dynamic/%s/lease", cfg.Project, cfg.Env, matched.ID)
	lResp, err := authedRequest(cfg, "POST", leasePath, leaseReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		os.Exit(1)
	}
	defer lResp.Body.Close()

	if lResp.StatusCode != http.StatusCreated && lResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(lResp.Body)
		fmt.Fprintf(os.Stderr, "failed to issue credentials (%d): %s\n", lResp.StatusCode, strings.TrimSpace(string(b)))
		os.Exit(1)
	}

	var issued struct {
		LeaseID    string    `json:"lease_id"`
		Username   string    `json:"username"`
		Password   string    `json:"password"`
		ConnString string    `json:"connection_string"`
		ExpiresAt  time.Time `json:"expires_at"`
		Engine     string    `json:"engine"`
	}
	if err := json.NewDecoder(lResp.Body).Decode(&issued); err != nil {
		fmt.Fprintf(os.Stderr, "decoding lease failed: %v\n", err)
		os.Exit(1)
	}

	switch strings.ToLower(*format) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(issued)
	case "env", "dotenv":
		fmt.Printf("DUCKSECRETS_LEASE_ID=%s\n", issued.LeaseID)
		fmt.Printf("DATABASE_USER=%s\n", issued.Username)
		fmt.Printf("DATABASE_PASSWORD=%s\n", issued.Password)
		if issued.ConnString != "" {
			fmt.Printf("DATABASE_URL=%s\n", issued.ConnString)
		}
		fmt.Printf("DUCKSECRETS_EXPIRES_AT=%s\n", issued.ExpiresAt.Format(time.RFC3339))
	default:
		rem := time.Until(issued.ExpiresAt).Round(time.Second)
		fmt.Println("✓ Dynamic credentials issued successfully!")
		fmt.Printf("  Lease ID:        %s\n", issued.LeaseID)
		fmt.Printf("  Engine:          %s\n", issued.Engine)
		fmt.Printf("  Username:        %s\n", issued.Username)
		fmt.Printf("  Password:        %s\n", issued.Password)
		if issued.ConnString != "" {
			fmt.Printf("  Connection URI:  %s\n", issued.ConnString)
		}
		fmt.Printf("  Expires At:      %s (in %s)\n", issued.ExpiresAt.Format(time.RFC3339), rem)
	}
}

func runDynamicLeases(args []string) {
	fs := flag.NewFlagSet("dynamic leases", flag.ExitOnError)
	project := fs.String("project", "", "Project slug")
	envName := fs.String("env", "", "Environment slug (default from config/DUCKSECRETS_ENV or dev)")
	serverURL := fs.String("server", "", "Server daemon URL")
	fs.Parse(args)

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	if *project != "" {
		cfg.Project = *project
	}
	if cfg.Project == "" {
		cfg.Project = "default"
	}
	if *envName != "" {
		cfg.Env = *envName
	}
	if cfg.Env == "" {
		cfg.Env = "dev"
	}

	targetFilter := ""
	if fs.NArg() > 0 {
		targetFilter = fs.Arg(0)
	}

	listPath := fmt.Sprintf("/api/v1/projects/%s/environments/%s/dynamic", cfg.Project, cfg.Env)
	resp, err := authedRequest(cfg, "GET", listPath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "failed to list providers (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
		os.Exit(1)
	}

	var providers []dynamicProviderItem
	_ = json.NewDecoder(resp.Body).Decode(&providers)

	foundAny := false
	for _, prov := range providers {
		if targetFilter != "" && !strings.EqualFold(prov.Name, targetFilter) && prov.ID != targetFilter {
			continue
		}

		leasesPath := fmt.Sprintf("/api/v1/projects/%s/environments/%s/dynamic/%s/leases", cfg.Project, cfg.Env, prov.ID)
		lResp, err := authedRequest(cfg, "GET", leasesPath, nil)
		if err != nil || lResp.StatusCode != http.StatusOK {
			if lResp != nil {
				lResp.Body.Close()
			}
			continue
		}

		var leases []dynamicLeaseItem
		_ = json.NewDecoder(lResp.Body).Decode(&leases)
		lResp.Body.Close()

		if !foundAny {
			fmt.Printf("%-18s  %-16s  %-20s  %-18s  %-12s\n", "PROVIDER", "LEASE ID", "USERNAME", "ISSUED TO", "TIME LEFT")
			fmt.Println(strings.Repeat("-", 90))
			foundAny = true
		}

		for _, l := range leases {
			if l.RevokedAt != nil {
				continue
			}
			timeLeft := time.Until(l.ExpiresAt).Round(time.Second)
			timeStr := timeLeft.String()
			if timeLeft <= 0 {
				timeStr = "expired"
			}
			fmt.Printf("%-18s  %-16s  %-20s  %-18s  %-12s\n", prov.Name, l.ID, l.Username, l.IssuedTo, timeStr)
		}
	}

	if !foundAny {
		fmt.Println("No active dynamic credential leases found.")
	}
}

func runDynamicRevoke(args []string) {
	fs := flag.NewFlagSet("dynamic revoke", flag.ExitOnError)
	project := fs.String("project", "", "Project slug")
	envName := fs.String("env", "", "Environment slug (default from config/DUCKSECRETS_ENV or dev)")
	providerID := fs.String("provider", "", "Provider ID or name (optional)")
	serverURL := fs.String("server", "", "Server daemon URL")

	var flagArgs, posArgs []string
	valFlags := map[string]bool{"-project": true, "--project": true, "-env": true, "--env": true, "-provider": true, "--provider": true, "-server": true, "--server": true}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if valFlags[arg] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: lease ID is required. Usage: ducksecrets dynamic revoke <lease-id>")
		os.Exit(1)
	}
	leaseID := posArgs[0]

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	if *project != "" {
		cfg.Project = *project
	}
	if cfg.Project == "" {
		cfg.Project = "default"
	}
	if *envName != "" {
		cfg.Env = *envName
	}
	if cfg.Env == "" {
		cfg.Env = "dev"
	}

	pid := *providerID
	if pid == "" {
		// Use placeholder since server route requires {provider_id} but checks lease directly
		pid = "any"
	}

	revokePath := fmt.Sprintf("/api/v1/projects/%s/environments/%s/dynamic/%s/leases/%s", cfg.Project, cfg.Env, pid, leaseID)
	resp, err := authedRequest(cfg, "DELETE", revokePath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "failed to revoke lease (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
		os.Exit(1)
	}

	fmt.Printf("✓ Dynamic lease '%s' revoked and credentials dropped successfully.\n", leaseID)
}

func runRotate(args []string) {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	project := fs.String("project", "", "Project slug")
	envName := fs.String("env", "", "Environment slug (default from config/DUCKSECRETS_ENV or dev)")
	serverURL := fs.String("server", "", "Server daemon URL")

	var flagArgs, posArgs []string
	valFlags := map[string]bool{"-project": true, "--project": true, "-env": true, "--env": true, "-server": true, "--server": true}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if valFlags[arg] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: secret key is required. Usage: ducksecrets rotate <SECRET_KEY> [--env=dev]")
		os.Exit(1)
	}
	targetSecret := posArgs[0]

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	if *project != "" {
		cfg.Project = *project
	}
	if cfg.Project == "" {
		cfg.Project = "default"
	}
	if *envName != "" {
		cfg.Env = *envName
	}
	if cfg.Env == "" {
		cfg.Env = "dev"
	}

	// 1. Find secret ID by key
	secretsPath := fmt.Sprintf("/api/v1/projects/%s/environments/%s/secrets?path=*", cfg.Project, cfg.Env)
	resp, err := authedRequest(cfg, "GET", secretsPath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "failed to retrieve secrets (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
		os.Exit(1)
	}

	var secretList struct {
		Items []struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&secretList); err != nil {
		fmt.Fprintf(os.Stderr, "decoding secrets failed: %v\n", err)
		os.Exit(1)
	}

	var secretID string
	for _, s := range secretList.Items {
		if strings.EqualFold(s.Key, targetSecret) || s.ID == targetSecret {
			secretID = s.ID
			break
		}
	}

	if secretID == "" {
		fmt.Fprintf(os.Stderr, "error: secret '%s' not found in project '%s' (%s)\n", targetSecret, cfg.Project, cfg.Env)
		os.Exit(1)
	}

	// 2. Trigger rotation run
	fmt.Printf("Rotating secret '%s'...\n", targetSecret)
	rotatePath := fmt.Sprintf("/api/v1/projects/%s/environments/%s/secrets/%s/rotation/run", cfg.Project, cfg.Env, secretID)
	rResp, err := authedRequest(cfg, "POST", rotatePath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		os.Exit(1)
	}
	defer rResp.Body.Close()

	if rResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(rResp.Body)
		fmt.Fprintf(os.Stderr, "rotation request failed (%d): %s\n", rResp.StatusCode, strings.TrimSpace(string(b)))
		os.Exit(1)
	}

	var runRes struct {
		Success    bool   `json:"success"`
		RolledBack bool   `json:"rolled_back"`
		Message    string `json:"message"`
		NewVersion int32  `json:"new_version"`
	}
	if err := json.NewDecoder(rResp.Body).Decode(&runRes); err != nil {
		fmt.Fprintf(os.Stderr, "decoding rotation response failed: %v\n", err)
		os.Exit(1)
	}

	if runRes.RolledBack {
		fmt.Fprintf(os.Stderr, "✗ Secret rotation failed and was rolled back automatically!\n  %s\n", runRes.Message)
		os.Exit(1)
	}

	if runRes.Success {
		fmt.Printf("✓ Secret '%s' successfully rotated to version %d!\n", targetSecret, runRes.NewVersion)
		fmt.Printf("  Message: %s\n", runRes.Message)
	} else {
		fmt.Printf("Rotation status: %s\n", runRes.Message)
	}
}

func buildExecClientCmd(engine, username, password, dbName string, port int, insecureSSH bool) *exec.Cmd {
	var cmd *exec.Cmd
	switch strings.ToLower(engine) {
	case "postgres":
		execURI := fmt.Sprintf("postgresql://%s@127.0.0.1:%d/%s", url.User(username).String(), port, url.PathEscape(dbName))
		cmd = exec.Command("psql", execURI)
		if password != "" {
			cmd.Env = append(os.Environ(), "PGPASSWORD="+password)
		}
	case "mysql":
		cmd = exec.Command("mysql", "-h", "127.0.0.1", "-P", strconv.Itoa(port), "-u", username, dbName)
		if password != "" {
			cmd.Env = append(os.Environ(), "MYSQL_PWD="+password)
		}
	case "redis":
		cmd = exec.Command("redis-cli", "-h", "127.0.0.1", "-p", strconv.Itoa(port))
		if password != "" {
			cmd.Env = append(os.Environ(), "REDISCLI_AUTH="+password)
		}
	case "pam":
		args := []string{"-p", strconv.Itoa(port), "-o", "StrictHostKeyChecking=accept-new"}
		if insecureSSH {
			args = []string{"-p", strconv.Itoa(port), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"}
		}
		args = append(args, fmt.Sprintf("%s@127.0.0.1", username))
		cmd = exec.Command("ssh", args...)
	}
	return cmd
}

func splitFlagsAndPositional(args []string, valFlags map[string]bool) (flagArgs, posArgs []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if valFlags[arg] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	return flagArgs, posArgs
}

func runConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	project := fs.String("project", "", "Project slug")
	envName := fs.String("env", "", "Environment slug (default from config/DUCKSECRETS_ENV or dev)")
	portFlag := fs.Int("port", 0, "Local port to bind (default: 0 = ephemeral)")
	ttlStr := fs.String("ttl", "1h", "Lease duration (e.g. 30m, 1h, 8h)")
	leaseFlag := fs.String("lease", "", "Existing active lease ID to connect through")
	execFlag := fs.Bool("exec", false, "Launch interactive client (psql, mysql, redis-cli, ssh)")
	insecureSSH := fs.Bool("insecure-ssh", false, "Disable SSH host key verification for --exec pam")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	valFlags := map[string]bool{
		"-project": true, "--project": true,
		"-env": true, "--env": true,
		"-port": true, "--port": true,
		"-ttl": true, "--ttl": true,
		"-lease": true, "--lease": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	flagArgs, posArgs := splitFlagsAndPositional(args, valFlags)
	fs.Parse(flagArgs)

	if len(posArgs) == 0 && *leaseFlag == "" {
		fmt.Print(`ducksecrets connect — Open a secure managed localhost tunnel to a database or host

Usage:
  ducksecrets connect <provider> [flags]

Flags:
  --project string    Project slug (default from config or DUCKSECRETS_PROJECT)
  --env string        Environment slug (default: dev)
  --port int          Local port (default: 0 = ephemeral port, or admin enforced)
  --ttl string        Lease duration (default: 1h)
  --lease string      Reuse an existing active lease ID
  --exec              Execute native interactive client CLI (psql, mysql, redis-cli, ssh)
  --server string     DuckSecrets server URL
`)
		os.Exit(0)
	}

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)
	resolveProjectEnv(&cfg, *project, *envName)

	targetProvider := ""
	if len(posArgs) > 0 {
		targetProvider = posArgs[0]
	}
	openManagedTunnel(cfg, "dynamic", targetProvider, *portFlag, *ttlStr, *leaseFlag, *execFlag, *insecureSSH)
}

func openManagedTunnel(cfg cliConfig, resourcePrefix, targetProvider string, portReq int, ttlStr, leaseID string, execFlag, insecureSSH bool) {
	// 1. Fetch providers/hosts for project/env
	listPath := fmt.Sprintf("/api/v1/projects/%s/environments/%s/%s", cfg.Project, cfg.Env, resourcePrefix)
	resp, err := authedRequest(cfg, "GET", listPath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "failed to list %s targets (%d): %s\n", resourcePrefix, resp.StatusCode, strings.TrimSpace(string(b)))
		os.Exit(1)
	}

	var providers []dynamicProviderItem
	_ = json.NewDecoder(resp.Body).Decode(&providers)

	var matched *dynamicProviderItem
	for _, p := range providers {
		if strings.EqualFold(p.Name, targetProvider) || p.ID == targetProvider {
			matched = &p
			break
		}
	}

	if matched == nil {
		fmt.Fprintf(os.Stderr, "error: %s target '%s' not found in project '%s' (%s)\n", resourcePrefix, targetProvider, cfg.Project, cfg.Env)
		if len(providers) > 0 {
			fmt.Fprintln(os.Stderr, "Available targets:")
			for _, p := range providers {
				fmt.Fprintf(os.Stderr, "  - %s (engine: %s, id: %s)\n", p.Name, p.Engine, p.ID)
			}
		}
		os.Exit(1)
	}

	// 2. Determine local port binding according to policy:
	portToBind := 0
	portSource := "Ephemeral"
	if matched.EnforcedPort > 0 {
		if portReq > 0 && portReq != matched.EnforcedPort {
			fmt.Fprintf(os.Stderr, "error: administrator has enforced local port %d for this connection (cannot use --port %d)\n", matched.EnforcedPort, portReq)
			os.Exit(1)
		}
		portToBind = matched.EnforcedPort
		portSource = fmt.Sprintf("Admin Enforced (:%d)", portToBind)
	} else if portReq > 0 {
		portToBind = portReq
		portSource = fmt.Sprintf("User Specified (:%d)", portToBind)
	}

	// 3. Obtain credentials: lease from daemon or use existing lease
	var issued issuedLeaseItem
	if leaseID != "" {
		issued.LeaseID = leaseID
		issued.Engine = matched.Engine
	} else {
		ttlSec := parseTTL(ttlStr)
		leaseReq := map[string]any{"ttl_seconds": ttlSec}
		leasePath := fmt.Sprintf("/api/v1/projects/%s/environments/%s/%s/%s/lease", cfg.Project, cfg.Env, resourcePrefix, matched.ID)
		lResp, err := authedRequest(cfg, "POST", leasePath, leaseReq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "request error: %v\n", err)
			os.Exit(1)
		}
		defer lResp.Body.Close()
		if lResp.StatusCode != http.StatusCreated && lResp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(lResp.Body)
			fmt.Fprintf(os.Stderr, "failed to issue credentials (%d): %s\n", lResp.StatusCode, strings.TrimSpace(string(b)))
			os.Exit(1)
		}
		if err := json.NewDecoder(lResp.Body).Decode(&issued); err != nil {
			fmt.Fprintf(os.Stderr, "decoding lease response failed: %v\n", err)
			os.Exit(1)
		}
	}

	// 4. Start local TCP listener on 127.0.0.1:<portToBind>
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", portToBind))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error binding local port %d: %v\n", portToBind, err)
		os.Exit(1)
	}
	defer listener.Close()

	assignedPort := listener.Addr().(*net.TCPAddr).Port

	// 5. Build local connection URI
	dbName := issued.Database
	if dbName == "" {
		dbName = "app"
	}
	localURI := ""
	switch strings.ToLower(matched.Engine) {
	case "postgres":
		if issued.Password != "" {
			localURI = fmt.Sprintf("postgresql://%s:%s@127.0.0.1:%d/%s", issued.Username, issued.Password, assignedPort, dbName)
		} else {
			localURI = fmt.Sprintf("postgresql://%s@127.0.0.1:%d/%s", issued.Username, assignedPort, dbName)
		}
	case "mysql":
		if issued.Password != "" {
			localURI = fmt.Sprintf("%s:%s@tcp(127.0.0.1:%d)/%s", issued.Username, issued.Password, assignedPort, dbName)
		} else {
			localURI = fmt.Sprintf("%s@tcp(127.0.0.1:%d)/%s", issued.Username, assignedPort, dbName)
		}
	case "redis":
		if issued.Password != "" {
			localURI = fmt.Sprintf("redis://:%s@127.0.0.1:%d", issued.Password, assignedPort)
		} else {
			localURI = fmt.Sprintf("redis://127.0.0.1:%d", assignedPort)
		}
	case "pam":
		localURI = fmt.Sprintf("ssh -p %d %s@127.0.0.1", assignedPort, issued.Username)
	default:
		localURI = fmt.Sprintf("tcp://127.0.0.1:%d", assignedPort)
	}

	// 6. Display user friendly banner
	fmt.Printf(`
╔══════════════════════════════════════════════════════════════════════╗
║               DuckSecrets Managed Tunnel Active                      ║
╚══════════════════════════════════════════════════════════════════════╝
  Target:        %s (%s / env: %s)
  Local Port:    %d [%s]
  Lease ID:      %s
  Username:      %s
  Password:      %s
  Local URI:     %s

  Tunneling: 127.0.0.1:%d <===> ducksecretsd <===> %s (private network)
  Press Ctrl+C to close tunnel and immediately revoke credentials.
------------------------------------------------------------------------
`, matched.Name, matched.Engine, cfg.Env, assignedPort, portSource, issued.LeaseID, issued.Username, issued.Password, localURI, assignedPort, matched.Name)

	// Clean shutdown channel
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Background listener accept loop
	tunnelCtx, cancelTunnel := context.WithCancel(context.Background())
	defer cancelTunnel()

	go func() {
		for {
			clientConn, err := listener.Accept()
			if err != nil {
				return
			}
			go bridgeTunnelClient(tunnelCtx, cfg, resourcePrefix, cfg.Project, cfg.Env, matched.ID, issued.LeaseID, clientConn)
		}
	}()

	// If exec requested, spawn native client without leaking credentials via argv
	if execFlag {
		go func() {
			cmd := buildExecClientCmd(matched.Engine, issued.Username, issued.Password, dbName, assignedPort, insecureSSH)
			if cmd != nil {
				cmd.Stdin = os.Stdin
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				_ = cmd.Run()
				shutdown <- os.Interrupt
			}
		}()
	}

	<-shutdown
	fmt.Println("\nClosing managed tunnel and revoking ephemeral credentials...")
	listener.Close()
	cancelTunnel()

	// Revoke lease immediately on daemon
	if leaseID == "" && issued.LeaseID != "" {
		revokePath := fmt.Sprintf("/api/v1/projects/%s/environments/%s/%s/%s/leases/%s", cfg.Project, cfg.Env, resourcePrefix, matched.ID, issued.LeaseID)
		_, _ = authedRequest(cfg, "DELETE", revokePath, nil)
	}

	fmt.Printf("✓ Tunnel closed and lease '%s' revoked successfully.\n", issued.LeaseID)
}

func bridgeTunnelClient(ctx context.Context, cfg cliConfig, resourcePrefix, project, env, providerID, leaseID string, clientConn net.Conn) {
	defer clientConn.Close()

	wsURL := strings.Replace(cfg.ServerURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL += fmt.Sprintf("/api/v1/projects/%s/environments/%s/%s/%s/tunnel?lease_id=%s", project, env, resourcePrefix, providerID, leaseID)

	header := http.Header{}
	header.Set("X-Ducksecrets-Request", "1")
	if cfg.Token != "" {
		header.Set("Authorization", "Bearer "+cfg.Token)
		header.Add("Cookie", "ducksecrets_session="+cfg.Token)
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()

	ws, _, err := dialWebSocket(dialCtx, wsURL, cfg, header)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect tunnel to daemon: %v\n", err)
		return
	}
	defer ws.Close(websocket.StatusNormalClosure, "client closed")

	netConn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer netConn.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(netConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, netConn)
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}
}

type siteItem struct {
	ID          string     `json:"id"`
	ProjectID   string     `json:"project_id"`
	Name        string     `json:"name"`
	TokenPrefix string     `json:"token_prefix"`
	Description string     `json:"description"`
	Online      bool       `json:"online"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type createdSiteItem struct {
	siteItem
	Token string `json:"token"`
}

func runSite(args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Print(`ducksecrets site — Manage and run Site Connectors (Reverse Tunnel Gateways)

Usage:
  ducksecrets site <subcommand> [flags]

Subcommands:
  run       Run the outbound-only Site Connector agent in a private network
  list      List registered network sites and their online status
  create    Register a new network site and generate a connection token
  delete    Remove a network site

Run 'ducksecrets site <subcommand> --help' for details on a specific subcommand.
`)
		os.Exit(0)
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "run":
		runSiteRun(subargs)
	case "list", "ls":
		runSiteList(subargs)
	case "create", "new":
		runSiteCreate(subargs)
	case "delete", "rm":
		runSiteDelete(subargs)
	default:
		fmt.Fprintf(os.Stderr, "unknown site subcommand: %s. Run 'ducksecrets site --help' for usage.\n", subcmd)
		os.Exit(1)
	}
}

func runSiteRun(args []string) {
	fs := flag.NewFlagSet("site run", flag.ExitOnError)
	siteFlag := fs.String("site", "", "Site name or Site ID")
	siteIDFlag := fs.String("site-id", "", "Alias for --site")
	tokenFlag := fs.String("token", "", "Site token (duck_site_*)")
	project := fs.String("project", "", "Project slug")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)
	fs.Parse(args)

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)
	if _, err := buildTLSConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid TLS configuration: %v\n", err)
		os.Exit(1)
	}
	if *project != "" {
		cfg.Project = *project
	}
	if cfg.Project == "" {
		cfg.Project = "default"
	}

	siteTarget := *siteFlag
	if siteTarget == "" {
		siteTarget = *siteIDFlag
	}
	if siteTarget == "" && fs.NArg() > 0 {
		siteTarget = fs.Arg(0)
	}
	if siteTarget == "" {
		fmt.Fprintln(os.Stderr, "error: site name or ID is required. Usage: ducksecrets site run --site=<name> --token=<duck_site_*>")
		os.Exit(1)
	}

	token := *tokenFlag
	if token == "" {
		token = os.Getenv("DUCKSECRETS_SITE_TOKEN")
	}
	if token == "" {
		fmt.Print("Enter site token (duck_site_*): ")
		var input string
		fmt.Scanln(&input)
		token = strings.TrimSpace(input)
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "error: site token is required")
		os.Exit(1)
	}

	// Resolve site ID by listing sites if siteTarget is a name
	siteID := siteTarget
	listPath := fmt.Sprintf("/api/v1/projects/%s/sites", cfg.Project)
	resp, err := authedRequest(cfg, "GET", listPath, nil)
	if err == nil && resp.StatusCode == http.StatusOK {
		var sitesList []siteItem
		if err := json.NewDecoder(resp.Body).Decode(&sitesList); err == nil {
			for _, s := range sitesList {
				if strings.EqualFold(s.Name, siteTarget) || s.ID == siteTarget {
					siteID = s.ID
					break
				}
			}
		}
		resp.Body.Close()
	}

	wsURL := strings.Replace(cfg.ServerURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL += fmt.Sprintf("/api/v1/sites/%s/connect", siteID)

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	header.Set("X-Ducksecrets-Request", "1")

	fmt.Printf(`
╔══════════════════════════════════════════════════════════════════════╗
║               DuckSecrets Site Connector Active                      ║
╚══════════════════════════════════════════════════════════════════════╝
  Site:          %s (%s)
  Daemon URL:    %s
  Tunnel Mode:   Reverse WebSocket Stream (Outbound-only)
  Inbound Ports: 0 (Firewall / NAT Safe)
------------------------------------------------------------------------
Listening for incoming connection requests from daemon...
Press Ctrl+C to terminate connector.
`, siteTarget, siteID, cfg.ServerURL)

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-shutdown
		fmt.Println("\nStopping Site Connector...")
		cancel()
	}()

	for {
		if ctx.Err() != nil {
			break
		}

		dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
		ws, _, err := dialWebSocket(dialCtx, wsURL, cfg, header)
		dialCancel()

		if err != nil {
			if ctx.Err() != nil {
				break
			}
			fmt.Fprintf(os.Stderr, "[reconnect] error connecting to daemon: %v (retrying in 5s)\n", err)
			select {
			case <-time.After(5 * time.Second):
				continue
			case <-ctx.Done():
				return
			}
		}

		fmt.Println("✓ Connected to DuckSecrets daemon. Site is ONLINE.")

		for {
			var streamReq struct {
				Action   string `json:"action"`
				StreamID string `json:"stream_id"`
				Host     string `json:"host"`
				Port     int    `json:"port"`
			}
			err := wsjson.Read(ctx, ws, &streamReq)
			if err != nil {
				if ctx.Err() != nil {
					ws.Close(websocket.StatusNormalClosure, "shutdown")
					return
				}
				fmt.Fprintf(os.Stderr, "[warning] control channel disconnected: %v. Reconnecting...\n", err)
				ws.Close(websocket.StatusGoingAway, "lost connection")
				break
			}

			if streamReq.Action == "open_stream" {
				go handleSiteStream(ctx, cfg, siteID, token, streamReq.StreamID, streamReq.Host, streamReq.Port)
			}
		}
	}
}

func handleSiteStream(ctx context.Context, cfg cliConfig, siteID, token, streamID, host string, port int) {
	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()

	targetConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", targetAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[stream:%s] failed to connect to local target %s: %v\n", streamID, targetAddr, err)
		return
	}
	defer targetConn.Close()

	streamURL := strings.Replace(cfg.ServerURL, "http://", "ws://", 1)
	streamURL = strings.Replace(streamURL, "https://", "wss://", 1)
	streamURL += fmt.Sprintf("/api/v1/sites/%s/streams/%s", siteID, streamID)

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	header.Set("X-Ducksecrets-Request", "1")

	streamWS, _, err := dialWebSocket(ctx, streamURL, cfg, header)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[stream:%s] failed to attach data stream to daemon: %v\n", streamID, err)
		return
	}
	defer streamWS.Close(websocket.StatusNormalClosure, "closed")

	netConn := websocket.NetConn(ctx, streamWS, websocket.MessageBinary)
	defer netConn.Close()

	fmt.Printf("[stream:%s] bridged reverse tunnel <===> %s\n", streamID, targetAddr)

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(netConn, targetConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(targetConn, netConn)
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}

	fmt.Printf("[stream:%s] closed\n", streamID)
}

func runSiteList(args []string) {
	fs := flag.NewFlagSet("site list", flag.ExitOnError)
	project := fs.String("project", "", "Project slug")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)
	fs.Parse(args)

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)
	if *project != "" {
		cfg.Project = *project
	}
	if cfg.Project == "" {
		cfg.Project = "default"
	}

	listPath := fmt.Sprintf("/api/v1/projects/%s/sites", cfg.Project)
	resp, err := authedRequest(cfg, "GET", listPath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "failed to list sites (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
		os.Exit(1)
	}

	var sites []siteItem
	_ = json.NewDecoder(resp.Body).Decode(&sites)

	if len(sites) == 0 {
		fmt.Println("No network sites registered yet. Register one with 'ducksecrets site create <name>'.")
		return
	}

	fmt.Printf("%-20s  %-22s  %-10s  %-20s  %-20s\n", "NAME", "TOKEN PREFIX", "STATUS", "LAST SEEN", "DESCRIPTION")
	fmt.Println(strings.Repeat("-", 95))
	for _, s := range sites {
		status := "OFFLINE"
		if s.Online {
			status = "ONLINE"
		}
		lastSeen := "never"
		if s.LastSeenAt != nil {
			lastSeen = time.Since(*s.LastSeenAt).Round(time.Second).String() + " ago"
		}
		fmt.Printf("%-20s  %-22s  %-10s  %-20s  %-20s\n", s.Name, s.TokenPrefix, status, lastSeen, s.Description)
	}
}

func runSiteCreate(args []string) {
	fs := flag.NewFlagSet("site create", flag.ExitOnError)
	project := fs.String("project", "", "Project slug")
	description := fs.String("desc", "", "Site description (e.g. AWS Production VPC)")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	var flagArgs, posArgs []string
	valFlags := map[string]bool{
		"-project": true, "--project": true,
		"-desc": true, "--desc": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if valFlags[arg] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: site name is required. Usage: ducksecrets site create <name> [--desc=...]")
		os.Exit(1)
	}
	name := posArgs[0]

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)
	if *project != "" {
		cfg.Project = *project
	}
	if cfg.Project == "" {
		cfg.Project = "default"
	}

	reqBody := map[string]string{
		"name":        name,
		"description": *description,
	}

	createPath := fmt.Sprintf("/api/v1/projects/%s/sites", cfg.Project)
	resp, err := authedRequest(cfg, "POST", createPath, reqBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "failed to create site (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
		os.Exit(1)
	}

	var created createdSiteItem
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		fmt.Fprintf(os.Stderr, "decoding site failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf(`
✓ Network Site '%s' registered successfully!
  Site ID:      %s
  Token:        %s

  (Save this token securely! It will never be shown again.)

To connect this site from inside your private network / VPC:
  ducksecrets site run --site=%s --token=%s
`, created.Name, created.ID, created.Token, created.Name, created.Token)
}

func runSiteDelete(args []string) {
	fs := flag.NewFlagSet("site delete", flag.ExitOnError)
	project := fs.String("project", "", "Project slug")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)
	fs.Parse(args)

	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "error: site ID or name required. Usage: ducksecrets site delete <site-id>")
		os.Exit(1)
	}
	target := fs.Arg(0)

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)
	if *project != "" {
		cfg.Project = *project
	}
	if cfg.Project == "" {
		cfg.Project = "default"
	}

	// Resolve site ID
	siteID := target
	listPath := fmt.Sprintf("/api/v1/projects/%s/sites", cfg.Project)
	resp, err := authedRequest(cfg, "GET", listPath, nil)
	if err == nil && resp.StatusCode == http.StatusOK {
		var sitesList []siteItem
		if err := json.NewDecoder(resp.Body).Decode(&sitesList); err == nil {
			for _, s := range sitesList {
				if strings.EqualFold(s.Name, target) || s.ID == target {
					siteID = s.ID
					break
				}
			}
		}
		resp.Body.Close()
	}

	delPath := fmt.Sprintf("/api/v1/projects/%s/sites/%s", cfg.Project, siteID)
	dResp, err := authedRequest(cfg, "DELETE", delPath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection error: %v\n", err)
		os.Exit(1)
	}
	defer dResp.Body.Close()

	if dResp.StatusCode != http.StatusNoContent && dResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(dResp.Body)
		fmt.Fprintf(os.Stderr, "failed to delete site (%d): %s\n", dResp.StatusCode, strings.TrimSpace(string(b)))
		os.Exit(1)
	}

	fmt.Printf("✓ Network site '%s' deleted successfully.\n", target)
}
