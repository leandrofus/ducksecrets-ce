package main

import (
	"bytes"
	"crypto/sha256"
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
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type dockerConfig struct {
	Entrypoint []string `json:"Entrypoint"`
	Cmd        []string `json:"Cmd"`
	User       string   `json:"User"`
	WorkingDir string   `json:"WorkingDir"`
}

func validateDockerfileToken(name, val string) error {
	if val == "" {
		return nil
	}
	if strings.ContainsAny(val, "\r\n\x00") {
		return fmt.Errorf("%s contains invalid newline or NUL character", name)
	}
	return nil
}

func validateImageRef(ref string) error {
	if ref == "" {
		return fmt.Errorf("image reference is required")
	}
	if err := validateDockerfileToken("image", ref); err != nil {
		return err
	}
	if strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, " \t") {
		return fmt.Errorf("invalid image reference %q", ref)
	}
	return nil
}

func isTrustedDownloadURL(rawURL string, allowInsecure bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid server URL %q: %w", rawURL, err)
	}
	if strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	if strings.EqualFold(u.Scheme, "http") {
		host := u.Hostname()
		if allowInsecure || host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("refusing plain HTTP binary download from non-loopback host %q (use HTTPS or --allow-insecure-http)", host)
	}
	return fmt.Errorf("unsupported download URL scheme %q", u.Scheme)
}

func verifyBinarySHA256(data []byte, expectedHex string) error {
	expected := strings.TrimSpace(strings.ToLower(expectedHex))
	if fields := strings.Fields(expected); len(fields) > 0 {
		expected = fields[0]
	}
	if len(expected) != 64 {
		return fmt.Errorf("invalid sha256 checksum length (%d chars)", len(expected))
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("downloaded binary sha256 mismatch: got %s, want %s", actual, expected)
	}
	return nil
}

func buildWrapDockerfile(srcImage, serverURL, project, envName, user string, finalEntrypoint, finalCmd []string) (string, error) {
	if err := validateImageRef(srcImage); err != nil {
		return "", err
	}
	for name, v := range map[string]string{
		"server":  serverURL,
		"project": project,
		"env":     envName,
		"user":    user,
	} {
		if err := validateDockerfileToken(name, v); err != nil {
			return "", err
		}
	}
	if user != "" && strings.ContainsAny(user, " \t") {
		return "", fmt.Errorf("invalid Dockerfile USER metadata %q", user)
	}

	epJSON, err := json.Marshal(finalEntrypoint)
	if err != nil {
		return "", fmt.Errorf("serializing entrypoint: %w", err)
	}
	cmdJSON, err := json.Marshal(finalCmd)
	if err != nil {
		return "", fmt.Errorf("serializing cmd: %w", err)
	}

	var df bytes.Buffer
	df.WriteString(fmt.Sprintf("FROM %s\n", srcImage))
	df.WriteString("USER root\n")
	df.WriteString("COPY ducksecrets /usr/local/bin/ducksecrets\n")
	df.WriteString("RUN chmod 755 /usr/local/bin/ducksecrets\n")
	if serverURL != "" {
		df.WriteString(fmt.Sprintf("ENV DUCKSECRETS_SERVER=%q\n", serverURL))
	}
	if project != "" {
		df.WriteString(fmt.Sprintf("ENV DUCKSECRETS_PROJECT=%q\n", project))
	}
	if envName != "" {
		df.WriteString(fmt.Sprintf("ENV DUCKSECRETS_ENV=%q\n", envName))
	}
	if user != "" && user != "root" && user != "0" {
		df.WriteString(fmt.Sprintf("USER %s\n", user))
	}
	df.WriteString(fmt.Sprintf("ENTRYPOINT %s\n", string(epJSON)))
	if len(finalCmd) > 0 {
		df.WriteString(fmt.Sprintf("CMD %s\n", string(cmdJSON)))
	}
	return df.String(), nil
}

func runWrap(args []string) {
	fs := flag.NewFlagSet("wrap", flag.ExitOnError)
	srcImage := fs.String("image", "", "Source container image name or tag (e.g. node:20-alpine, my-app:latest)")
	destImage := fs.String("output", "", "Output container image tag (default: <source>-ducksecrets)")
	engine := fs.String("engine", "", "Container engine to use (docker or podman, default: auto-detect)")
	push := fs.Bool("push", false, "Push output image after building")
	serverURL := fs.String("server", "", "Default DUCKSECRETS_SERVER URL to bake as ENV in image (optional)")
	project := fs.String("project", "", "Default DUCKSECRETS_PROJECT to bake as ENV in image (optional)")
	envName := fs.String("env", "", "Default DUCKSECRETS_ENV to bake as ENV in image (optional)")
	expectedSHA := fs.String("sha256", os.Getenv("DUCKSECRETS_CLI_SHA256"), "Expected SHA-256 hex digest when downloading remote Linux CLI binary")
	allowInsecureHTTP := fs.Bool("allow-insecure-http", false, "Allow downloading CLI binary over plain HTTP from non-loopback hosts")
	fs.Parse(args)

	// Positional arguments support: ducksecrets wrap <src> [output]
	if *srcImage == "" && fs.NArg() > 0 {
		*srcImage = fs.Arg(0)
	}
	if *destImage == "" && fs.NArg() > 1 {
		*destImage = fs.Arg(1)
	}

	if *srcImage == "" {
		fmt.Fprintln(os.Stderr, "error: source container image is required.")
		fmt.Fprintln(os.Stderr, "Usage: ducksecrets wrap [flags] <source-image> [output-image]")
		fmt.Fprintln(os.Stderr, "Example: ducksecrets wrap node:20-alpine node:20-ducksecrets")
		os.Exit(1)
	}

	// 1. Determine container engine
	engineBin := *engine
	if engineBin == "" {
		if path, err := exec.LookPath("docker"); err == nil {
			engineBin = path
		} else if path, err := exec.LookPath("podman"); err == nil {
			engineBin = path
		} else {
			fmt.Fprintln(os.Stderr, "error: neither 'docker' nor 'podman' found in PATH. Please install a container engine.")
			os.Exit(1)
		}
	}

	// 2. Determine output tag
	outputTag := *destImage
	if outputTag == "" {
		if strings.Contains(*srcImage, ":") {
			parts := strings.SplitN(*srcImage, ":", 2)
			if parts[1] == "latest" {
				outputTag = parts[0] + ":ducksecrets"
			} else {
				outputTag = parts[0] + ":" + parts[1] + "-ducksecrets"
			}
		} else {
			outputTag = *srcImage + ":ducksecrets"
		}
	}

	fmt.Printf("🔍 Inspecting source image '%s' using %s...\n", *srcImage, filepath.Base(engineBin))

	// 3. Inspect image config using engine
	cmdInspect := exec.Command(engineBin, "inspect", *srcImage, "--format={{json .Config}}")
	outInspect, err := cmdInspect.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error inspecting image '%s': %v\nMake sure the image exists locally or in registry.\n", *srcImage, err)
		os.Exit(1)
	}

	var cfg dockerConfig
	if err := json.Unmarshal(bytes.TrimSpace(outInspect), &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing image inspect config: %v\n", err)
		os.Exit(1)
	}

	// Combine original Entrypoint and Cmd with Docker standards:
	// If Entrypoint was defined, ducksecrets wraps the entrypoint executable, preserving CMD arguments.
	// If only Cmd was defined, the first element of Cmd is the executable.
	var finalEntrypoint []string
	var finalCmd []string

	if len(cfg.Entrypoint) > 0 {
		finalEntrypoint = append([]string{"/usr/local/bin/ducksecrets", "run", "--"}, cfg.Entrypoint...)
		finalCmd = cfg.Cmd
	} else if len(cfg.Cmd) > 0 {
		finalEntrypoint = []string{"/usr/local/bin/ducksecrets", "run", "--", cfg.Cmd[0]}
		finalCmd = cfg.Cmd[1:]
	} else {
		finalEntrypoint = []string{"/usr/local/bin/ducksecrets", "run", "--", "/bin/sh"}
		finalCmd = []string{}
	}

	// 4. Create temporary build context
	tmpDir, err := os.MkdirTemp("", "ducksecrets-wrap-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating temporary build context: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	targetBinPath := filepath.Join(tmpDir, "ducksecrets")

	// 5. Obtain Linux static CLI binary
	obtained := false
	if runtime.GOOS == "linux" {
		if selfExec, err := os.Executable(); err == nil {
			if data, err := os.ReadFile(selfExec); err == nil && len(data) > 0 {
				if err := os.WriteFile(targetBinPath, data, 0o755); err == nil {
					obtained = true
				}
			}
		}
	}

	if !obtained {
		// Download static Linux binary from configured DuckSecrets server
		cfgGlobal := loadConfig()
		server := *serverURL
		if server == "" {
			server = cfgGlobal.ServerURL
		}
		if server == "" {
			server = defaultServerURL
		}
		downloadURL := strings.TrimRight(server, "/") + "/download/ducksecrets"
		if err := isTrustedDownloadURL(downloadURL, *allowInsecureHTTP); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("⬇️  Downloading static Linux CLI from %s...\n", downloadURL)

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(downloadURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error downloading CLI binary from %s: %v\n", downloadURL, err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "error downloading CLI binary from %s: HTTP %d\n", downloadURL, resp.StatusCode)
			os.Exit(1)
		}

		binData, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading downloaded binary: %v\n", err)
			os.Exit(1)
		}
		if len(binData) < 4 || string(binData[:4]) != "\x7fELF" {
			fmt.Fprintf(os.Stderr, "error: downloaded artifact from %s is not a valid Linux ELF binary\n", downloadURL)
			os.Exit(1)
		}

		sha := strings.TrimSpace(*expectedSHA)
		if sha == "" {
			if sumResp, sumErr := client.Get(downloadURL + ".sha256"); sumErr == nil {
				defer sumResp.Body.Close()
				if sumResp.StatusCode == http.StatusOK {
					if sumBytes, err := io.ReadAll(io.LimitReader(sumResp.Body, 4096)); err == nil {
						sha = string(sumBytes)
					}
				}
			}
		}
		if sha == "" {
			fmt.Fprintf(os.Stderr, "error: refusing unverified binary download from %s (provide --sha256 or DUCKSECRETS_CLI_SHA256)\n", downloadURL)
			os.Exit(1)
		}
		if err := verifyBinarySHA256(binData, sha); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(targetBinPath, binData, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "error saving downloaded binary: %v\n", err)
			os.Exit(1)
		}
	}

	// 6. Generate validated Dockerfile
	dockerfileContent, err := buildWrapDockerfile(*srcImage, *serverURL, *project, *envName, cfg.User, finalEntrypoint, finalCmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating Dockerfile: %v\n", err)
		os.Exit(1)
	}

	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing Dockerfile: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🔨 Building autonomous container image '%s'...\n", outputTag)

	// 7. Execute container build
	buildCmd := exec.Command(engineBin, "build", "-t", outputTag, tmpDir)
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	if err := buildCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error building wrapped container: %v\n", err)
		os.Exit(1)
	}

	// 8. Push if requested
	if *push {
		fmt.Printf("🚀 Pushing wrapped image '%s'...\n", outputTag)
		pushCmd := exec.Command(engineBin, "push", outputTag)
		pushCmd.Stdout = os.Stdout
		pushCmd.Stderr = os.Stderr
		if err := pushCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "error pushing wrapped container: %v\n", err)
			os.Exit(1)
		}
	}

	// 9. Friendly success report
	var displayCmd []string
	if len(finalEntrypoint) > 3 {
		displayCmd = append(displayCmd, finalEntrypoint[3:]...)
	}
	displayCmd = append(displayCmd, finalCmd...)

	fmt.Printf("\n✨ Successfully wrapped container image!\n")
	fmt.Printf("  Source:   %s\n", *srcImage)
	fmt.Printf("  Target:   %s\n", outputTag)
	fmt.Printf("  Command:  %s\n", strings.Join(displayCmd, " "))
	fmt.Printf("\nRun your autonomous container:\n")
	fmt.Printf("  docker run -d \\\n")
	fmt.Printf("    -e DUCKSECRETS_SERVER=\"%s\" \\\n", *serverURL)
	fmt.Printf("    -e DUCKSECRETS_TOKEN=\"duck_st_...\" \\\n")
	fmt.Printf("    -e DUCKSECRETS_PROJECT=\"%s\" \\\n", *project)
	fmt.Printf("    -e DUCKSECRETS_ENV=\"%s\" \\\n", *envName)
	fmt.Printf("    %s\n\n", outputTag)
}
