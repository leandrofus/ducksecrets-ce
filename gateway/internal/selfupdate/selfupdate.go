// Package selfupdate implements verified binary self-updates against the
// latest GitHub release of the public DuckSecrets repository (or a configured mirror).
//
// It imports only the Go standard library so both the lightweight client CLI
// (ducksecrets) and server daemon (ducksecretsd) can share it without pulling
// database or server dependencies into the CLI.
package selfupdate

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultRepo is the public GitHub repository hosting Community Edition releases.
	DefaultRepo = "leandrofus/ducksecrets-ce"
	// DefaultAPIBase is the GitHub REST API base URL.
	DefaultAPIBase = "https://api.github.com"

	maxChecksumBytes = 1 << 20   // 1 MiB
	maxBinaryBytes   = 200 << 20 // 200 MiB
)

// Options configures release lookup and update application.
type Options struct {
	// BinaryName is the release asset prefix: "ducksecrets" or "ducksecretsd".
	BinaryName string
	// CurrentVersion is the currently running binary version (e.g. "0.2.0" or "dev").
	CurrentVersion string
	// TargetTag selects an explicit release tag instead of "latest" when non-empty.
	TargetTag string
	// Repo overrides DefaultRepo ("owner/repo"). Also read from $DUCKSECRETS_UPDATE_REPO.
	Repo string
	// APIBase overrides DefaultAPIBase. Also read from $DUCKSECRETS_UPDATE_API_URL.
	APIBase string
	// TargetPath overrides os.Executable() when set.
	TargetPath string
	// Force applies the download even when CurrentVersion >= release version.
	Force bool
	// HTTPClient optionally overrides the HTTP client used for API and asset requests.
	HTTPClient *http.Client
	// OS and Arch default to runtime.GOOS and runtime.GOARCH.
	OS   string
	Arch string
}

// ReleaseInfo summarizes a release check against the public repository.
type ReleaseInfo struct {
	Repo            string `json:"repo"`
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	ReleaseURL      string `json:"release_url,omitempty"`
	PublishedAt     string `json:"published_at,omitempty"`
	AssetName       string `json:"asset_name,omitempty"`
	DownloadURL     string `json:"download_url,omitempty"`
	ChecksumsURL    string `json:"checksums_url,omitempty"`
	ExpectedSHA256  string `json:"expected_sha256,omitempty"`
}

// ApplyResult summarizes an executed update.
type ApplyResult struct {
	ReleaseInfo
	Updated    bool   `json:"updated"`
	TargetPath string `json:"target_path"`
	ActualSHA  string `json:"actual_sha256,omitempty"`
}

type githubRelease struct {
	TagName     string `json:"tag_name"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func (o *Options) resolve() (Options, error) {
	out := *o
	if out.BinaryName == "" {
		return out, errors.New("binary name is required")
	}
	if out.Repo == "" {
		if env := strings.TrimSpace(os.Getenv("DUCKSECRETS_UPDATE_REPO")); env != "" {
			out.Repo = env
		} else {
			out.Repo = DefaultRepo
		}
	}
	if !validRepoSlug(out.Repo) {
		return out, fmt.Errorf("invalid update repository %q (expected owner/repo)", out.Repo)
	}
	if out.APIBase == "" {
		if env := strings.TrimSpace(os.Getenv("DUCKSECRETS_UPDATE_API_URL")); env != "" {
			out.APIBase = env
		} else {
			out.APIBase = DefaultAPIBase
		}
	}
	out.APIBase = strings.TrimRight(out.APIBase, "/")
	if out.OS == "" {
		out.OS = runtime.GOOS
	}
	if out.Arch == "" {
		out.Arch = runtime.GOARCH
	}
	if out.HTTPClient == nil {
		out.HTTPClient = &http.Client{Timeout: 60 * time.Second}
	}
	return out, nil
}

func validRepoSlug(s string) bool {
	parts := strings.Split(s, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, p := range parts {
		if strings.ContainsAny(p, " \t\r\n?#") || p == "." || p == ".." {
			return false
		}
	}
	return true
}

// ExpectedAssetName returns the canonical release asset filename for binary/os/arch.
func ExpectedAssetName(binaryName, goOS, goArch string) string {
	ext := ""
	if goOS == "windows" {
		ext = ".exe"
	}
	return fmt.Sprintf("%s-%s-%s%s", binaryName, goOS, goArch, ext)
}

// Check queries the configured repository's latest release (or TargetTag) and
// compares it against CurrentVersion without modifying any files on disk.
func Check(ctx context.Context, opts Options) (ReleaseInfo, error) {
	o, err := opts.resolve()
	if err != nil {
		return ReleaseInfo{}, err
	}

	endpoint := fmt.Sprintf("%s/repos/%s/releases/latest", o.APIBase, o.Repo)
	if o.TargetTag != "" {
		tag := o.TargetTag
		if !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}
		endpoint = fmt.Sprintf("%s/repos/%s/releases/tags/%s", o.APIBase, o.Repo, url.PathEscape(tag))
	}
	if err := validateDownloadURL(endpoint); err != nil {
		return ReleaseInfo{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ReleaseInfo{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", fmt.Sprintf("ducksecrets/%s", o.CurrentVersion))

	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		return ReleaseInfo{}, fmt.Errorf("checking %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return ReleaseInfo{}, fmt.Errorf("release check HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rel githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&rel); err != nil {
		return ReleaseInfo{}, fmt.Errorf("decoding release response: %w", err)
	}
	if rel.TagName == "" {
		return ReleaseInfo{}, errors.New("release response missing tag_name")
	}

	assetName := ExpectedAssetName(o.BinaryName, o.OS, o.Arch)
	info := ReleaseInfo{
		Repo:            o.Repo,
		CurrentVersion:  o.CurrentVersion,
		LatestVersion:   rel.TagName,
		UpdateAvailable: CompareVersions(o.CurrentVersion, rel.TagName) < 0,
		ReleaseURL:      rel.HTMLURL,
		PublishedAt:     rel.PublishedAt,
		AssetName:       assetName,
	}
	for _, a := range rel.Assets {
		switch a.Name {
		case assetName:
			info.DownloadURL = a.BrowserDownloadURL
		case "SHA256SUMS":
			info.ChecksumsURL = a.BrowserDownloadURL
		}
	}
	if info.DownloadURL != "" && info.ChecksumsURL != "" {
		if sum, err := fetchExpectedSHA(ctx, o.HTTPClient, info.ChecksumsURL, assetName, o.CurrentVersion); err == nil {
			info.ExpectedSHA256 = sum
		}
	}
	return info, nil
}

// Apply downloads the target release asset, verifies its SHA-256 checksum
// against the release's SHA256SUMS file, and atomically replaces the executable.
func Apply(ctx context.Context, opts Options) (ApplyResult, error) {
	o, err := opts.resolve()
	if err != nil {
		return ApplyResult{}, err
	}

	info, err := Check(ctx, o)
	if err != nil {
		return ApplyResult{}, err
	}

	target := o.TargetPath
	if target == "" {
		exe, err := os.Executable()
		if err != nil {
			return ApplyResult{}, fmt.Errorf("resolving executable path: %w", err)
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		target = exe
	}

	res := ApplyResult{
		ReleaseInfo: info,
		TargetPath:  target,
	}
	if !info.UpdateAvailable && !o.Force {
		return res, nil
	}
	if info.DownloadURL == "" {
		return res, fmt.Errorf("release %s does not include asset %q", info.LatestVersion, info.AssetName)
	}
	if info.ChecksumsURL == "" {
		return res, fmt.Errorf("release %s is missing SHA256SUMS manifest; refusing unverified binary", info.LatestVersion)
	}

	expectedSHA, err := fetchExpectedSHA(ctx, o.HTTPClient, info.ChecksumsURL, info.AssetName, o.CurrentVersion)
	if err != nil {
		return res, err
	}
	res.ExpectedSHA256 = expectedSHA

	if err := validateDownloadURL(info.DownloadURL); err != nil {
		return res, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, info.DownloadURL, nil)
	if err != nil {
		return res, err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("ducksecrets/%s", o.CurrentVersion))

	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		return res, fmt.Errorf("downloading %s: %w", info.AssetName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("downloading %s: HTTP %d", info.AssetName, resp.StatusCode)
	}

	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, filepath.Base(target)+".update-*")
	if err != nil {
		if os.IsPermission(err) {
			return res, fmt.Errorf("permission denied writing in %s (re-run with elevated privileges or upgrade via package manager): %w", dir, err)
		}
		return res, fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanupTmp := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxBinaryBytes+1))
	if err != nil {
		cleanupTmp()
		return res, fmt.Errorf("saving update binary: %w", err)
	}
	if written > maxBinaryBytes {
		cleanupTmp()
		return res, fmt.Errorf("downloaded binary exceeds maximum size (%d bytes)", maxBinaryBytes)
	}
	actualSHA := hex.EncodeToString(h.Sum(nil))
	res.ActualSHA = actualSHA
	if !strings.EqualFold(actualSHA, expectedSHA) {
		cleanupTmp()
		return res, fmt.Errorf("SHA-256 mismatch for %s: got %s, want %s", info.AssetName, actualSHA, expectedSHA)
	}

	if err := tmp.Chmod(0o755); err != nil {
		cleanupTmp()
		return res, fmt.Errorf("chmod temp binary: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanupTmp()
		return res, fmt.Errorf("sync temp binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return res, fmt.Errorf("closing temp binary: %w", err)
	}

	if err := swapExecutable(tmpPath, target, o.OS); err != nil {
		_ = os.Remove(tmpPath)
		return res, err
	}
	res.Updated = true
	return res, nil
}

func swapExecutable(tmpPath, target, goOS string) error {
	if goOS != "windows" {
		if err := os.Rename(tmpPath, target); err != nil {
			if os.IsPermission(err) {
				return fmt.Errorf("permission denied replacing %s (re-run with sudo or upgrade via package manager): %w", target, err)
			}
			return fmt.Errorf("replacing %s: %w", target, err)
		}
		return nil
	}

	oldPath := target + ".old"
	_ = os.Remove(oldPath)
	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, oldPath); err != nil {
			return fmt.Errorf("moving current Windows binary aside: %w", err)
		}
	}
	if err := os.Rename(tmpPath, target); err != nil {
		_ = os.Rename(oldPath, target)
		return fmt.Errorf("activating updated Windows binary: %w", err)
	}
	return nil
}

func fetchExpectedSHA(ctx context.Context, client *http.Client, checksumsURL, assetName, currentVersion string) (string, error) {
	if err := validateDownloadURL(checksumsURL); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumsURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("ducksecrets/%s", currentVersion))
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("downloading SHA256SUMS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("downloading SHA256SUMS: HTTP %d", resp.StatusCode)
	}
	return parseSHA256SUMS(io.LimitReader(resp.Body, maxChecksumBytes), assetName)
}

func parseSHA256SUMS(r io.Reader, assetName string) (string, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		sum := strings.ToLower(strings.TrimSpace(fields[0]))
		name := strings.TrimPrefix(strings.TrimSpace(fields[len(fields)-1]), "*")
		name = filepath.Base(name)
		if name == assetName && len(sum) == 64 {
			if _, err := hex.DecodeString(sum); err == nil {
				return sum, nil
			}
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("reading SHA256SUMS: %w", err)
	}
	return "", fmt.Errorf("SHA256SUMS does not list checksum for %s", assetName)
}

func validateDownloadURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("refusing non-HTTPS URL %q", raw)
}

type semver struct {
	major, minor, patch int
	pre                 string
	valid               bool
}

func parseSemver(v string) semver {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" || v == "dev" {
		return semver{}
	}
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	var pre string
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return semver{}
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	pat, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || maj < 0 || min < 0 || pat < 0 {
		return semver{}
	}
	return semver{major: maj, minor: min, patch: pat, pre: pre, valid: true}
}

// CompareVersions compares two version strings (e.g. "v0.1.0" vs "0.2.0").
// Returns -1 if a < b, 0 if equal, +1 if a > b. Unparseable/dev builds sort
// below any valid semver release.
func CompareVersions(a, b string) int {
	sa, sb := parseSemver(a), parseSemver(b)
	switch {
	case !sa.valid && !sb.valid:
		return strings.Compare(strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v"))
	case !sa.valid:
		return -1
	case !sb.valid:
		return 1
	}
	if sa.major != sb.major {
		return cmpInt(sa.major, sb.major)
	}
	if sa.minor != sb.minor {
		return cmpInt(sa.minor, sb.minor)
	}
	if sa.patch != sb.patch {
		return cmpInt(sa.patch, sb.patch)
	}
	switch {
	case sa.pre == sb.pre:
		return 0
	case sa.pre == "":
		return 1
	case sb.pre == "":
		return -1
	default:
		return strings.Compare(sa.pre, sb.pre)
	}
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	return 1
}
