package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type cliCredentialPayload struct {
	PrivateKey   string `json:"private_key,omitempty"`
	PublicKey    string `json:"public_key,omitempty"`
	Passphrase   string `json:"passphrase,omitempty"`
	KeyType      string `json:"key_type,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	Host         string `json:"host,omitempty"`
	Port         int    `json:"port,omitempty"`
	Username     string `json:"username,omitempty"`
	Certificate  string `json:"certificate,omitempty"`
	CAChain      string `json:"ca_chain,omitempty"`
	Subject      string `json:"subject,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	Provider     string `json:"provider,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	APIKey       string `json:"api_key,omitempty"`
	TokenURL     string `json:"token_url,omitempty"`
	EndpointURL  string `json:"endpoint_url,omitempty"`
	Scopes       string `json:"scopes,omitempty"`
	Password     string `json:"password,omitempty"`
	URL          string `json:"url,omitempty"`
	Database     string `json:"database,omitempty"`
	Notes        string `json:"notes,omitempty"`
}

type cliCredential struct {
	ID              string                `json:"id"`
	ProjectID       *string               `json:"project_id,omitempty"`
	ProjectName     string                `json:"project_name,omitempty"`
	ProjectSlug     string                `json:"project_slug,omitempty"`
	EnvironmentSlug string                `json:"environment_slug"`
	Name            string                `json:"name"`
	Kind            string                `json:"kind"`
	Description     string                `json:"description"`
	Summary         string                `json:"summary"`
	Payload         *cliCredentialPayload `json:"payload,omitempty"`
	ExpiresAt       *time.Time            `json:"expires_at,omitempty"`
	CreatedBy       string                `json:"created_by"`
	CreatedAt       time.Time             `json:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at"`
}

type cliCredentialList struct {
	Items []cliCredential `json:"items"`
	Total int             `json:"total"`
}

func runCreds(args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printCredsUsage()
		os.Exit(0)
	}

	subcmd := strings.ToLower(args[0])
	subargs := args[1:]

	switch subcmd {
	// Type-specific namespaces with tailored actions per type
	case "ssh", "ssh_key", "ssh-key":
		runCredSSHNamespace(subargs)
	case "db", "database":
		runCredDBNamespace(subargs)
	case "login", "account":
		runCredLoginNamespace(subargs)
	case "tls", "cert", "tls_cert", "tls-cert":
		runCredTLSNamespace(subargs)
	case "api", "oauth", "oauth_api", "oauth-api":
		runCredAPINamespace(subargs)

	// Top-level convenience actions
	case "list", "ls":
		runCredsList(subargs, "")
	case "get", "show", "inspect":
		runCredsGet(subargs, "")
	case "delete", "rm", "remove":
		runCredsDelete(subargs)
	case "sync", "sync-env":
		runCredsSync(subargs)
	case "set", "put", "create", "save":
		fmt.Fprintln(os.Stderr, "error: 'set' must be called on a specific credential type:\n  ducksecrets cred ssh set <name> [flags]\n  ducksecrets cred db set <name> [flags]\n  ducksecrets cred login set <name> [flags]\n  ducksecrets cred tls set <name> [flags]\n  ducksecrets cred api set <name> [flags]")
		os.Exit(1)
	case "connect", "exec":
		fmt.Fprintln(os.Stderr, "error: 'connect' is only applicable to interactive session types (SSH or Database):\n  ducksecrets cred ssh connect <name-or-id> [flags]\n  ducksecrets cred db connect <name-or-id> [flags]\n\nFor TLS certificates, use 'ducksecrets cred tls export <name-or-id> --dir=./certs'.\nFor API/OAuth or Logins, use 'ducksecrets cred api get <name-or-id> --format=env' or 'cred login get <name-or-id>'.")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "unknown cred subcommand: %s. Run 'ducksecrets cred --help' for usage.\n", subcmd)
		os.Exit(1)
	}
}

func runCredSSHNamespace(args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printCredTypeUsage("ssh")
		os.Exit(0)
	}
	action := strings.ToLower(args[0])
	rest := args[1:]
	switch action {
	case "set", "create", "save":
		runCredSSHSet(rest)
	case "get", "show", "inspect":
		runCredsGet(rest, "ssh_key")
	case "connect", "ssh", "exec":
		runCredSSHConnect(rest)
	case "export":
		runCredSSHExport(rest)
	case "list", "ls":
		runCredsList(rest, "ssh_key")
	case "delete", "rm":
		runCredsDelete(rest)
	case "sync", "sync-env":
		runCredsSync(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown action %q for 'ducksecrets cred ssh'. Valid actions: set, get, connect, export, list, sync, delete.\n", action)
		os.Exit(1)
	}
}

func runCredDBNamespace(args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printCredTypeUsage("db")
		os.Exit(0)
	}
	action := strings.ToLower(args[0])
	rest := args[1:]
	switch action {
	case "set", "create", "save":
		runCredDBSet(rest)
	case "get", "show", "inspect":
		runCredsGet(rest, "login")
	case "connect", "exec":
		runCredDBConnect(rest)
	case "list", "ls":
		runCredsList(rest, "login")
	case "delete", "rm":
		runCredsDelete(rest)
	case "sync", "sync-env":
		runCredsSync(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown action %q for 'ducksecrets cred db'. Valid actions: set, get, connect, list, sync, delete.\n", action)
		os.Exit(1)
	}
}

func runCredLoginNamespace(args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printCredTypeUsage("login")
		os.Exit(0)
	}
	action := strings.ToLower(args[0])
	rest := args[1:]
	switch action {
	case "set", "create", "save":
		runCredLoginSet(rest)
	case "get", "show", "inspect":
		runCredsGet(rest, "login")
	case "list", "ls":
		runCredsList(rest, "login")
	case "delete", "rm":
		runCredsDelete(rest)
	case "sync", "sync-env":
		runCredsSync(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown action %q for 'ducksecrets cred login'. Valid actions: set, get, list, sync, delete.\n", action)
		os.Exit(1)
	}
}

func runCredTLSNamespace(args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printCredTypeUsage("tls")
		os.Exit(0)
	}
	action := strings.ToLower(args[0])
	rest := args[1:]
	switch action {
	case "set", "create", "save":
		runCredTLSSet(rest)
	case "get", "show", "inspect":
		runCredsGet(rest, "tls_cert")
	case "export", "write":
		runCredTLSExport(rest)
	case "list", "ls":
		runCredsList(rest, "tls_cert")
	case "delete", "rm":
		runCredsDelete(rest)
	case "sync", "sync-env":
		runCredsSync(rest)
	case "connect":
		fmt.Fprintln(os.Stderr, "error: TLS certificates do not support 'connect' (a certificate is not a remote server).\nTo export PEM files to disk for nginx/caddy/envoy/curl, use:\n  ducksecrets cred tls export <name-or-id> --dir=./certs")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "unknown action %q for 'ducksecrets cred tls'. Valid actions: set, get, export, list, sync, delete.\n", action)
		os.Exit(1)
	}
}

func runCredAPINamespace(args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printCredTypeUsage("api")
		os.Exit(0)
	}
	action := strings.ToLower(args[0])
	rest := args[1:]
	switch action {
	case "set", "create", "save":
		runCredAPISet(rest)
	case "get", "show", "inspect":
		runCredsGet(rest, "oauth_api")
	case "list", "ls":
		runCredsList(rest, "oauth_api")
	case "delete", "rm":
		runCredsDelete(rest)
	case "sync", "sync-env":
		runCredsSync(rest)
	case "connect":
		fmt.Fprintln(os.Stderr, "error: API/OAuth credentials do not support 'connect'.\nTo export as environment variables or sync into a project, use:\n  ducksecrets cred api get <name-or-id> --format=env\n  ducksecrets cred api sync <name-or-id> --project=<slug> --env=<env>")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "unknown action %q for 'ducksecrets cred api'. Valid actions: set, get, list, sync, delete.\n", action)
		os.Exit(1)
	}
}

func printCredsUsage() {
	fmt.Print(`ducksecrets cred (or creds) — Manage and use typed credentials

Usage:
  ducksecrets cred <type> <action> [arguments]

Credential Types & Their Supported Actions:
  ssh     SSH Keypairs          actions: set, get, connect, export, list, sync, delete
  db      Databases             actions: set, get, connect, list, sync, delete
  login   Accounts & Logins     actions: set, get, list, sync, delete
  tls     TLS Certificates      actions: set, get, export, list, sync, delete
  api     API Keys & OAuth 2.0  actions: set, get, list, sync, delete

Global Actions (across all types):
  ducksecrets cred list [--project=...] [--kind=...]
  ducksecrets cred get <name-or-id> [--field=...] [--format=text|env|json]
  ducksecrets cred sync <name-or-id> --project=<slug> --env=<env> [--prefix=...]
  ducksecrets cred delete <name-or-id>

Type-Specific Examples:
  # 1. SSH Keys — supports 'connect' (opens ssh with ephemeral 0600 key) & 'export'
  ducksecrets cred ssh set "Bastion Prod" --generate=ed25519 --user=ubuntu --host=10.0.1.25 --port=22
  ducksecrets cred ssh connect "Bastion Prod"
  ducksecrets cred ssh export "Bastion Prod" --dir=~/.ssh/bastion

  # 2. Databases — supports 'connect' (opens psql, mysql, or redis-cli with password in memory)
  ducksecrets cred db set "Analytics PG" --engine=postgres --host=10.0.1.50 --db=analytics --user=readonly
  ducksecrets cred db connect "Analytics PG"

  # 3. TLS Certificates — supports 'export' (writes cert.pem, key.pem [0600], ca.pem to a directory)
  ducksecrets cred tls set "Wildcard Cert" --cert-file=./fullchain.pem --key-file=./privkey.pem
  ducksecrets cred tls export "Wildcard Cert" --dir=/etc/ssl/app

  # 4. API Keys & OAuth 2.0 — supports 'get --format=env' and 'sync'
  ducksecrets cred api set "Stripe Live" --provider=Stripe --api-key=sk_live_12345
  ducksecrets cred api get "Stripe Live" --format=env

  # 5. Account / Console Logins — supports 'get' and 'sync'
  ducksecrets cred login set "AWS Console" --user=admin@acme.com --url=https://console.aws.amazon.com
  ducksecrets cred login get "AWS Console" --field=password

Run 'ducksecrets cred <type> --help' for detailed flags of each credential type.
`)
}

func printCredTypeUsage(ns string) {
	switch ns {
	case "ssh":
		fmt.Print(`ducksecrets cred ssh — Manage SSH Keypair credentials

Actions:
  ducksecrets cred ssh set <name> [flags]
  ducksecrets cred ssh connect <name-or-id> [--host=...] [--user=...] [--port=...] [-- extra-ssh-args]
  ducksecrets cred ssh export <name-or-id> [--dir=.] [--name=id_ed25519]
  ducksecrets cred ssh get <name-or-id> [--field=private_key|public_key|fingerprint] [--out=file]
  ducksecrets cred ssh list [--project=...]
  ducksecrets cred ssh delete <name-or-id>

Flags for 'cred ssh set':
  --generate string     Generate a fresh SSH keypair on daemon: ed25519, rsa4096, ecdsa256
  --key-file string     Path to existing SSH private key file (e.g. ~/.ssh/id_ed25519)
  --private-key string  Raw SSH private key PEM string
  --pub-file string     Path to SSH public key file (auto-derived if private key is unencrypted)
  --public-key string   Raw SSH public key string
  --passphrase string   Optional passphrase if private key is encrypted
  --user string         Default SSH username (e.g. ubuntu, root, git)
  --host string         Target hostname or IP (e.g. 10.0.1.25, github.com)
  --port int            SSH port (default: 22)
  --project string      Optional project slug to bind credential to
  --env string          Optional environment slug (e.g. dev, staging, prod)
  --expires string      Optional expiration date (YYYY-MM-DD)
  --desc string         Optional description / notes
`)
	case "db":
		fmt.Print(`ducksecrets cred db — Manage Database credentials (PostgreSQL, MySQL, Redis)

Actions:
  ducksecrets cred db set <name> [flags]
  ducksecrets cred db connect <name-or-id> [--engine=postgres|mysql|redis] [-- extra-client-args]
  ducksecrets cred db get <name-or-id> [--field=password|username|host|port|database|url] [--format=text|env|json]
  ducksecrets cred db list [--project=...]
  ducksecrets cred db delete <name-or-id>

Flags for 'cred db set':
  --engine string       Database engine: postgres, mysql, redis (auto-sets default port & URI scheme)
  --host string         Database hostname or IP (required unless --uri is set)
  --port int            Database port (default: 5432 for postgres, 3306 for mysql, 6379 for redis)
  --db string           Database name (e.g. app_prod, analytics)
  --user string         Database username
  --password string     Database password (prompted hidden if omitted and stdin is a terminal)
  --uri string          Optional full connection URI (e.g. postgresql://user:pass@host:5432/db)
  --project string      Optional project slug to bind credential to
  --env string          Optional environment slug (e.g. dev, staging, prod)
  --expires string      Optional expiration date (YYYY-MM-DD)
  --desc string         Optional description / notes
`)
	case "login":
		fmt.Print(`ducksecrets cred login — Manage Account & Console login credentials

Actions:
  ducksecrets cred login set <name> [flags]
  ducksecrets cred login get <name-or-id> [--field=password|username|url|host] [--format=text|env|json]
  ducksecrets cred login list [--project=...]
  ducksecrets cred login sync <name-or-id> --project=<slug> --env=<env>
  ducksecrets cred login delete <name-or-id>

Flags for 'cred login set':
  --user string         Username, email, or principal (required)
  --password string     Password (prompted hidden if omitted and stdin is a terminal)
  --url string          Optional login / console URL (e.g. https://console.aws.amazon.com)
  --host string         Optional target hostname or IP
  --service string      Optional service or realm name
  --project string      Optional project slug to bind credential to
  --env string          Optional environment slug (e.g. dev, staging, prod)
  --expires string      Optional expiration date (YYYY-MM-DD)
  --desc string         Optional description / notes
`)
	case "tls":
		fmt.Print(`ducksecrets cred tls — Manage X.509 TLS Certificate credentials

Actions:
  ducksecrets cred tls set <name> [flags]
  ducksecrets cred tls export <name-or-id> [--dir=.] [--prefix=tls]
  ducksecrets cred tls get <name-or-id> [--field=cert|private_key|ca_chain|fingerprint] [--out=file]
  ducksecrets cred tls list [--project=...]
  ducksecrets cred tls delete <name-or-id>

Flags for 'cred tls set':
  --cert-file string    Path to X.509 certificate PEM file (fullchain or leaf)
  --cert string         Raw X.509 certificate PEM string
  --key-file string     Path to private key PEM file
  --private-key string  Raw private key PEM string
  --ca-file string      Optional path to intermediate / root CA bundle PEM file
  --ca-chain string     Optional raw CA chain PEM string
  --passphrase string   Optional private key passphrase
  --project string      Optional project slug to bind credential to
  --env string          Optional environment slug (e.g. dev, staging, prod)
  --expires string      Optional expiration date (auto-detected from X.509 NotAfter if omitted)
  --desc string         Optional description / notes

Flags for 'cred tls export':
  --dir string          Target directory to write PEM files (default: current directory ".")
  --cert-out string     Custom filename for certificate (default: cert.pem)
  --key-out string      Custom filename for private key, mode 0600 (default: key.pem)
  --ca-out string       Custom filename for CA chain (default: ca.pem)
`)
	case "api":
		fmt.Print(`ducksecrets cred api — Manage API Key & OAuth 2.0 credentials

Actions:
  ducksecrets cred api set <name> [flags]
  ducksecrets cred api get <name-or-id> [--field=api_key|client_id|client_secret] [--format=text|env|json]
  ducksecrets cred api sync <name-or-id> --project=<slug> --env=<env> [--prefix=...]
  ducksecrets cred api list [--project=...]
  ducksecrets cred api delete <name-or-id>

Flags for 'cred api set':
  --provider string       Service / provider name (e.g. Stripe, GitHub, AWS, OpenAI, Auth0)
  --api-key string        Bearer token, API key, or webhook secret
  --client-id string      OAuth Client ID or Access Key ID
  --client-secret string  OAuth Client Secret or Secret Access Key
  --token-url string      Optional OAuth 2.0 token endpoint URL
  --endpoint string       Optional base API endpoint URL
  --scopes string         Optional comma/space-separated scopes
  --project string        Optional project slug to bind credential to
  --env string            Optional environment slug (e.g. dev, staging, prod)
  --expires string        Optional expiration date (YYYY-MM-DD)
  --desc string           Optional description / notes
`)
	}
}

func readFileExpanded(path string) string {
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, path[2:])
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading file %s: %v\n", path, err)
		os.Exit(1)
	}
	return string(data)
}

func parseCredentialExpires(raw string) *time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return &t
	}
	if t, err := time.Parse("2006-01-02", raw); err == nil {
		endOfDay := time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.UTC)
		return &endOfDay
	}
	fmt.Fprintf(os.Stderr, "error: invalid --expires format %q (use YYYY-MM-DD or RFC3339)\n", raw)
	os.Exit(1)
	return nil
}

func saveCredentialUpsert(cfg cliConfig, existing *cliCredential, name, kind, desc, project, envName string, expTime *time.Time, payload cliCredentialPayload) {
	reqBody := map[string]any{
		"name":    name,
		"kind":    kind,
		"payload": payload,
	}
	if desc != "" || existing == nil {
		reqBody["description"] = desc
	}
	if project != "" {
		reqBody["project_id"] = strings.TrimSpace(project)
	}
	if envName != "" {
		reqBody["environment_slug"] = strings.TrimSpace(envName)
	}
	if expTime != nil {
		reqBody["expires_at"] = expTime.Format(time.RFC3339)
	}

	var resp *http.Response
	var err error
	if existing != nil {
		resp, err = authedRequest(cfg, http.MethodPatch, "/api/v1/credentials/"+url.PathEscape(existing.ID), reqBody)
	} else {
		resp, err = authedRequest(cfg, http.MethodPost, "/api/v1/credentials", reqBody)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "failed to save credential (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
		os.Exit(1)
	}

	var saved cliCredential
	if err := json.NewDecoder(resp.Body).Decode(&saved); err != nil {
		fmt.Fprintf(os.Stderr, "error decoding response: %v\n", err)
		os.Exit(1)
	}

	action := "created"
	if existing != nil {
		action = "updated"
	}
	fmt.Printf("✓ Credential %q (%s) %s! [id: %s]\n", saved.Name, saved.Kind, action, saved.ID)
	if saved.Summary != "" {
		fmt.Printf("  Summary: %s\n", saved.Summary)
	}
}

// 1. `ducksecrets cred ssh set <name>`
func runCredSSHSet(args []string) {
	fs := flag.NewFlagSet("cred ssh set", flag.ExitOnError)
	genAlgo := fs.String("generate", "", "Generate fresh SSH keypair on daemon: ed25519, rsa4096, ecdsa256")
	genSSHAlias := fs.String("generate-ssh", "", "Alias for --generate")
	keyFile := fs.String("key-file", "", "Path to SSH private key file (e.g. ~/.ssh/id_ed25519)")
	privKeyFileAlias := fs.String("private-key-file", "", "Alias for --key-file")
	privKey := fs.String("private-key", "", "Raw SSH private key PEM")
	pubFile := fs.String("pub-file", "", "Path to SSH public key file")
	pubKeyFileAlias := fs.String("public-key-file", "", "Alias for --pub-file")
	pubKey := fs.String("public-key", "", "Raw SSH public key")
	passphrase := fs.String("passphrase", "", "Optional private key passphrase")
	user := fs.String("user", "", "Default SSH username (e.g. ubuntu, root, git)")
	host := fs.String("host", "", "Target host or bastion IP")
	port := fs.Int("port", 22, "SSH port (default: 22)")
	desc := fs.String("desc", "", "Optional description / notes")
	project := fs.String("project", "", "Optional project slug")
	envName := fs.String("env", "", "Optional environment slug")
	expires := fs.String("expires", "", "Optional expiration date (YYYY-MM-DD)")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	valFlags := map[string]bool{
		"-generate": true, "--generate": true,
		"-generate-ssh": true, "--generate-ssh": true,
		"-key-file": true, "--key-file": true,
		"-private-key-file": true, "--private-key-file": true,
		"-private-key": true, "--private-key": true,
		"-pub-file": true, "--pub-file": true,
		"-public-key-file": true, "--public-key-file": true,
		"-public-key": true, "--public-key": true,
		"-passphrase": true, "--passphrase": true,
		"-user": true, "--user": true,
		"-host": true, "--host": true,
		"-port": true, "--port": true,
		"-desc": true, "--desc": true,
		"-project": true, "--project": true,
		"-env": true, "--env": true,
		"-expires": true, "--expires": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	flagArgs, posArgs := splitFlagsAndPositional(args, valFlags)
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		printCredTypeUsage("ssh")
		os.Exit(1)
	}
	name := strings.TrimSpace(posArgs[0])

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)

	existing, _ := resolveCredentialByNameOrID(cfg, name, strings.TrimSpace(*project), strings.TrimSpace(*envName))
	payload := cliCredentialPayload{Port: 22}
	if existing != nil && existing.Payload != nil {
		payload = *existing.Payload
	}

	algo := strings.TrimSpace(*genAlgo)
	if algo == "" {
		algo = strings.TrimSpace(*genSSHAlias)
	}
	if algo != "" {
		genResp, err := authedRequest(cfg, http.MethodPost, "/api/v1/credentials/generate-ssh", map[string]string{
			"algorithm": algo,
			"comment":   name,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error generating SSH keypair: %v\n", err)
			os.Exit(1)
		}
		defer genResp.Body.Close()
		if genResp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(genResp.Body)
			fmt.Fprintf(os.Stderr, "SSH key generation failed (%d): %s\n", genResp.StatusCode, strings.TrimSpace(string(b)))
			os.Exit(1)
		}
		var genData struct {
			PrivateKey  string `json:"private_key"`
			PublicKey   string `json:"public_key"`
			Fingerprint string `json:"fingerprint"`
			KeyType     string `json:"key_type"`
		}
		if err := json.NewDecoder(genResp.Body).Decode(&genData); err != nil {
			fmt.Fprintf(os.Stderr, "error decoding generated SSH key: %v\n", err)
			os.Exit(1)
		}
		payload.PrivateKey = genData.PrivateKey
		payload.PublicKey = genData.PublicKey
		payload.Fingerprint = genData.Fingerprint
		payload.KeyType = genData.KeyType
	}

	kf := *keyFile
	if kf == "" {
		kf = *privKeyFileAlias
	}
	if v := readFileExpanded(kf); v != "" {
		payload.PrivateKey = v
	} else if *privKey != "" {
		payload.PrivateKey = *privKey
	}

	pf := *pubFile
	if pf == "" {
		pf = *pubKeyFileAlias
	}
	if v := readFileExpanded(pf); v != "" {
		payload.PublicKey = v
	} else if *pubKey != "" {
		payload.PublicKey = *pubKey
	}

	if *passphrase != "" {
		payload.Passphrase = *passphrase
	}
	if *user != "" {
		payload.Username = *user
	}
	if *host != "" {
		payload.Host = *host
	}
	if *port > 0 {
		payload.Port = *port
	}

	if strings.TrimSpace(payload.PrivateKey) == "" {
		fmt.Fprintln(os.Stderr, "error: SSH credential requires a private key. Pass --generate=ed25519 or --key-file=~/.ssh/id_ed25519")
		os.Exit(1)
	}

	saveCredentialUpsert(cfg, existing, name, "ssh_key", *desc, *project, *envName, parseCredentialExpires(*expires), payload)
}

// `ducksecrets cred ssh export <name>`
func runCredSSHExport(args []string) {
	fs := flag.NewFlagSet("cred ssh export", flag.ExitOnError)
	dir := fs.String("dir", ".", "Target directory to write SSH key files")
	baseName := fs.String("name", "id_ducksecrets", "Base filename for private key (and <name>.pub for public key)")
	project := fs.String("project", "", "Project slug filter")
	envName := fs.String("env", "", "Environment slug filter")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	valFlags := map[string]bool{
		"-dir": true, "--dir": true,
		"-name": true, "--name": true,
		"-project": true, "--project": true,
		"-env": true, "--env": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	flagArgs, posArgs := splitFlagsAndPositional(args, valFlags)
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: credential name or ID is required.\nUsage: ducksecrets cred ssh export <name-or-id> [--dir=.] [--name=id_ed25519]")
		os.Exit(1)
	}
	target := posArgs[0]

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)

	cred, err := resolveCredentialByNameOrID(cfg, target, strings.TrimSpace(*project), strings.TrimSpace(*envName))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if cred.Kind != "ssh_key" || cred.Payload == nil {
		fmt.Fprintf(os.Stderr, "error: %q is not an SSH key credential\n", cred.Name)
		os.Exit(1)
	}

	targetDir := *dir
	if strings.HasPrefix(targetDir, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			targetDir = filepath.Join(home, targetDir[2:])
		}
	}
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "error creating directory %s: %v\n", targetDir, err)
		os.Exit(1)
	}

	privPath := filepath.Join(targetDir, *baseName)
	if err := os.WriteFile(privPath, []byte(strings.TrimSpace(cred.Payload.PrivateKey)+"\n"), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing private key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Private key written to %s (mode 0600)\n", privPath)

	if strings.TrimSpace(cred.Payload.PublicKey) != "" {
		pubPath := filepath.Join(targetDir, *baseName+".pub")
		if err := os.WriteFile(pubPath, []byte(strings.TrimSpace(cred.Payload.PublicKey)+"\n"), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing public key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Public key written to  %s (mode 0644)\n", pubPath)
	}
}

// `ducksecrets cred tls export <name>`
func runCredTLSExport(args []string) {
	fs := flag.NewFlagSet("cred tls export", flag.ExitOnError)
	dir := fs.String("dir", ".", "Target directory to write PEM files")
	certOut := fs.String("cert-out", "cert.pem", "Certificate PEM filename")
	keyOut := fs.String("key-out", "key.pem", "Private key PEM filename (mode 0600)")
	caOut := fs.String("ca-out", "ca.pem", "CA chain PEM filename")
	project := fs.String("project", "", "Project slug filter")
	envName := fs.String("env", "", "Environment slug filter")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	valFlags := map[string]bool{
		"-dir": true, "--dir": true,
		"-cert-out": true, "--cert-out": true,
		"-key-out": true, "--key-out": true,
		"-ca-out": true, "--ca-out": true,
		"-project": true, "--project": true,
		"-env": true, "--env": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	flagArgs, posArgs := splitFlagsAndPositional(args, valFlags)
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: credential name or ID is required.\nUsage: ducksecrets cred tls export <name-or-id> [--dir=./certs]")
		os.Exit(1)
	}
	target := posArgs[0]

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)

	cred, err := resolveCredentialByNameOrID(cfg, target, strings.TrimSpace(*project), strings.TrimSpace(*envName))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if cred.Kind != "tls_cert" || cred.Payload == nil {
		fmt.Fprintf(os.Stderr, "error: %q is not a TLS certificate credential\n", cred.Name)
		os.Exit(1)
	}

	targetDir := *dir
	if strings.HasPrefix(targetDir, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			targetDir = filepath.Join(home, targetDir[2:])
		}
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating directory %s: %v\n", targetDir, err)
		os.Exit(1)
	}

	if strings.TrimSpace(cred.Payload.Certificate) != "" {
		cPath := filepath.Join(targetDir, *certOut)
		if err := os.WriteFile(cPath, []byte(strings.TrimSpace(cred.Payload.Certificate)+"\n"), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing certificate: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Certificate written to %s (mode 0644)\n", cPath)
	}
	if strings.TrimSpace(cred.Payload.PrivateKey) != "" {
		kPath := filepath.Join(targetDir, *keyOut)
		if err := os.WriteFile(kPath, []byte(strings.TrimSpace(cred.Payload.PrivateKey)+"\n"), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "error writing private key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Private key written to %s (mode 0600)\n", kPath)
	}
	if strings.TrimSpace(cred.Payload.CAChain) != "" {
		caPath := filepath.Join(targetDir, *caOut)
		if err := os.WriteFile(caPath, []byte(strings.TrimSpace(cred.Payload.CAChain)+"\n"), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing CA bundle: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ CA bundle written to   %s (mode 0644)\n", caPath)
	}
}

// 2. `ducksecrets cred db set <name>`
func runCredDBSet(args []string) {
	fs := flag.NewFlagSet("cred db set", flag.ExitOnError)
	engine := fs.String("engine", "", "Database engine: postgres, mysql, redis")
	host := fs.String("host", "", "Database hostname or IP")
	port := fs.Int("port", 0, "Database port (default: 5432 postgres, 3306 mysql, 6379 redis)")
	database := fs.String("db", "", "Database name")
	user := fs.String("user", "", "Database username")
	password := fs.String("password", "", "Database password (prompted hidden if omitted)")
	uri := fs.String("uri", "", "Full connection URI (e.g. postgresql://user:pass@host:5432/dbname)")
	desc := fs.String("desc", "", "Optional description / notes")
	project := fs.String("project", "", "Optional project slug")
	envName := fs.String("env", "", "Optional environment slug")
	expires := fs.String("expires", "", "Optional expiration date (YYYY-MM-DD)")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	valFlags := map[string]bool{
		"-engine": true, "--engine": true,
		"-host": true, "--host": true,
		"-port": true, "--port": true,
		"-db": true, "--db": true,
		"-user": true, "--user": true,
		"-password": true, "--password": true,
		"-uri": true, "--uri": true,
		"-desc": true, "--desc": true,
		"-project": true, "--project": true,
		"-env": true, "--env": true,
		"-expires": true, "--expires": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	flagArgs, posArgs := splitFlagsAndPositional(args, valFlags)
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		printCredTypeUsage("db")
		os.Exit(1)
	}
	name := strings.TrimSpace(posArgs[0])

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)

	existing, _ := resolveCredentialByNameOrID(cfg, name, strings.TrimSpace(*project), strings.TrimSpace(*envName))
	payload := cliCredentialPayload{}
	if existing != nil && existing.Payload != nil {
		payload = *existing.Payload
	}

	if strings.TrimSpace(*uri) != "" {
		payload.URL = strings.TrimSpace(*uri)
		if u, err := url.Parse(payload.URL); err == nil {
			if u.Hostname() != "" && *host == "" {
				payload.Host = u.Hostname()
			}
			if pStr := u.Port(); pStr != "" && *port == 0 {
				if pNum, err := strconv.Atoi(pStr); err == nil {
					payload.Port = pNum
				}
			}
			if u.User != nil {
				if u.User.Username() != "" && *user == "" {
					payload.Username = u.User.Username()
				}
				if pw, ok := u.User.Password(); ok && pw != "" && *password == "" {
					payload.Password = pw
				}
			}
			if dbPath := strings.TrimPrefix(u.Path, "/"); dbPath != "" && *database == "" {
				payload.Database = dbPath
			}
		}
	}

	eng := strings.ToLower(strings.TrimSpace(*engine))
	if *host != "" {
		payload.Host = *host
	}
	if *port > 0 {
		payload.Port = *port
	} else if payload.Port == 0 {
		switch eng {
		case "postgres", "pg", "postgresql":
			payload.Port = 5432
		case "mysql", "mariadb":
			payload.Port = 3306
		case "redis":
			payload.Port = 6379
		}
	}
	if *database != "" {
		payload.Database = *database
	}
	if *user != "" {
		payload.Username = *user
	}
	if *password != "" {
		payload.Password = *password
	} else if payload.Password == "" {
		if info, err := os.Stdin.Stat(); err == nil && (info.Mode()&os.ModeCharDevice) != 0 {
			payload.Password = readPasswordPrompt(fmt.Sprintf("Database password for %s (leave empty if none): ", name))
		}
	}

	if payload.Host == "" && payload.URL == "" {
		fmt.Fprintln(os.Stderr, "error: database credential requires --host=<hostname> or --uri=<connection-uri>")
		os.Exit(1)
	}

	if payload.URL == "" && payload.Host != "" {
		scheme := eng
		if scheme == "" {
			switch payload.Port {
			case 3306:
				scheme = "mysql"
			case 6379:
				scheme = "redis"
			default:
				scheme = "postgresql"
			}
		} else if scheme == "postgres" || scheme == "pg" {
			scheme = "postgresql"
		}
		if payload.Username != "" {
			if payload.Database != "" {
				payload.URL = fmt.Sprintf("%s://%s@%s:%d/%s", scheme, payload.Username, payload.Host, payload.Port, payload.Database)
			} else {
				payload.URL = fmt.Sprintf("%s://%s@%s:%d", scheme, payload.Username, payload.Host, payload.Port)
			}
		}
	}

	saveCredentialUpsert(cfg, existing, name, "login", *desc, *project, *envName, parseCredentialExpires(*expires), payload)
}

// 3. `ducksecrets cred login set <name>`
func runCredLoginSet(args []string) {
	fs := flag.NewFlagSet("cred login set", flag.ExitOnError)
	user := fs.String("user", "", "Username, email, or principal")
	password := fs.String("password", "", "Password (prompted hidden if omitted)")
	host := fs.String("host", "", "Optional target host or IP")
	port := fs.Int("port", 0, "Optional port")
	loginURL := fs.String("url", "", "Optional login or console URL")
	service := fs.String("service", "", "Optional service or realm name")
	desc := fs.String("desc", "", "Optional description / notes")
	project := fs.String("project", "", "Optional project slug")
	envName := fs.String("env", "", "Optional environment slug")
	expires := fs.String("expires", "", "Optional expiration date (YYYY-MM-DD)")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	valFlags := map[string]bool{
		"-user": true, "--user": true,
		"-password": true, "--password": true,
		"-host": true, "--host": true,
		"-port": true, "--port": true,
		"-url": true, "--url": true,
		"-service": true, "--service": true,
		"-desc": true, "--desc": true,
		"-project": true, "--project": true,
		"-env": true, "--env": true,
		"-expires": true, "--expires": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	flagArgs, posArgs := splitFlagsAndPositional(args, valFlags)
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		printCredTypeUsage("login")
		os.Exit(1)
	}
	name := strings.TrimSpace(posArgs[0])

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)

	existing, _ := resolveCredentialByNameOrID(cfg, name, strings.TrimSpace(*project), strings.TrimSpace(*envName))
	payload := cliCredentialPayload{}
	if existing != nil && existing.Payload != nil {
		payload = *existing.Payload
	}

	if *user != "" {
		payload.Username = *user
	}
	if payload.Username == "" {
		fmt.Fprintln(os.Stderr, "error: login credential requires --user=<username>")
		os.Exit(1)
	}
	if *password != "" {
		payload.Password = *password
	} else if payload.Password == "" {
		if info, err := os.Stdin.Stat(); err == nil && (info.Mode()&os.ModeCharDevice) != 0 {
			payload.Password = readPasswordPrompt(fmt.Sprintf("Password for %s (%s): ", name, payload.Username))
		}
	}
	if *host != "" {
		payload.Host = *host
	}
	if *port > 0 {
		payload.Port = *port
	}
	if *loginURL != "" {
		payload.URL = *loginURL
	}
	if *service != "" {
		payload.Database = *service
	}

	saveCredentialUpsert(cfg, existing, name, "login", *desc, *project, *envName, parseCredentialExpires(*expires), payload)
}

// 4. `ducksecrets cred tls set <name>`
func runCredTLSSet(args []string) {
	fs := flag.NewFlagSet("cred tls set", flag.ExitOnError)
	certFile := fs.String("cert-file", "", "Path to X.509 certificate PEM file")
	cert := fs.String("cert", "", "Raw X.509 certificate PEM string")
	keyFile := fs.String("key-file", "", "Path to private key PEM file")
	privKeyFileAlias := fs.String("private-key-file", "", "Alias for --key-file")
	privKey := fs.String("private-key", "", "Raw private key PEM string")
	caFile := fs.String("ca-file", "", "Optional path to CA chain PEM file")
	caChainFileAlias := fs.String("ca-chain-file", "", "Alias for --ca-file")
	caChain := fs.String("ca-chain", "", "Optional raw CA chain PEM string")
	passphrase := fs.String("passphrase", "", "Optional private key passphrase")
	desc := fs.String("desc", "", "Optional description / notes")
	project := fs.String("project", "", "Optional project slug")
	envName := fs.String("env", "", "Optional environment slug")
	expires := fs.String("expires", "", "Optional expiration date (auto-detected from cert if omitted)")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	valFlags := map[string]bool{
		"-cert-file": true, "--cert-file": true,
		"-cert": true, "--cert": true,
		"-key-file": true, "--key-file": true,
		"-private-key-file": true, "--private-key-file": true,
		"-private-key": true, "--private-key": true,
		"-ca-file": true, "--ca-file": true,
		"-ca-chain-file": true, "--ca-chain-file": true,
		"-ca-chain": true, "--ca-chain": true,
		"-passphrase": true, "--passphrase": true,
		"-desc": true, "--desc": true,
		"-project": true, "--project": true,
		"-env": true, "--env": true,
		"-expires": true, "--expires": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	flagArgs, posArgs := splitFlagsAndPositional(args, valFlags)
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		printCredTypeUsage("tls")
		os.Exit(1)
	}
	name := strings.TrimSpace(posArgs[0])

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)

	existing, _ := resolveCredentialByNameOrID(cfg, name, strings.TrimSpace(*project), strings.TrimSpace(*envName))
	payload := cliCredentialPayload{}
	if existing != nil && existing.Payload != nil {
		payload = *existing.Payload
	}

	if v := readFileExpanded(*certFile); v != "" {
		payload.Certificate = v
	} else if *cert != "" {
		payload.Certificate = *cert
	}

	kf := *keyFile
	if kf == "" {
		kf = *privKeyFileAlias
	}
	if v := readFileExpanded(kf); v != "" {
		payload.PrivateKey = v
	} else if *privKey != "" {
		payload.PrivateKey = *privKey
	}

	cf := *caFile
	if cf == "" {
		cf = *caChainFileAlias
	}
	if v := readFileExpanded(cf); v != "" {
		payload.CAChain = v
	} else if *caChain != "" {
		payload.CAChain = *caChain
	}

	if *passphrase != "" {
		payload.Passphrase = *passphrase
	}

	if strings.TrimSpace(payload.Certificate) == "" {
		fmt.Fprintln(os.Stderr, "error: TLS credential requires a certificate PEM (--cert-file or --cert)")
		os.Exit(1)
	}

	saveCredentialUpsert(cfg, existing, name, "tls_cert", *desc, *project, *envName, parseCredentialExpires(*expires), payload)
}

// 5. `ducksecrets cred api set <name>`
func runCredAPISet(args []string) {
	fs := flag.NewFlagSet("cred api set", flag.ExitOnError)
	provider := fs.String("provider", "", "Service / provider name (e.g. Stripe, GitHub, AWS, OpenAI)")
	apiKey := fs.String("api-key", "", "Bearer / API token")
	tokenAlias := fs.String("token", "", "Alias for --api-key")
	clientID := fs.String("client-id", "", "OAuth Client ID or Access Key ID")
	clientSecret := fs.String("client-secret", "", "OAuth Client Secret or Secret Access Key")
	tokenURL := fs.String("token-url", "", "Optional OAuth Token URL")
	endpoint := fs.String("endpoint", "", "Optional Base API Endpoint URL")
	endpointAlias := fs.String("endpoint-url", "", "Alias for --endpoint")
	scopes := fs.String("scopes", "", "Optional OAuth scopes or permissions")
	desc := fs.String("desc", "", "Optional description / notes")
	project := fs.String("project", "", "Optional project slug")
	envName := fs.String("env", "", "Optional environment slug")
	expires := fs.String("expires", "", "Optional expiration date (YYYY-MM-DD)")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	valFlags := map[string]bool{
		"-provider": true, "--provider": true,
		"-api-key": true, "--api-key": true,
		"-token": true, "--token": true,
		"-client-id": true, "--client-id": true,
		"-client-secret": true, "--client-secret": true,
		"-token-url": true, "--token-url": true,
		"-endpoint": true, "--endpoint": true,
		"-endpoint-url": true, "--endpoint-url": true,
		"-scopes": true, "--scopes": true,
		"-desc": true, "--desc": true,
		"-project": true, "--project": true,
		"-env": true, "--env": true,
		"-expires": true, "--expires": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	flagArgs, posArgs := splitFlagsAndPositional(args, valFlags)
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		printCredTypeUsage("api")
		os.Exit(1)
	}
	name := strings.TrimSpace(posArgs[0])

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)

	existing, _ := resolveCredentialByNameOrID(cfg, name, strings.TrimSpace(*project), strings.TrimSpace(*envName))
	payload := cliCredentialPayload{}
	if existing != nil && existing.Payload != nil {
		payload = *existing.Payload
	}

	if *provider != "" {
		payload.Provider = *provider
	}
	ak := *apiKey
	if ak == "" {
		ak = *tokenAlias
	}
	if ak != "" {
		payload.APIKey = ak
	}
	if *clientID != "" {
		payload.ClientID = *clientID
	}
	if *clientSecret != "" {
		payload.ClientSecret = *clientSecret
	}
	if *tokenURL != "" {
		payload.TokenURL = *tokenURL
	}
	ep := *endpoint
	if ep == "" {
		ep = *endpointAlias
	}
	if ep != "" {
		payload.EndpointURL = ep
	}
	if *scopes != "" {
		payload.Scopes = *scopes
	}

	if payload.APIKey == "" && payload.ClientID == "" && payload.ClientSecret == "" {
		fmt.Fprintln(os.Stderr, "error: API/OAuth credential requires at least --api-key or --client-id / --client-secret")
		os.Exit(1)
	}

	saveCredentialUpsert(cfg, existing, name, "oauth_api", *desc, *project, *envName, parseCredentialExpires(*expires), payload)
}

func resolveCredentialByNameOrID(cfg cliConfig, target, projectFilter, envFilter string) (*cliCredential, error) {
	list, err := fetchCredentialList(cfg, projectFilter, envFilter, "")
	if err != nil {
		return nil, err
	}

	var matched *cliCredential
	for i := range list {
		if list[i].ID == target {
			matched = &list[i]
			break
		}
	}
	if matched == nil {
		for i := range list {
			if strings.EqualFold(list[i].Name, target) {
				matched = &list[i]
				if projectFilter != "" && (list[i].ProjectSlug == projectFilter || (list[i].ProjectID != nil && *list[i].ProjectID == projectFilter)) {
					break
				}
			}
		}
	}
	if matched == nil {
		return nil, fmt.Errorf("credential %q not found", target)
	}

	resp, err := authedRequest(cfg, http.MethodGet, "/api/v1/credentials/"+url.PathEscape(matched.ID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get credential (%d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var full cliCredential
	if err := json.NewDecoder(resp.Body).Decode(&full); err != nil {
		return nil, err
	}
	return &full, nil
}

func fetchCredentialList(cfg cliConfig, projectFilter, envFilter, kindFilter string) ([]cliCredential, error) {
	q := url.Values{}
	if envFilter != "" {
		q.Set("environment_slug", envFilter)
	}
	if kindFilter != "" {
		q.Set("kind", kindFilter)
	}

	path := "/api/v1/credentials"
	if projectFilter != "" {
		path = fmt.Sprintf("/api/v1/projects/%s/credentials", url.PathEscape(projectFilter))
	}
	if encQ := q.Encode(); encQ != "" {
		path += "?" + encQ
	}

	resp, err := authedRequest(cfg, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list credentials (%d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var list cliCredentialList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func runCredsList(args []string, defaultKind string) {
	fs := flag.NewFlagSet("cred list", flag.ExitOnError)
	project := fs.String("project", "", "Filter by project slug or ID")
	envName := fs.String("env", "", "Filter by environment slug")
	kind := fs.String("kind", defaultKind, "Filter by kind: ssh_key, tls_cert, oauth_api, login")
	format := fs.String("format", "table", "Output format: table, json")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)
	fs.Parse(args)

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)

	items, err := fetchCredentialList(cfg, strings.TrimSpace(*project), strings.TrimSpace(*envName), strings.TrimSpace(*kind))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if strings.EqualFold(*format, "json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(items)
		return
	}

	if len(items) == 0 {
		fmt.Println("No credentials found.")
		return
	}

	fmt.Printf("%-24s  %-12s  %-22s  %-30s  %-16s\n", "NAME", "KIND", "SCOPE", "SUMMARY", "ID")
	fmt.Println(strings.Repeat("-", 112))
	for _, c := range items {
		scope := "Global Vault"
		if c.ProjectSlug != "" {
			if c.EnvironmentSlug != "" {
				scope = fmt.Sprintf("%s (%s)", c.ProjectSlug, c.EnvironmentSlug)
			} else {
				scope = fmt.Sprintf("%s (*)", c.ProjectSlug)
			}
		} else if c.ProjectID != nil && *c.ProjectID != "" {
			scope = *c.ProjectID
		}
		name := c.Name
		if len(name) > 24 {
			name = name[:21] + "..."
		}
		summary := c.Summary
		if len(summary) > 30 {
			summary = summary[:27] + "..."
		}
		fmt.Printf("%-24s  %-12s  %-22s  %-30s  %-16s\n", name, c.Kind, scope, summary, c.ID)
	}
}

func extractCredentialField(pay *cliCredentialPayload, field string) (string, error) {
	if pay == nil {
		return "", fmt.Errorf("credential payload is empty")
	}
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "private_key", "private-key", "privkey", "key":
		return pay.PrivateKey, nil
	case "public_key", "public-key", "pubkey", "pub":
		return pay.PublicKey, nil
	case "passphrase":
		return pay.Passphrase, nil
	case "fingerprint":
		return pay.Fingerprint, nil
	case "host", "hostname":
		return pay.Host, nil
	case "port":
		if pay.Port > 0 {
			return strconv.Itoa(pay.Port), nil
		}
		return "", nil
	case "username", "user":
		return pay.Username, nil
	case "password", "pass":
		return pay.Password, nil
	case "certificate", "cert":
		return pay.Certificate, nil
	case "ca_chain", "ca-chain", "ca":
		return pay.CAChain, nil
	case "subject":
		return pay.Subject, nil
	case "issuer":
		return pay.Issuer, nil
	case "provider":
		return pay.Provider, nil
	case "client_id", "client-id":
		return pay.ClientID, nil
	case "client_secret", "client-secret":
		return pay.ClientSecret, nil
	case "api_key", "api-key", "token":
		return pay.APIKey, nil
	case "token_url", "token-url":
		return pay.TokenURL, nil
	case "endpoint_url", "endpoint-url", "endpoint":
		return pay.EndpointURL, nil
	case "scopes", "scope":
		return pay.Scopes, nil
	case "url", "uri":
		return pay.URL, nil
	case "database", "db":
		return pay.Database, nil
	case "notes", "note":
		return pay.Notes, nil
	default:
		return "", fmt.Errorf("unknown credential field %q (valid: private_key, public_key, passphrase, username, password, host, port, database, url, certificate, ca_chain, client_id, client_secret, api_key, token_url, endpoint_url, scopes)", field)
	}
}

var cliEnvPrefixRegex = regexp.MustCompile(`[^A-Z0-9_]+`)

func sanitizeCLIEnvPrefix(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = cliEnvPrefixRegex.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		return "CRED"
	}
	return s
}

func credentialToEnvMap(cred *cliCredential, customPrefix string) map[string]string {
	prefix := customPrefix
	if strings.TrimSpace(prefix) == "" {
		prefix = cred.Name
	}
	p := sanitizeCLIEnvPrefix(prefix)
	out := make(map[string]string)
	pay := cred.Payload
	if pay == nil {
		return out
	}
	add := func(suffix, val string) {
		if strings.TrimSpace(val) != "" {
			out[p+"_"+suffix] = val
		}
	}

	switch cred.Kind {
	case "ssh_key":
		add("PRIVATE_KEY", pay.PrivateKey)
		add("PUBLIC_KEY", pay.PublicKey)
		add("PASSPHRASE", pay.Passphrase)
		add("HOST", pay.Host)
		if pay.Port > 0 {
			add("PORT", strconv.Itoa(pay.Port))
		}
		add("USER", pay.Username)
		add("FINGERPRINT", pay.Fingerprint)
	case "tls_cert":
		add("CERT", pay.Certificate)
		add("PRIVATE_KEY", pay.PrivateKey)
		add("CA_CHAIN", pay.CAChain)
		add("PASSPHRASE", pay.Passphrase)
	case "oauth_api":
		add("CLIENT_ID", pay.ClientID)
		add("CLIENT_SECRET", pay.ClientSecret)
		add("API_KEY", pay.APIKey)
		add("TOKEN_URL", pay.TokenURL)
		add("ENDPOINT_URL", pay.EndpointURL)
		add("SCOPES", pay.Scopes)
	case "login":
		add("USERNAME", pay.Username)
		add("PASSWORD", pay.Password)
		add("URL", pay.URL)
		add("HOST", pay.Host)
		if pay.Port > 0 {
			add("PORT", strconv.Itoa(pay.Port))
		}
		add("DATABASE", pay.Database)
	}
	return out
}

func runCredsGet(args []string, expectedKind string) {
	fs := flag.NewFlagSet("cred get", flag.ExitOnError)
	project := fs.String("project", "", "Project slug or ID filter")
	envName := fs.String("env", "", "Environment slug filter")
	field := fs.String("field", "", "Extract a single raw field value (e.g. private_key, public_key, password, api_key)")
	format := fs.String("format", "text", "Output format: text, json, env")
	prefix := fs.String("prefix", "", "Variable prefix when --format=env (default: credential name)")
	outFile := fs.String("out", "", "Write output to file (with 0600 permissions)")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	valFlags := map[string]bool{
		"-project": true, "--project": true,
		"-env": true, "--env": true,
		"-field": true, "--field": true,
		"-format": true, "--format": true,
		"-prefix": true, "--prefix": true,
		"-out": true, "--out": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	flagArgs, posArgs := splitFlagsAndPositional(args, valFlags)
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: credential name or ID is required.\nUsage: ducksecrets cred get <name-or-id> [--field=private_key] [--format=text|json|env]")
		os.Exit(1)
	}
	target := posArgs[0]

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)

	cred, err := resolveCredentialByNameOrID(cfg, target, strings.TrimSpace(*project), strings.TrimSpace(*envName))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if expectedKind != "" && cred.Kind != expectedKind {
		fmt.Fprintf(os.Stderr, "error: credential %q is of kind %q, not %q\n", cred.Name, cred.Kind, expectedKind)
		os.Exit(1)
	}

	var output string
	if *field != "" {
		val, fErr := extractCredentialField(cred.Payload, *field)
		if fErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", fErr)
			os.Exit(1)
		}
		output = val
		if !strings.HasSuffix(output, "\n") {
			output += "\n"
		}
	} else {
		switch strings.ToLower(strings.TrimSpace(*format)) {
		case "json":
			b, err := json.MarshalIndent(cred, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "error encoding json: %v\n", err)
				os.Exit(1)
			}
			output = string(b) + "\n"
		case "env", "dotenv":
			envMap := credentialToEnvMap(cred, *prefix)
			s, err := formatExportSecrets(envMap, "dotenv")
			if err != nil {
				fmt.Fprintf(os.Stderr, "error formatting env: %v\n", err)
				os.Exit(1)
			}
			output = s
		default:
			output = formatCredentialText(cred)
		}
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(output), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "error writing to %s: %v\n", *outFile, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "✓ Written to %s (mode 0600)\n", *outFile)
		return
	}

	fmt.Print(output)
}

func formatCredentialText(c *cliCredential) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Name:         %s\n", c.Name)
	fmt.Fprintf(&b, "ID:           %s\n", c.ID)
	fmt.Fprintf(&b, "Kind:         %s\n", c.Kind)
	scope := "Global Vault"
	if c.ProjectSlug != "" {
		if c.EnvironmentSlug != "" {
			scope = fmt.Sprintf("%s (%s)", c.ProjectSlug, c.EnvironmentSlug)
		} else {
			scope = fmt.Sprintf("%s (All Environments)", c.ProjectSlug)
		}
	}
	fmt.Fprintf(&b, "Scope:        %s\n", scope)
	if c.Description != "" {
		fmt.Fprintf(&b, "Description:  %s\n", c.Description)
	}
	if c.Summary != "" {
		fmt.Fprintf(&b, "Summary:      %s\n", c.Summary)
	}
	if c.ExpiresAt != nil {
		fmt.Fprintf(&b, "Expires At:   %s\n", c.ExpiresAt.Format(time.RFC3339))
	}

	p := c.Payload
	if p == nil {
		return b.String()
	}
	b.WriteString(strings.Repeat("-", 60) + "\n")

	addField := func(label, val string) {
		if strings.TrimSpace(val) != "" {
			fmt.Fprintf(&b, "%-14s %s\n", label+":", val)
		}
	}
	addField("Provider", p.Provider)
	addField("Username", p.Username)
	addField("Password", p.Password)
	addField("Host", p.Host)
	if p.Port > 0 {
		addField("Port", strconv.Itoa(p.Port))
	}
	addField("Database", p.Database)
	addField("URL", p.URL)
	addField("Client ID", p.ClientID)
	addField("Client Secret", p.ClientSecret)
	addField("API Key", p.APIKey)
	addField("Token URL", p.TokenURL)
	addField("Endpoint URL", p.EndpointURL)
	addField("Scopes", p.Scopes)
	addField("Key Type", p.KeyType)
	addField("Fingerprint", p.Fingerprint)
	addField("Subject", p.Subject)
	addField("Issuer", p.Issuer)
	addField("Passphrase", p.Passphrase)
	if strings.TrimSpace(p.PublicKey) != "" {
		fmt.Fprintf(&b, "Public Key:\n%s\n", strings.TrimSpace(p.PublicKey))
	}
	if strings.TrimSpace(p.Certificate) != "" {
		fmt.Fprintf(&b, "Certificate:\n%s\n", strings.TrimSpace(p.Certificate))
	}
	if strings.TrimSpace(p.CAChain) != "" {
		fmt.Fprintf(&b, "CA Chain:\n%s\n", strings.TrimSpace(p.CAChain))
	}
	if strings.TrimSpace(p.PrivateKey) != "" {
		fmt.Fprintf(&b, "Private Key:\n%s\n", strings.TrimSpace(p.PrivateKey))
	}
	return b.String()
}

// `ducksecrets cred ssh connect <name>` — dedicated SSH connection
func runCredSSHConnect(args []string) {
	var cliArgs, extraCmdArgs []string
	for i, arg := range args {
		if arg == "--" {
			cliArgs = args[:i]
			extraCmdArgs = args[i+1:]
			break
		}
	}
	if cliArgs == nil {
		cliArgs = args
	}

	fs := flag.NewFlagSet("cred ssh connect", flag.ExitOnError)
	project := fs.String("project", "", "Project slug or ID filter")
	envName := fs.String("env", "", "Environment slug filter")
	hostOverride := fs.String("host", "", "Override target host / IP")
	portOverride := fs.Int("port", 0, "Override SSH port")
	userOverride := fs.String("user", "", "Override SSH username")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	valFlags := map[string]bool{
		"-project": true, "--project": true,
		"-env": true, "--env": true,
		"-host": true, "--host": true,
		"-port": true, "--port": true,
		"-user": true, "--user": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	flagArgs, posArgs := splitFlagsAndPositional(cliArgs, valFlags)
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: SSH credential name or ID is required.\nUsage: ducksecrets cred ssh connect <name-or-id> [--host=...] [--user=...] [--port=...] [-- extra-ssh-args]")
		os.Exit(1)
	}
	target := posArgs[0]

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)

	cred, err := resolveCredentialByNameOrID(cfg, target, strings.TrimSpace(*project), strings.TrimSpace(*envName))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if cred.Kind != "ssh_key" || cred.Payload == nil {
		fmt.Fprintf(os.Stderr, "error: credential %q is %q (expected ssh_key)\n", cred.Name, cred.Kind)
		os.Exit(1)
	}
	pay := cred.Payload

	if strings.TrimSpace(pay.PrivateKey) == "" {
		fmt.Fprintln(os.Stderr, "error: SSH credential does not contain a private key")
		os.Exit(1)
	}
	host := pay.Host
	if *hostOverride != "" {
		host = *hostOverride
	}
	if host == "" {
		fmt.Fprintln(os.Stderr, "error: target host is required (set --host on the credential or pass --host=<hostname>)")
		os.Exit(1)
	}
	port := pay.Port
	if *portOverride > 0 {
		port = *portOverride
	}
	if port <= 0 {
		port = 22
	}
	user := pay.Username
	if *userOverride != "" {
		user = *userOverride
	}

	tmpDir, err := os.MkdirTemp("", "ducksecrets-ssh-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating temporary directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "id_key")
	keyContent := strings.TrimSpace(pay.PrivateKey) + "\n"
	if err := os.WriteFile(keyPath, []byte(keyContent), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing temporary SSH key: %v\n", err)
		os.Exit(1)
	}

	sshDest := host
	if user != "" {
		sshDest = fmt.Sprintf("%s@%s", user, host)
	}
	sshArgs := []string{"-i", keyPath, "-p", strconv.Itoa(port)}
	sshArgs = append(sshArgs, extraCmdArgs...)
	sshArgs = append(sshArgs, sshDest)

	fmt.Fprintf(os.Stderr, "🔐 Connecting to %s:%d via SSH using credential %q...\n", sshDest, port, cred.Name)
	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ssh execution failed: %v\n", err)
		os.Exit(1)
	}
}

// `ducksecrets cred db connect <name>` — dedicated Database client connection (psql, mysql, redis-cli)
func runCredDBConnect(args []string) {
	var cliArgs, extraCmdArgs []string
	for i, arg := range args {
		if arg == "--" {
			cliArgs = args[:i]
			extraCmdArgs = args[i+1:]
			break
		}
	}
	if cliArgs == nil {
		cliArgs = args
	}

	fs := flag.NewFlagSet("cred db connect", flag.ExitOnError)
	project := fs.String("project", "", "Project slug or ID filter")
	envName := fs.String("env", "", "Environment slug filter")
	hostOverride := fs.String("host", "", "Override database host / IP")
	portOverride := fs.Int("port", 0, "Override database port")
	userOverride := fs.String("user", "", "Override database username")
	dbOverride := fs.String("db", "", "Override database name")
	engine := fs.String("engine", "", "Database client: postgres, mysql, redis (auto-detected from port/URI if omitted)")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	valFlags := map[string]bool{
		"-project": true, "--project": true,
		"-env": true, "--env": true,
		"-host": true, "--host": true,
		"-port": true, "--port": true,
		"-user": true, "--user": true,
		"-db": true, "--db": true,
		"-engine": true, "--engine": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	flagArgs, posArgs := splitFlagsAndPositional(cliArgs, valFlags)
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: database credential name or ID is required.\nUsage: ducksecrets cred db connect <name-or-id> [--engine=postgres|mysql|redis] [-- extra-args]")
		os.Exit(1)
	}
	target := posArgs[0]

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)

	cred, err := resolveCredentialByNameOrID(cfg, target, strings.TrimSpace(*project), strings.TrimSpace(*envName))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if cred.Kind != "login" || cred.Payload == nil {
		fmt.Fprintf(os.Stderr, "error: credential %q is %q (expected db/login credential)\n", cred.Name, cred.Kind)
		os.Exit(1)
	}
	pay := cred.Payload

	host := pay.Host
	if *hostOverride != "" {
		host = *hostOverride
	}
	port := pay.Port
	if *portOverride > 0 {
		port = *portOverride
	}
	user := pay.Username
	if *userOverride != "" {
		user = *userOverride
	}
	dbName := pay.Database
	if *dbOverride != "" {
		dbName = *dbOverride
	}

	resolvedEngine := strings.ToLower(strings.TrimSpace(*engine))
	if resolvedEngine == "" {
		switch port {
		case 3306:
			resolvedEngine = "mysql"
		case 6379:
			resolvedEngine = "redis"
		default:
			if strings.HasPrefix(pay.URL, "mysql://") {
				resolvedEngine = "mysql"
			} else if strings.HasPrefix(pay.URL, "redis://") {
				resolvedEngine = "redis"
			} else {
				resolvedEngine = "postgres"
			}
		}
	}

	if host == "" {
		fmt.Fprintln(os.Stderr, "error: database host is required (set --host on the credential or pass --host=<hostname>)")
		os.Exit(1)
	}

	var cmd *exec.Cmd
	switch resolvedEngine {
	case "postgres", "pg", "psql", "postgresql":
		if port <= 0 {
			port = 5432
		}
		if dbName == "" {
			dbName = "postgres"
		}
		connURI := fmt.Sprintf("postgresql://%s@%s:%d/%s", url.User(user).String(), host, port, url.PathEscape(dbName))
		cArgs := append([]string{connURI}, extraCmdArgs...)
		cmd = exec.Command("psql", cArgs...)
		if pay.Password != "" {
			cmd.Env = append(os.Environ(), "PGPASSWORD="+pay.Password)
		}
	case "mysql", "mariadb":
		if port <= 0 {
			port = 3306
		}
		cArgs := []string{"-h", host, "-P", strconv.Itoa(port), "-u", user}
		if dbName != "" {
			cArgs = append(cArgs, dbName)
		}
		cArgs = append(cArgs, extraCmdArgs...)
		cmd = exec.Command("mysql", cArgs...)
		if pay.Password != "" {
			cmd.Env = append(os.Environ(), "MYSQL_PWD="+pay.Password)
		}
	case "redis", "redis-cli":
		if port <= 0 {
			port = 6379
		}
		cArgs := []string{"-h", host, "-p", strconv.Itoa(port)}
		if user != "" {
			cArgs = append(cArgs, "--user", user)
		}
		cArgs = append(cArgs, extraCmdArgs...)
		cmd = exec.Command("redis-cli", cArgs...)
		if pay.Password != "" {
			cmd.Env = append(os.Environ(), "REDISCLI_AUTH="+pay.Password)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unsupported database engine %q (use postgres, mysql, or redis)\n", resolvedEngine)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "🔐 Connecting to %s:%d (%s) using credential %q...\n", host, port, resolvedEngine, cred.Name)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "%s execution failed: %v\n", resolvedEngine, err)
		os.Exit(1)
	}
}

func runCredsSync(args []string) {
	fs := flag.NewFlagSet("cred sync", flag.ExitOnError)
	project := fs.String("project", "", "Target project slug or ID")
	envName := fs.String("env", "", "Target environment slug (default: dev)")
	prefix := fs.String("prefix", "", "Secret key prefix (default: sanitized credential name)")
	folder := fs.String("path", "/", "Target secret folder path")
	overwrite := fs.Bool("overwrite", true, "Overwrite existing secret keys")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	valFlags := map[string]bool{
		"-project": true, "--project": true,
		"-env": true, "--env": true,
		"-prefix": true, "--prefix": true,
		"-path": true, "--path": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	flagArgs, posArgs := splitFlagsAndPositional(args, valFlags)
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: credential name or ID is required.\nUsage: ducksecrets cred sync <name-or-id> --project=<slug> --env=<env> [--prefix=...]")
		os.Exit(1)
	}
	target := posArgs[0]

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)
	resolveProjectEnv(&cfg, *project, *envName)

	cred, err := resolveCredentialByNameOrID(cfg, target, "", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	reqBody := map[string]any{
		"project_id":       cfg.Project,
		"environment_slug": cfg.Env,
		"prefix":           *prefix,
		"path":             *folder,
		"overwrite":        *overwrite,
	}
	resp, err := authedRequest(cfg, http.MethodPost, fmt.Sprintf("/api/v1/credentials/%s/sync-env", url.PathEscape(cred.ID)), reqBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "failed to sync credential (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
		os.Exit(1)
	}

	var res struct {
		Created int      `json:"created"`
		Updated int      `json:"updated"`
		Keys    []string `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		fmt.Fprintf(os.Stderr, "error decoding response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Synced %d secret variables into %s (%s) [%d created, %d updated]:\n", len(res.Keys), cfg.Project, cfg.Env, res.Created, res.Updated)
	for _, k := range res.Keys {
		fmt.Printf("  - %s\n", k)
	}
}

func runCredsDelete(args []string) {
	fs := flag.NewFlagSet("cred delete", flag.ExitOnError)
	project := fs.String("project", "", "Project slug or ID filter")
	serverURL := fs.String("server", "", "Server daemon URL")
	tf := registerTLSFlags(fs)

	valFlags := map[string]bool{
		"-project": true, "--project": true,
		"-server": true, "--server": true,
		"-ca-cert": true, "--ca-cert": true,
		"-tls-fingerprint": true, "--tls-fingerprint": true,
	}
	flagArgs, posArgs := splitFlagsAndPositional(args, valFlags)
	fs.Parse(flagArgs)

	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: credential name or ID is required.\nUsage: ducksecrets cred delete <name-or-id>")
		os.Exit(1)
	}
	target := posArgs[0]

	cfg := loadConfig()
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	applyTLSFlags(&cfg, tf)

	cred, err := resolveCredentialByNameOrID(cfg, target, strings.TrimSpace(*project), "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	resp, err := authedRequest(cfg, http.MethodDelete, "/api/v1/credentials/"+url.PathEscape(cred.ID), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "failed to delete credential (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
		os.Exit(1)
	}

	fmt.Printf("✓ Credential %q (%s) deleted.\n", cred.Name, cred.ID)
}
