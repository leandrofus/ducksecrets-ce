// Command ducksecretsd is the server daemon: API, embedded UI and database in
// one binary. Every flag has a DUCKSECRETS_<NAME> environment variable.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/leandrofus/ducksecrets/gateway/internal/audit"
	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/crypto"
	"github.com/leandrofus/ducksecrets/gateway/internal/events"
	"github.com/leandrofus/ducksecrets/gateway/internal/license"
	"github.com/leandrofus/ducksecrets/gateway/internal/selfupdate"
	"github.com/leandrofus/ducksecrets/gateway/internal/server"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
	"github.com/leandrofus/ducksecrets/gateway/internal/tlsutil"
)

var version = "dev"

type config struct {
	listen, db, proxies string
	secureCookies       bool
	allowScripts        bool
	allowPrivateProbes  bool
	publicURL           string
	admin               string
	auditKey            string
	encryptionKey       string
	licenseKey          string
	tlsMode             string
	tlsCert             string
	tlsKey              string
	tlsHosts            string
}

// env returns $DUCKSECRETS_<name>, or def.
func env(name, def string) string {
	if v := os.Getenv("DUCKSECRETS_" + name); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "update" || os.Args[1] == "self-update") {
		runDaemonUpdate(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "tls" {
		runTLSCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
	var c config
	flag.StringVar(&c.listen, "listen", env("LISTEN", "127.0.0.1:5179"), "address to listen on ($DUCKSECRETS_LISTEN)")
	flag.StringVar(&c.db, "db", env("DB", "ducksecrets.db"), "SQLite file or postgres:// URL ($DUCKSECRETS_DB)")
	flag.StringVar(&c.proxies, "trusted-proxies", env("TRUSTED_PROXIES", ""), "reverse proxies whose X-Forwarded-* count, comma-separated ($DUCKSECRETS_TRUSTED_PROXIES)")
	flag.BoolVar(&c.secureCookies, "secure-cookies", env("SECURE_COOKIES", "") == "1", "always set Secure on cookies ($DUCKSECRETS_SECURE_COOKIES=1)")
	flag.BoolVar(&c.allowScripts, "allow-scripts", env("ALLOW_SCRIPTS", "") == "1", "allow host-side script rotation verifiers and PAM local/command drivers ($DUCKSECRETS_ALLOW_SCRIPTS=1)")
	flag.BoolVar(&c.allowPrivateProbes, "allow-private-probes", env("ALLOW_PRIVATE_PROBES", "") == "1", "allow http_probe and tcp_probe rotation verifiers to target loopback/private networks ($DUCKSECRETS_ALLOW_PRIVATE_PROBES=1)")
	flag.StringVar(&c.publicURL, "public-url", env("PUBLIC_URL", ""), "canonical public base URL for /install.sh ($DUCKSECRETS_PUBLIC_URL)")
	flag.StringVar(&c.admin, "admin", env("ADMIN", "admin"), "first admin username ($DUCKSECRETS_ADMIN)")
	flag.StringVar(&c.auditKey, "audit-key", env("AUDIT_KEY", ""), "hex HMAC key of the audit chain; default <db>.audit-key, created on first start ($DUCKSECRETS_AUDIT_KEY)")
	flag.StringVar(&c.encryptionKey, "encryption-key", env("ENCRYPTION_KEY", ""), "hex master AES-256 key for secrets; default <db>.encryption-key, created on first start ($DUCKSECRETS_ENCRYPTION_KEY)")
	flag.StringVar(&c.licenseKey, "license-key", env("LICENSE_KEY", ""), "offline Ed25519 license token (dkl1...) for Pro/Business features ($DUCKSECRETS_LICENSE_KEY)")
	flag.StringVar(&c.tlsMode, "tls-mode", env("TLS_MODE", tlsutil.ModeAuto), "TLS mode: auto, self-signed, custom, off ($DUCKSECRETS_TLS_MODE)")
	flag.StringVar(&c.tlsCert, "tls-cert", env("TLS_CERT", ""), "path to TLS certificate PEM file ($DUCKSECRETS_TLS_CERT)")
	flag.StringVar(&c.tlsKey, "tls-key", env("TLS_KEY", ""), "path to TLS private key PEM file ($DUCKSECRETS_TLS_KEY)")
	flag.StringVar(&c.tlsHosts, "tls-hosts", env("TLS_HOSTS", ""), "comma-separated extra SAN DNS names/IPs for self-signed TLS certs ($DUCKSECRETS_TLS_HOSTS)")
	flag.Parse()

	if err := run(c); err != nil {
		slog.Error("ducksecrets", "err", err)
		os.Exit(1)
	}
}

func run(c config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runContext(ctx, c, nil)
}

func runContext(ctx context.Context, c config, ready chan<- string) error {
	st, err := store.Open(c.db)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer st.Close()

	proxies, err := server.ParseProxies(c.proxies)
	if err != nil {
		return err
	}
	srv := &server.Server{
		Store:              st,
		TrustedProxies:     proxies,
		SecureCookies:      c.secureCookies,
		AllowScripts:       c.allowScripts,
		AllowPrivateProbes: c.allowPrivateProbes,
		PublicURL:          c.publicURL,
		Version:            version,
		DefaultAdmin:       c.admin,
	}

	srv.Auth = &auth.Service{Store: st}
	if wantPW := os.Getenv("DUCKSECRETS_ADMIN_PASSWORD"); wantPW != "" {
		if _, err := srv.Auth.Bootstrap(ctx, c.admin, wantPW); err != nil {
			return fmt.Errorf("creating the first admin: %w", err)
		}
		if os.Getenv("DUCKSECRETS_ADMIN_PASSWORD_RESET") == "1" {
			if err := srv.Auth.ResetPassword(ctx, c.admin, wantPW); err != nil {
				return fmt.Errorf("setting the admin's password: %w", err)
			}
		}
	} else if n, err := st.Q.CountUsers(ctx); err != nil {
		return fmt.Errorf("checking initial users: %w", err)
	} else if n == 0 {
		slog.Info("no users configured yet; open the web UI to set the administrator password on first login", "default_admin", c.admin)
	}

	srv.Events = events.New()

	key, err := loadAuditKey(c)
	if err != nil {
		return fmt.Errorf("audit key: %w", err)
	}
	srv.Audit = &audit.Log{Store: st, Key: key}

	encKey, err := loadEncryptionKey(c)
	if err != nil {
		return fmt.Errorf("encryption key: %w", err)
	}
	vault, err := crypto.NewVault(encKey)
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	srv.Vault = vault

	licMgr := license.MustManager()
	if c.licenseKey != "" {
		if err := licMgr.LoadStartup(c.licenseKey, "env"); err != nil {
			slog.Warn("configured license key rejected or expired; falling back to community edition", "err", err)
		}
	} else if setting, err := st.Q.GetSystemSetting(ctx, "license_token"); err == nil && setting.Value != "" {
		if err := licMgr.LoadStartup(setting.Value, "database"); err != nil {
			slog.Warn("persisted license key rejected or expired; falling back to community edition", "err", err)
		}
	} else if err != nil && !errors.Is(store.Classify(err), store.ErrNotFound) {
		return fmt.Errorf("loading license setting: %w", err)
	}
	srv.License = licMgr

	tlsMgr, tlsActive, err := initTLS(ctx, c, st)
	if err != nil {
		return fmt.Errorf("TLS setup: %w", err)
	}
	srv.TLS = tlsMgr

	workerCtx, workerCancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		workerCancel()
		wg.Wait()
	}()
	startWorker := func(fn func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(workerCtx)
		}()
	}
	startWorker(func(wctx context.Context) { purgeSessions(wctx, srv.Auth) })
	startWorker(func(wctx context.Context) { purgeShares(wctx, srv.Store) })
	startWorker(func(wctx context.Context) { reapDynamicLeases(wctx, srv) })
	startWorker(func(wctx context.Context) { runScheduledRotations(wctx, srv) })

	ln, err := net.Listen("tcp", c.listen)
	if err != nil {
		workerCancel()
		return err
	}
	serveLn := ln
	scheme := "http"
	if tlsActive {
		serveLn = tls.NewListener(ln, tlsMgr.TLSConfig())
		scheme = "https"
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-workerCtx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	if ready != nil {
		ready <- ln.Addr().String()
		close(ready)
	}
	slog.Info("listening", "addr", scheme+"://"+ln.Addr().String(), "version", version, "postgres", st.Postgres, "edition", srv.License.Status().Edition, "tls_mode", tlsMgr.Status().Mode)
	if err := hs.Serve(serveLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
		workerCancel()
		<-shutdownDone
		return err
	}
	workerCancel()
	<-shutdownDone
	return nil
}

func purgeSessions(ctx context.Context, a *auth.Service) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := a.PurgeExpired(ctx); err != nil {
				slog.Warn("purging sessions", "err", err)
			}
		}
	}
}

func purgeShares(ctx context.Context, st *store.Store) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := store.Now()
			burnedCutoff := sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true}
			if n, err := st.Q.DeleteExpiredShares(ctx, db.DeleteExpiredSharesParams{
				Now:          now,
				BurnedCutoff: burnedCutoff,
			}); err != nil {
				slog.Warn("purging expired shares", "err", err)
			} else if n > 0 {
				slog.Debug("purged expired shares", "count", n)
			}
		}
	}
}

func reapDynamicLeases(ctx context.Context, srv *server.Server) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			srv.ReapExpiredLeases(ctx)
		}
	}
}

func runScheduledRotations(ctx context.Context, srv *server.Server) {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			srv.ProcessPendingRotations(ctx)
		}
	}
}

// loadAuditKey reads the key from the flag, or from a file beside the SQLite
// database, created with a random key on first start. PostgreSQL has no file
// beside it, so the key must be given.
func loadAuditKey(c config) ([]byte, error) {
	if c.auditKey != "" {
		return hex.DecodeString(c.auditKey)
	}
	if store.IsPostgres(c.db) {
		return nil, errors.New("set -audit-key ($DUCKSECRETS_AUDIT_KEY) with PostgreSQL")
	}
	path := c.db + ".audit-key"
	if b, err := os.ReadFile(path); err == nil {
		return hex.DecodeString(strings.TrimSpace(string(b)))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	rand.Read(key)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, err
	}
	slog.Info("created the audit key; back it up with the database", "path", path)
	return key, nil
}

// loadEncryptionKey reads the master key from the flag, or from a file beside the
// SQLite database, created with a random 32-byte key on first start.
func loadEncryptionKey(c config) ([]byte, error) {
	if c.encryptionKey != "" {
		return hex.DecodeString(c.encryptionKey)
	}
	if store.IsPostgres(c.db) {
		return nil, errors.New("set -encryption-key ($DUCKSECRETS_ENCRYPTION_KEY) with PostgreSQL")
	}
	path := c.db + ".encryption-key"
	if b, err := os.ReadFile(path); err == nil {
		return hex.DecodeString(strings.TrimSpace(string(b)))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, err
	}
	slog.Info("created the encryption key; back it up with the database", "path", path)
	return key, nil
}

func runDaemonUpdate(args []string) {
	if err := selfupdate.RunCLI("ducksecretsd", version, args); err != nil {
		if err == flag.ErrHelp {
			return
		}
		fmt.Fprintf(os.Stderr, "update failed: %v\n", err)
		os.Exit(1)
	}
}

func runTLSCommand(args []string) {
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprintln(os.Stderr, "usage: ducksecretsd tls init [--cert path] [--key path] [--hosts h1,h2] [--force]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("tls init", flag.ExitOnError)
	certPath := fs.String("cert", env("TLS_CERT", "/etc/ducksecrets/tls.crt"), "output certificate PEM path")
	keyPath := fs.String("key", env("TLS_KEY", "/etc/ducksecrets/tls.key"), "output private key PEM path")
	hosts := fs.String("hosts", env("TLS_HOSTS", ""), "comma-separated extra SAN DNS names/IPs")
	force := fs.Bool("force", false, "overwrite existing certificate and key")
	_ = fs.Parse(args[1:])

	if !*force {
		if _, errC := os.Stat(*certPath); errC == nil {
			if _, errK := os.Stat(*keyPath); errK == nil {
				fmt.Printf("TLS certificate already exists at %s (pass --force to regenerate)\n", *certPath)
				return
			}
		}
	}
	certPEM, keyPEM, info, err := tlsutil.GenerateSelfSigned(splitTrim(*hosts), 365)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tls init failed: %v\n", err)
		os.Exit(1)
	}
	if err := tlsutil.WritePair(*certPath, *keyPath, certPEM, keyPEM); err != nil {
		fmt.Fprintf(os.Stderr, "writing TLS files failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Generated self-signed TLS certificate:\n  cert: %s\n  key:  %s\n  sha256: %s\n  sans: %s\n",
		*certPath, *keyPath, info.FingerprintSHA256, strings.Join(append(info.SANDNS, info.SANIPs...), ", "))
}

func splitTrim(csv string) []string {
	var out []string
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func initTLS(ctx context.Context, c config, st *store.Store) (*tlsutil.Manager, bool, error) {
	mode := strings.ToLower(strings.TrimSpace(c.tlsMode))
	if mode == "" {
		mode = tlsutil.ModeAuto
	}
	hosts := splitTrim(c.tlsHosts)
	if mode == tlsutil.ModeOff {
		return tlsutil.NewManager(false, tlsutil.ModeOff, c.tlsCert, c.tlsKey, hosts), false, nil
	}

	certSetting, errC := st.Q.GetSystemSetting(ctx, "tls_cert_pem")
	keySetting, errK := st.Q.GetSystemSetting(ctx, "tls_key_pem")
	modeSetting, _ := st.Q.GetSystemSetting(ctx, "tls_mode")
	hasDBPair := errC == nil && errK == nil && certSetting.Value != "" && keySetting.Value != ""

	hasPaths := c.tlsCert != "" && c.tlsKey != ""
	if hasDBPair {
		mgr := tlsutil.NewManager(true, tlsutil.ModeCustom, c.tlsCert, c.tlsKey, hosts)
		savedMode := tlsutil.ModeCustom
		if modeSetting.Value == tlsutil.ModeSelfSigned {
			savedMode = tlsutil.ModeSelfSigned
		}
		if _, err := mgr.LoadPEM(savedMode, []byte(certSetting.Value), []byte(keySetting.Value)); err == nil {
			return mgr, true, nil
		} else {
			slog.Warn("persisted TLS certificate rejected; falling back to configured paths", "err", err)
		}
	}

	if mode == tlsutil.ModeCustom {
		if !hasPaths {
			return nil, false, errors.New("tls-mode=custom requires -tls-cert/-tls-key or an uploaded certificate")
		}
		cb, err1 := os.ReadFile(c.tlsCert)
		kb, err2 := os.ReadFile(c.tlsKey)
		if err1 != nil || err2 != nil {
			return nil, false, fmt.Errorf("reading custom TLS files: %v / %v", err1, err2)
		}
		mgr := tlsutil.NewManager(true, tlsutil.ModeCustom, c.tlsCert, c.tlsKey, hosts)
		if _, err := mgr.LoadPEM(tlsutil.ModeCustom, cb, kb); err != nil {
			return nil, false, err
		}
		return mgr, true, nil
	}

	if hasPaths {
		mgr := tlsutil.NewManager(true, tlsutil.ModeSelfSigned, c.tlsCert, c.tlsKey, hosts)
		created, err := mgr.LoadOrInitFiles(c.tlsCert, c.tlsKey)
		if err != nil {
			return nil, false, err
		}
		if created {
			slog.Info("generated self-signed TLS certificate", "cert", c.tlsCert, "key", c.tlsKey)
		}
		return mgr, true, nil
	}

	if mode == tlsutil.ModeSelfSigned {
		certPath, keyPath := "", ""
		if !store.IsPostgres(c.db) && c.db != "" {
			certPath = filepath.Join(filepath.Dir(c.db), "tls.crt")
			keyPath = filepath.Join(filepath.Dir(c.db), "tls.key")
		}
		mgr := tlsutil.NewManager(true, tlsutil.ModeSelfSigned, certPath, keyPath, hosts)
		if certPath != "" {
			created, err := mgr.LoadOrInitFiles(certPath, keyPath)
			if err != nil {
				return nil, false, err
			}
			if created {
				slog.Info("generated self-signed TLS certificate", "cert", certPath, "key", keyPath)
			}
		} else {
			if _, _, _, err := mgr.RegenerateSelfSigned(nil); err != nil {
				return nil, false, err
			}
		}
		return mgr, true, nil
	}

	// Default mode "auto" without paths or DB pair keeps plain HTTP for local dev and tests.
	return tlsutil.NewManager(false, tlsutil.ModeOff, "", "", hosts), false, nil
}
