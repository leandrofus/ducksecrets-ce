package dynamic

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type RedisConfig struct {
	Address  string `json:"address"` // e.g. "127.0.0.1:6379" or "rediss://redis.internal:6379"
	Password string `json:"password,omitempty"`
	Username string `json:"username,omitempty"`  // Default "default"
	ACLRules string `json:"acl_rules,omitempty"` // Default "~* +@read"
}

type RedisDriver struct{}

func init() {
	RegisterDriver(&RedisDriver{})
}

func (d *RedisDriver) Engine() string {
	return "redis"
}

func hasControlBytes(s string) bool {
	return strings.ContainsAny(s, "\r\n\x00")
}

func parseRedisAddress(raw string) (addr string, useTLS bool, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, fmt.Errorf("address is required (e.g. 127.0.0.1:6379 or rediss://host:6379)")
	}
	if hasControlBytes(raw) {
		return "", false, fmt.Errorf("address contains invalid control characters")
	}
	if strings.HasPrefix(raw, "redis://") || strings.HasPrefix(raw, "rediss://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "", false, fmt.Errorf("invalid redis URL %q", raw)
		}
		addr = u.Host
		if _, _, splitErr := net.SplitHostPort(addr); splitErr != nil {
			addr = net.JoinHostPort(u.Hostname(), "6379")
		}
		return addr, u.Scheme == "rediss", nil
	}
	return raw, false, nil
}

func (d *RedisDriver) ValidateConfig(configJSON []byte) error {
	var cfg RedisConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return fmt.Errorf("parsing redis config: %w", err)
	}
	if _, _, err := parseRedisAddress(cfg.Address); err != nil {
		return err
	}
	if hasControlBytes(cfg.Username) || hasControlBytes(cfg.Password) || hasControlBytes(cfg.ACLRules) {
		return fmt.Errorf("redis config fields must not contain CR/LF/NUL bytes")
	}
	return nil
}

// writeRESPCommand encodes args as a binary-safe RESP multi-bulk array.
func writeRESPCommand(w io.Writer, args ...string) error {
	var b strings.Builder
	b.WriteByte('*')
	b.WriteString(strconv.Itoa(len(args)))
	b.WriteString("\r\n")
	for _, arg := range args {
		b.WriteByte('$')
		b.WriteString(strconv.Itoa(len(arg)))
		b.WriteString("\r\n")
		b.WriteString(arg)
		b.WriteString("\r\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func readRESPReply(r *bufio.Reader) (prefix byte, payload string, err error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return 0, "", err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if line == "" {
		return 0, "", fmt.Errorf("empty RESP reply")
	}
	return line[0], line[1:], nil
}

func execRESP(conn net.Conn, reader *bufio.Reader, args ...string) (byte, string, error) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeRESPCommand(conn, args...); err != nil {
		return 0, "", err
	}
	return readRESPReply(reader)
}

func dialRedis(ctx context.Context, cfg RedisConfig) (net.Conn, *bufio.Reader, string, bool, error) {
	addr, useTLS, err := parseRedisAddress(cfg.Address)
	if err != nil {
		return nil, nil, "", false, err
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	var conn net.Conn
	if useTLS {
		conn, err = (&tls.Dialer{NetDialer: d}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, nil, "", false, fmt.Errorf("connecting to redis at %s: %w", addr, err)
	}

	reader := bufio.NewReader(conn)

	if cfg.Password != "" {
		var authArgs []string
		if cfg.Username != "" {
			authArgs = []string{"AUTH", cfg.Username, cfg.Password}
		} else {
			authArgs = []string{"AUTH", cfg.Password}
		}
		prefix, payload, err := execRESP(conn, reader, authArgs...)
		if err != nil || prefix != '+' || payload != "OK" {
			conn.Close()
			return nil, nil, "", false, fmt.Errorf("redis auth failed: %c%s", prefix, payload)
		}
	}

	return conn, reader, addr, useTLS, nil
}

func (d *RedisDriver) Test(ctx context.Context, configJSON []byte) error {
	var cfg RedisConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return err
	}
	conn, reader, _, _, err := dialRedis(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	prefix, payload, err := execRESP(conn, reader, "PING")
	if err != nil || prefix != '+' || payload != "PONG" {
		return fmt.Errorf("redis ping failed: %c%s", prefix, payload)
	}
	return nil
}

func (d *RedisDriver) IssueLease(ctx context.Context, configJSON []byte, roleTemplate, username, password string, ttl time.Duration) (*LeaseCredentials, error) {
	if err := validateLeaseUsername(username); err != nil {
		return nil, err
	}
	if hasControlBytes(password) || strings.ContainsAny(password, " \t") {
		return nil, fmt.Errorf("redis password contains disallowed characters")
	}

	var cfg RedisConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, err
	}
	conn, reader, addr, useTLS, err := dialRedis(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	rules := cfg.ACLRules
	if roleTemplate != "" {
		rules = roleTemplate
	}
	if rules == "" {
		rules = "~* +@read"
	}
	if hasControlBytes(rules) {
		return nil, fmt.Errorf("ACL rules contain disallowed control bytes")
	}
	ruleTokens := strings.Fields(rules)

	args := make([]string, 0, 4+len(ruleTokens))
	args = append(args, "ACL", "SETUSER", username, "on", ">"+password)
	args = append(args, ruleTokens...)

	prefix, payload, err := execRESP(conn, reader, args...)
	if err != nil || prefix != '+' || payload != "OK" {
		return nil, fmt.Errorf("ACL SETUSER failed: %c%s", prefix, payload)
	}

	scheme := "redis"
	if useTLS {
		scheme = "rediss"
	}
	connStr := fmt.Sprintf("%s://%s:%s@%s/0", scheme, url.QueryEscape(username), url.QueryEscape(password), addr)

	return &LeaseCredentials{
		Username:   username,
		Password:   password,
		ConnString: connStr,
		Engine:     d.Engine(),
		Extra: map[string]string{
			"acl_rules": rules,
		},
	}, nil
}

func (d *RedisDriver) RevokeLease(ctx context.Context, configJSON []byte, username string) error {
	if err := validateLeaseUsername(username); err != nil {
		return err
	}
	var cfg RedisConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return err
	}
	conn, reader, _, _, err := dialRedis(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	prefix, payload, err := execRESP(conn, reader, "ACL", "DELUSER", username)
	if err != nil {
		return fmt.Errorf("sending ACL DELUSER: %w", err)
	}
	if prefix == '-' {
		return fmt.Errorf("ACL DELUSER error: %s", payload)
	}
	return nil
}
