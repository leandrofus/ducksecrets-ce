package dynamic

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

var safeLeaseUsernameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)

func validateLeaseUsername(username string) error {
	if !safeLeaseUsernameRe.MatchString(username) {
		return fmt.Errorf("invalid dynamic lease username %q", username)
	}
	return nil
}

func validateSQLRoleTemplate(tmpl string) error {
	if strings.ContainsRune(tmpl, 0) ||
		strings.Contains(tmpl, "--") ||
		strings.Contains(tmpl, "/*") ||
		strings.Contains(tmpl, "*/") ||
		strings.ContainsAny(tmpl, "'\"`$") {
		return fmt.Errorf("role_template contains disallowed SQL characters or comments")
	}
	for _, rawStmt := range strings.Split(tmpl, ";") {
		stmt := strings.TrimSpace(rawStmt)
		if stmt == "" {
			continue
		}
		upper := strings.ToUpper(stmt)
		if !strings.HasPrefix(upper, "GRANT ") && !strings.HasPrefix(upper, "REVOKE ") {
			return fmt.Errorf("role_template statements must start with GRANT or REVOKE")
		}
	}
	return nil
}

// LeaseCredentials represents the generated temporary credentials.
type LeaseCredentials struct {
	Username   string            `json:"username"`
	Password   string            `json:"password"`
	ConnString string            `json:"connection_string,omitempty"`
	Engine     string            `json:"engine"`
	Extra      map[string]string `json:"extra,omitempty"`
}

// Driver is the pluggable adapter interface for dynamic credentials engines.
type Driver interface {
	Engine() string
	ValidateConfig(configJSON []byte) error
	Test(ctx context.Context, configJSON []byte) error
	IssueLease(ctx context.Context, configJSON []byte, roleTemplate, username, password string, ttl time.Duration) (*LeaseCredentials, error)
	RevokeLease(ctx context.Context, configJSON []byte, username string) error
}

var (
	driversMu sync.RWMutex
	drivers   = make(map[string]Driver)
)

// RegisterDriver registers a dynamic secret engine driver.
func RegisterDriver(d Driver) {
	driversMu.Lock()
	defer driversMu.Unlock()
	drivers[d.Engine()] = d
}

// GetDriver returns the driver registered for the specified engine.
func GetDriver(engine string) (Driver, error) {
	driversMu.RLock()
	defer driversMu.RUnlock()
	d, ok := drivers[engine]
	if !ok {
		return nil, fmt.Errorf("unsupported dynamic secret engine: %q", engine)
	}
	return d, nil
}

// SupportedEngines returns a list of registered engine names.
func SupportedEngines() []string {
	driversMu.RLock()
	defer driversMu.RUnlock()
	list := make([]string, 0, len(drivers))
	for name := range drivers {
		list = append(list, name)
	}
	return list
}

// GenerateRandomCredentials returns a unique temporary username and high-entropy password.
func GenerateRandomCredentials(prefix string) (username, password string, err error) {
	if prefix == "" {
		prefix = "duck_d_"
	}
	uBytes := make([]byte, 5)
	if _, err := io.ReadFull(rand.Reader, uBytes); err != nil {
		return "", "", err
	}
	username = prefix + hex.EncodeToString(uBytes)

	pBytes := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, pBytes); err != nil {
		return "", "", err
	}
	password = hex.EncodeToString(pBytes)
	return username, password, nil
}
