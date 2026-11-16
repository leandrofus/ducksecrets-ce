package auth

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

func TestLimiterLocksOutAndResets(t *testing.T) {
	l := NewLimiter()
	for i := 0; i < l.Max; i++ {
		if !l.Allowed("ana|10.0.0.1") {
			t.Fatalf("refused after %d failures", i)
		}
		l.Fail("ana|10.0.0.1")
	}
	if l.Allowed("ana|10.0.0.1") {
		t.Fatal("allowed after Max failures")
	}
	if !l.Allowed("ana|10.0.0.2") {
		t.Fatal("another address locked out too")
	}
	l.Reset("ana|10.0.0.1")
	if !l.Allowed("ana|10.0.0.1") {
		t.Fatal("still locked after reset")
	}
}

func TestLimiterWindowExpires(t *testing.T) {
	l := NewLimiter()
	l.Window = 20 * time.Millisecond
	for i := 0; i < l.Max; i++ {
		l.Fail("k")
	}
	if l.Allowed("k") {
		t.Fatal("not locked")
	}
	time.Sleep(30 * time.Millisecond)
	if !l.Allowed("k") {
		t.Fatal("still locked after the window")
	}
}

// Many distinct keys, each failing once (a distributed attack), do not grow
// the map without bound.
func TestLimiterBoundedMemory(t *testing.T) {
	l := NewLimiter()
	l.MaxKeys = 100
	for i := 0; i < 1000; i++ {
		l.Fail(fmt.Sprintf("user%d|10.0.%d.%d", i, i/256, i%256))
	}
	if n := l.Len(); n > l.MaxKeys {
		t.Fatalf("%d keys tracked, cap %d", n, l.MaxKeys)
	}

	// Expired keys are swept.
	l.Window = time.Millisecond
	time.Sleep(5 * time.Millisecond)
	l.lastSweep = time.Time{}
	l.Allowed("x")
	if n := l.Len(); n != 0 {
		t.Fatalf("%d expired keys left after a sweep", n)
	}
}

func TestLimiterSingleIPFloodBlockedAndZeroValueSafe(t *testing.T) {
	// Zero-value Limiter must not panic
	var zero Limiter
	if !zero.Allowed("alice|10.0.0.1") {
		t.Fatal("zero-value Limiter refused first attempt")
	}
	zero.Fail("alice|10.0.0.1")
	zero.Reset("alice|10.0.0.1")

	// Single IP flooding unknown usernames must not exhaust MaxKeys and gets blocked
	l := NewLimiter()
	l.MaxKeys = 200
	l.MaxPerIP = 10
	for i := 0; i < 50; i++ {
		l.Fail(fmt.Sprintf("bogus%d|198.51.100.9", i))
	}
	if l.Len() > l.MaxPerIP {
		t.Fatalf("single IP created %d keys, cap %d", l.Len(), l.MaxPerIP)
	}
	if l.Allowed("admin|198.51.100.9") {
		t.Fatal("expected IP flooding unknown usernames to be rate-limited")
	}
	if !l.Allowed("admin|198.51.100.10") {
		t.Fatal("other IP should not be affected")
	}
}

func TestServicePurgeExpiredAndSessionTransientError(t *testing.T) {
	st, closeDB, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()

	svc := &Service{Store: st}
	ctx := context.Background()
	if _, err := svc.Bootstrap(ctx, "admin", "admin-password"); err != nil {
		t.Fatal(err)
	}
	u, err := st.Q.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := svc.NewSession(ctx, u.ID, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}

	// PurgeExpired runs cleanly without SQLite-only julianday()
	if _, err := svc.PurgeExpired(ctx); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}

	// Transient error (canceled ctx) must NOT delete the valid session
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := svc.Session(canceledCtx, tok); err == nil || err == ErrNoSession {
		t.Fatalf("expected non-ErrNoSession transient error on canceled ctx, got %v", err)
	}
	if _, err := svc.Session(ctx, tok); err != nil {
		t.Fatalf("valid session was deleted after transient error: %v", err)
	}
}

func TestPasswordPolicyAuthAndSessionRevocation(t *testing.T) {
	if err := CheckPasswordPolicy(strings.Repeat("a", 73)); err == nil {
		t.Fatal("expected error for >72 byte password")
	}
	if err := CheckPasswordPolicy("valid-pass-10"); err != nil {
		t.Fatalf("unexpected error for valid password: %v", err)
	}

	st, closeDB, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()

	svc := &Service{Store: st}
	ctx := context.Background()
	if _, err := svc.Bootstrap(ctx, "admin", "admin-password"); err != nil {
		t.Fatal(err)
	}
	u, err := st.Q.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	// Wrong password must return zeroed user struct (no PasswordHash leak)
	gotUser, err := svc.Authenticate(ctx, "admin", "wrong-password")
	if err != ErrInvalid || gotUser.ID != "" || gotUser.PasswordHash != "" {
		t.Fatalf("expected zeroed user & ErrInvalid, got user=%+v err=%v", gotUser, err)
	}

	// Non-local empty hash user must also fail with ErrInvalid & zeroed user
	if err := st.Q.CreateUser(ctx, db.CreateUserParams{
		ID: store.NewID(), Username: "pamuser", DisplayName: "pamuser", PasswordHash: "", Role: "user", Now: store.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	pamUser, err := svc.Authenticate(ctx, "pamuser", "any-password")
	if err != ErrInvalid || pamUser.ID != "" {
		t.Fatalf("expected ErrInvalid for empty hash user, got user=%+v err=%v", pamUser, err)
	}

	// ResetPassword rejects weak passwords and revokes active web sessions
	if err := svc.ResetPassword(ctx, "admin", "short"); err == nil {
		t.Fatal("expected policy error for short password in ResetPassword")
	}
	tok, err := svc.NewSession(ctx, u.ID, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ResetPassword(ctx, "admin", "new-admin-password"); err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}
	if _, err := svc.Session(ctx, tok); err != ErrNoSession {
		t.Fatalf("expected existing session revoked after ResetPassword, got %v", err)
	}
}
