package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leandrofus/ducksecrets/gateway/internal/audit"
	"github.com/leandrofus/ducksecrets/gateway/internal/auth"
	"github.com/leandrofus/ducksecrets/gateway/internal/crypto"
	"github.com/leandrofus/ducksecrets/gateway/internal/events"
	"github.com/leandrofus/ducksecrets/gateway/internal/license"
	"github.com/leandrofus/ducksecrets/gateway/internal/store"
)

func TestOpenCoreLicenseAPIAndSiteQuota(t *testing.T) {
	pub, priv, err := license.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	licMgr, err := license.NewManager(hex.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}

	st, closeDB, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()

	vault, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Store:   st,
		Auth:    &auth.Service{Store: st},
		Audit:   &audit.Log{Store: st, Key: []byte("k")},
		Events:  events.New(),
		Vault:   vault,
		License: licMgr,
		Version: "test",
	}
	if _, err := srv.Auth.Bootstrap(context.Background(), "admin", "admin-password"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	admin := newClient(t, ts)
	admin.login("admin", "admin-password")

	// Create a non-admin regular user.
	admin.must(201, "POST", "/users", map[string]any{
		"username": "devuser",
		"password": "DevUser!123456",
		"role":     "user",
	}, nil)
	user := newClient(t, ts)
	user.login("devuser", "DevUser!123456")

	var prj projectDTO
	admin.must(201, "POST", "/projects", map[string]any{"name": "Quota Test", "slug": "quota-test"}, &prj)

	// Community Edition allows up to 2 Network Sites, and prompts initial admin for license onboarding until skipped or licensed.
	var stDTO licenseStatusDTO
	admin.must(200, "GET", "/system/license", nil, &stDTO)
	if stDTO.Edition != license.EditionCommunity || stDTO.MaxSites != license.CommunityMaxSites || stDTO.UsedSites != 0 || !stDTO.NeedsOnboarding {
		t.Fatalf("unexpected initial license status: %+v", stDTO)
	}
	var initialUserView licenseStatusDTO
	user.must(200, "GET", "/system/license", nil, &initialUserView)
	if initialUserView.NeedsOnboarding {
		t.Fatalf("expected needs_onboarding=false for non-admin user: %+v", initialUserView)
	}

	// Non-admin user cannot skip license onboarding.
	user.must(403, "POST", "/system/license/skip", nil, nil)

	// Admin clicks Skip -> stays on Community Edition with needs_onboarding cleared.
	admin.must(200, "POST", "/system/license/skip", nil, &stDTO)
	if stDTO.Edition != license.EditionCommunity || stDTO.NeedsOnboarding || stDTO.MaxSites != license.CommunityMaxSites {
		t.Fatalf("unexpected status after skip: %+v", stDTO)
	}
	admin.must(200, "GET", "/system/license", nil, &stDTO)
	if stDTO.NeedsOnboarding {
		t.Fatalf("expected persisted needs_onboarding=false after skip: %+v", stDTO)
	}

	admin.must(201, "POST", fmt.Sprintf("/projects/%s/sites", prj.ID), map[string]any{"name": "site-1"}, nil)
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/sites", prj.ID), map[string]any{"name": "site-2"}, nil)

	// 3rd site hits 402 Payment Required / license_required.
	admin.must(402, "POST", fmt.Sprintf("/projects/%s/sites", prj.ID), map[string]any{"name": "site-3"}, nil)

	// Non-admin user cannot activate/delete licenses.
	user.must(403, "PUT", "/system/license", map[string]string{"token": "dkl1.bad.sig"}, nil)
	user.must(403, "DELETE", "/system/license", nil, nil)

	// Invalid token returns 400.
	admin.must(400, "PUT", "/system/license", map[string]string{"token": "dkl1.invalid.token"}, nil)

	// Activate signed Pro license -> unlocks >2 sites and persists in system_settings.
	exp := time.Now().UTC().Add(30 * 24 * time.Hour)
	proTok, err := license.Sign(priv, license.Claims{
		ID:        "lic_test_pro",
		Edition:   license.EditionPro,
		Customer:  "Test Co",
		Org:       "testco",
		ExpiresAt: &exp,
	})
	if err != nil {
		t.Fatal(err)
	}

	admin.must(200, "PUT", "/system/license", map[string]string{"token": proTok}, &stDTO)
	if stDTO.Edition != license.EditionPro || !stDTO.Valid || stDTO.Customer != "Test Co" || stDTO.MaxSites != license.ProDefaultMaxSites {
		t.Fatalf("unexpected Pro status after PUT: %+v", stDTO)
	}

	// Regular user sees edition/quota, but customer metadata is redacted.
	var userView licenseStatusDTO
	user.must(200, "GET", "/system/license", nil, &userView)
	if userView.Edition != license.EditionPro || userView.Customer != "" || userView.LicenseID != "" {
		t.Fatalf("expected redacted holder info for non-admin: %+v", userView)
	}

	// Verify persisted setting reloads across a fresh License Manager.
	setting, err := st.Q.GetSystemSetting(context.Background(), licenseSettingKey)
	if err != nil || setting.Value != proTok {
		t.Fatalf("persisted license mismatch: %+v err=%v", setting, err)
	}

	// 3rd site now succeeds under Pro!
	admin.must(201, "POST", fmt.Sprintf("/projects/%s/sites", prj.ID), map[string]any{"name": "site-3"}, nil)

	// Deleting license reverts to Community without re-triggering onboarding.
	admin.must(200, "DELETE", "/system/license", nil, &stDTO)
	if stDTO.Edition != license.EditionCommunity || stDTO.MaxSites != license.CommunityMaxSites || stDTO.UsedSites != 3 || stDTO.NeedsOnboarding {
		t.Fatalf("expected Community without onboarding after DELETE with used_sites=3, got %+v", stDTO)
	}
	admin.must(402, "POST", fmt.Sprintf("/projects/%s/sites", prj.ID), map[string]any{"name": "site-4"}, nil)

	// Env-managed license reports needs_onboarding=false and rejects API mutations with 409 Conflict.
	if err := licMgr.LoadStartup(proTok, "env"); err != nil {
		t.Fatal(err)
	}
	admin.must(200, "GET", "/system/license", nil, &stDTO)
	if stDTO.NeedsOnboarding {
		t.Fatalf("expected needs_onboarding=false when env license is active: %+v", stDTO)
	}
	admin.must(409, "PUT", "/system/license", map[string]string{"token": proTok}, nil)
	admin.must(409, "DELETE", "/system/license", nil, nil)
}
