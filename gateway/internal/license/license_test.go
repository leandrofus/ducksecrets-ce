package license

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOpenCoreCommunityAndSignedEditions(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	mgr, err := NewManager(hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Default state: Community edition with 2 sites quota and no commercial flags.
	st := mgr.Status()
	if st.Edition != EditionCommunity || st.Valid || st.MaxSites != CommunityMaxSites {
		t.Fatalf("unexpected default status: %+v", st)
	}
	if err := mgr.CanCreateSite(1); err != nil {
		t.Fatalf("expected 1/2 sites to be allowed in Community, got %v", err)
	}
	if err := mgr.CanCreateSite(2); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected 2/2 sites to hit ErrQuotaExceeded, got %v", err)
	}
	if err := mgr.RequireFeature(FeatureSSOOIDC); !errors.Is(err, ErrFeatureLocked) {
		t.Fatalf("expected ErrFeatureLocked, got %v", err)
	}

	// Sign and activate a Pro license.
	exp := time.Now().UTC().Add(30 * 24 * time.Hour)
	proTok, err := Sign(priv, Claims{
		ID:        "lic_pro_1",
		Edition:   EditionPro,
		Customer:  "Acme Labs",
		Org:       "acme",
		ExpiresAt: &exp,
	})
	if err != nil {
		t.Fatalf("Sign Pro: %v", err)
	}
	st, err = mgr.Activate(proTok, "database")
	if err != nil {
		t.Fatalf("Activate Pro: %v", err)
	}
	if st.Edition != EditionPro || !st.Valid || st.MaxSites != ProDefaultMaxSites || st.Source != "database" {
		t.Fatalf("unexpected Pro status: %+v", st)
	}
	if !mgr.HasFeature(FeatureSSOOIDC) || !mgr.HasFeature(FeatureMasterKeyRotate) {
		t.Fatalf("expected Pro features to be active: %+v", st.Features)
	}
	if mgr.HasFeature(FeatureApprovals) {
		t.Fatal("Pro edition must not enable Business-only approvals feature")
	}
	if err := mgr.CanCreateSite(24); err != nil {
		t.Fatalf("expected 24/25 sites allowed under Pro: %v", err)
	}
	if err := mgr.CanCreateSite(25); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected 25/25 sites to fail under Pro: %v", err)
	}

	// Tampered token must fail without clobbering active Pro license.
	parts := strings.Split(proTok, ".")
	tampered := parts[0] + "." + parts[1] + "A." + parts[2]
	if _, err := mgr.Activate(tampered, "database"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for tampered token, got %v", err)
	}
	if cur := mgr.Status(); cur.Edition != EditionPro || !cur.Valid {
		t.Fatalf("failed activation modified prior state: %+v", cur)
	}

	// Token signed by another key must fail verification.
	_, otherPriv, _ := GenerateKeypair()
	forged, err := Sign(otherPriv, Claims{ID: "lic_bad", Edition: EditionBusiness, Customer: "Mallory"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Activate(forged, "database"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for foreign key, got %v", err)
	}

	// Business perpetual license unlocks everything & unlimited sites.
	bizTok, err := Sign(priv, Claims{
		ID:       "lic_biz_1",
		Edition:  EditionBusiness,
		Customer: "MegaCorp",
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err = mgr.Activate(bizTok, "env")
	if err != nil {
		t.Fatalf("Activate Business: %v", err)
	}
	if st.Edition != EditionBusiness || st.MaxSites != Unlimited || !mgr.HasFeature(FeatureApprovals) || !mgr.HasFeature(FeatureExternalKMS) {
		t.Fatalf("unexpected Business status: %+v", st)
	}
	if err := mgr.CanCreateSite(10000); err != nil {
		t.Fatalf("expected unlimited sites under Business: %v", err)
	}

	// Clearing reverts to Community.
	mgr.Clear()
	if cur := mgr.Status(); cur.Edition != EditionCommunity || cur.Valid || cur.MaxSites != CommunityMaxSites {
		t.Fatalf("expected Community after Clear, got %+v", cur)
	}
}

func TestExpiredLicenseFallsBackToCommunity(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(hex.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	mgr.nowFn = func() time.Time { return now }

	exp := now.Add(24 * time.Hour)
	tok, err := Sign(priv, Claims{
		ID:        "lic_exp",
		Edition:   EditionPro,
		Customer:  "Expiring Co",
		IssuedAt:  now.Add(-48 * time.Hour),
		ExpiresAt: &exp,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Still valid before expiry.
	if st, err := mgr.Activate(tok, "database"); err != nil || st.Edition != EditionPro {
		t.Fatalf("expected valid Pro before expiry, got st=%+v err=%v", st, err)
	}

	// Advance clock past expiration: gracefully degrades to Community while retaining metadata.
	now = exp.Add(time.Minute)
	st := mgr.Status()
	if st.Valid || !st.Expired || st.Edition != EditionCommunity || st.LicensedEdition != EditionPro || st.MaxSites != CommunityMaxSites {
		t.Fatalf("expected graceful fallback on expiration, got %+v", st)
	}
	if mgr.HasFeature(FeatureSSOOIDC) {
		t.Fatal("expired license must not grant Pro features")
	}

	// Startup load of an already-expired token does not block boot and keeps Community fallback.
	mgr2, _ := NewManager(hex.EncodeToString(pub))
	mgr2.nowFn = func() time.Time { return now }
	if err := mgr2.LoadStartup(tok, "env"); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken from LoadStartup, got %v", err)
	}
	if st2 := mgr2.Status(); !st2.Expired || st2.Edition != EditionCommunity || st2.Source != "env" {
		t.Fatalf("unexpected LoadStartup expired status: %+v", st2)
	}

	// Default MustManager compiles cleanly with DefaultPublicKeyHex.
	defMgr := MustManager()
	if defMgr.Status().Edition != EditionCommunity {
		t.Fatal("expected default manager to start in Community edition")
	}
	if len(defMgr.pubKey) != ed25519.PublicKeySize {
		t.Fatal("invalid default public key size")
	}
}

func TestManagerConcurrency(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	mgr, _ := NewManager(hex.EncodeToString(pub))
	tok, _ := Sign(priv, Claims{ID: "lic_conc", Edition: EditionPro, Customer: "Conc"})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_, _ = mgr.Activate(tok, "database")
			} else {
				_ = mgr.Status()
				_ = mgr.HasFeature(FeatureSSOOIDC)
				_ = mgr.CanCreateSite(1)
			}
		}(i)
	}
	wg.Wait()
}
