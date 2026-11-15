package interpolate

import (
	"reflect"
	"strings"
	"testing"
)

func TestHasReferenceAndExtract(t *testing.T) {
	str := "postgres://${DB_USER}:{{DB_PASSWORD}}@10.0.1.5:5432/${DB_NAME}"
	if !HasReference(str) {
		t.Errorf("expected HasReference to return true")
	}

	refs := ExtractReferences(str)
	expected := []string{"DB_USER", "DB_PASSWORD", "DB_NAME"}
	if !reflect.DeepEqual(refs, expected) {
		t.Errorf("expected refs %v, got %v", expected, refs)
	}

	plain := "plain_secret_value"
	if HasReference(plain) {
		t.Errorf("expected HasReference to return false for plain text")
	}
	if len(ExtractReferences(plain)) != 0 {
		t.Errorf("expected no references in plain text")
	}
}

func TestExpandSimple(t *testing.T) {
	secrets := map[string]string{
		"DB_USER":      "app_dev",
		"DB_PASSWORD":  "supersecretdevpass",
		"DB_HOST":      "10.0.1.5:5432",
		"DB_NAME":      "ecommerce_dev",
		"DATABASE_URL": "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/${DB_NAME}",
	}

	expanded := Expand(secrets)
	expectedURL := "postgres://app_dev:supersecretdevpass@10.0.1.5:5432/ecommerce_dev"
	if expanded["DATABASE_URL"] != expectedURL {
		t.Fatalf("expected %q, got %q", expectedURL, expanded["DATABASE_URL"])
	}
}

func TestExpandNestedAndChained(t *testing.T) {
	secrets := map[string]string{
		"HOST":         "10.0.1.5",
		"PORT":         "5432",
		"ENDPOINT":     "${HOST}:${PORT}",
		"PASSWORD":     "secret123",
		"DATABASE_URL": "postgres://user:${PASSWORD}@{{ENDPOINT}}/db",
	}

	expanded := Expand(secrets)
	expectedURL := "postgres://user:secret123@10.0.1.5:5432/db"
	if expanded["DATABASE_URL"] != expectedURL {
		t.Fatalf("expected %q, got %q", expectedURL, expanded["DATABASE_URL"])
	}
}

func TestExpandCycles(t *testing.T) {
	// A points to B, B points to A -> should terminate gracefully without panic
	secrets := map[string]string{
		"A": "val-${B}",
		"B": "val-${A}",
		"C": "ok",
	}

	expanded := Expand(secrets)
	if expanded["C"] != "ok" {
		t.Errorf("expected C to be ok, got %q", expanded["C"])
	}
}

func TestExpandMissingReference(t *testing.T) {
	// Reference to non-existent secret should remain unreplaced
	secrets := map[string]string{
		"FOO": "${DOES_NOT_EXIST}",
	}
	expanded := Expand(secrets)
	if expanded["FOO"] != "${DOES_NOT_EXIST}" {
		t.Errorf("expected FOO to remain unexpanded, got %q", expanded["FOO"])
	}
}

func TestExpandNoDoubleInterpolation(t *testing.T) {
	// Concatenating fragments from resolved values must not create new placeholders
	// that get expanded a second time, and literal ${...} returned from another
	// value via depth limit or concatenation stays untouched.
	secrets := map[string]string{
		"PRE":    "${",
		"POST":   "SECRET}",
		"SECRET": "topsecret",
		"MSG":    "${PRE}${POST}",
	}
	expanded := Expand(secrets)
	if expanded["MSG"] != "${SECRET}" {
		t.Fatalf("expected literal ${SECRET} without double interpolation, got %q", expanded["MSG"])
	}
}

func TestExpandBillionLaughsBounded(t *testing.T) {
	secrets := map[string]string{
		"L0": strings.Repeat("a", 1024),
	}
	prev := "L0"
	for i := 1; i <= 8; i++ {
		cur := "L" + string(rune('0'+i))
		// 4x amplification per level -> 4^8 * 1KB = 64MB unconstrained
		secrets[cur] = "${" + prev + "}${" + prev + "}${" + prev + "}${" + prev + "}"
		prev = cur
	}

	expanded := Expand(secrets)
	for k, v := range expanded {
		if len(v) > maxExpandedValueBytes {
			t.Fatalf("key %s exceeded maxExpandedValueBytes (%d > %d)", k, len(v), maxExpandedValueBytes)
		}
	}
}
