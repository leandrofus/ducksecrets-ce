package audit

import (
	"context"
	"testing"

	"github.com/leandrofus/ducksecrets/gateway/internal/store"
	"github.com/leandrofus/ducksecrets/gateway/internal/store/db"
)

func TestChain(t *testing.T) {
	s, closeDB, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	ctx := context.Background()
	l := &Log{Store: s, Key: []byte("test-key")}
	for i, action := range []string{"note.create", "note.update", "note.delete"} {
		if err := l.Record(ctx, Event{Actor: Actor{Username: "ana", IP: "10.0.0.1"}, Action: action, TargetID: "n1", Details: map[string]any{"i": i}}); err != nil {
			t.Fatal(err)
		}
	}
	v, err := l.Verify(ctx)
	if err != nil || !v.Valid || v.Events != 3 {
		t.Fatalf("fresh chain: %+v %v", v, err)
	}

	// Another key cannot vouch for the chain.
	v, _ = (&Log{Store: s, Key: []byte("other")}).Verify(ctx)
	if v.Valid {
		t.Fatal("chain verified with the wrong key")
	}

	// The table refuses edits and (on PostgreSQL) TRUNCATE.
	if _, err := s.DB.Exec(`UPDATE audit_events SET action = 'x' WHERE seq = 2`); err == nil {
		t.Fatal("audit_events accepted an UPDATE")
	}
	if s.IsPostgresDB() {
		if _, err := s.DB.Exec(`TRUNCATE audit_events`); err == nil {
			t.Fatal("audit_events accepted a TRUNCATE")
		}
	}

	// Empty HMAC key is rejected explicitly
	if err := (&Log{Store: s}).Record(ctx, Event{Action: "x"}); err == nil {
		t.Fatal("expected error when Record called with empty key")
	}
	if _, err := (&Log{Store: s}).Verify(ctx); err == nil {
		t.Fatal("expected error when Verify called with empty key")
	}

	// Corrupted details JSON reports Valid=false instead of unhandled error.
	s2, closeDB2, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB2()
	if err := s2.Q.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		Seq:           1,
		ActorUsername: "ana",
		ActorIP:       "127.0.0.1",
		Action:        "a",
		Details:       "{bad-json",
		PrevHash:      GenesisHash,
		Hash:          "bad",
		CreatedAt:     store.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	v2, err := (&Log{Store: s2, Key: []byte("test-key")}).Verify(ctx)
	if err != nil || v2.Valid {
		t.Fatalf("expected Valid=false with nil error on corrupted details JSON, got %+v err=%v", v2, err)
	}
}
