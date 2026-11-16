package sites

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func openTestWS(t *testing.T) (*websocket.Conn, <-chan struct{}, func()) {
	t.Helper()
	serverClosed := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			close(serverClosed)
			return
		}
		defer close(serverClosed)
		for {
			if _, _, err := ws.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		srv.Close()
		t.Fatalf("dial test ws: %v", err)
	}
	return conn, serverClosed, func() {
		_ = conn.CloseNow()
		srv.Close()
	}
}

func TestManagerRegisterUnregisterDisplaced(t *testing.T) {
	m := New()
	ws1, closed1, cleanup1 := openTestWS(t)
	defer cleanup1()
	ws2, _, cleanup2 := openTestWS(t)
	defer cleanup2()

	m.Register("site-1", ws1)
	if !m.IsOnline("site-1") {
		t.Fatal("expected site-1 online")
	}

	// Registering ws2 replaces ws1 and closes ws1
	m.Register("site-1", ws2)
	select {
	case <-closed1:
	case <-time.After(2 * time.Second):
		t.Fatal("expected displaced ws1 to be closed")
	}

	// Old ws1 unregister must NOT clear active ws2
	m.Unregister("site-1", ws1)
	if !m.IsOnline("site-1") {
		t.Fatal("stale Unregister(ws1) cleared newer ws2 connection")
	}

	// Active ws2 unregister clears it
	m.Unregister("site-1", ws2)
	if m.IsOnline("site-1") {
		t.Fatal("expected site-1 offline after Unregister(ws2)")
	}

	// Force unregister (conn == nil) removes and closes
	ws3, closed3, cleanup3 := openTestWS(t)
	defer cleanup3()
	m.Register("site-2", ws3)
	m.Unregister("site-2", nil)
	if m.IsOnline("site-2") {
		t.Fatal("expected site-2 offline after force Unregister(nil)")
	}
	select {
	case <-closed3:
	case <-time.After(2 * time.Second):
		t.Fatal("expected ws3 closed by Unregister(nil)")
	}
}

func TestManagerDialAndAttachStream(t *testing.T) {
	m := New()

	streamReqCh := make(chan StreamRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		var req StreamRequest
		if err := wsjson.Read(r.Context(), ws, &req); err == nil {
			streamReqCh <- req
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	ws, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer ws.CloseNow()

	m.Register("site-dial", ws)

	if m.HasPendingStream("missing") {
		t.Fatal("expected HasPendingStream(missing) to be false")
	}
	if err := m.AttachStream("missing", nil); err == nil {
		t.Fatal("expected error attaching unknown stream")
	}

	dialDone := make(chan net.Conn, 1)
	dialErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := m.Dial(ctx, "site-dial", "db.internal", 5432)
		if err != nil {
			dialErr <- err
			return
		}
		dialDone <- c
	}()

	var req StreamRequest
	select {
	case req = <-streamReqCh:
	case err := <-dialErr:
		t.Fatalf("Dial failed early: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for open_stream message")
	}
	if req.Action != "open_stream" || req.Host != "db.internal" || req.Port != 5432 || req.StreamID == "" {
		t.Fatalf("unexpected StreamRequest: %+v", req)
	}
	if !m.HasPendingStream(req.StreamID) {
		t.Fatalf("expected HasPendingStream(%s) to be true", req.StreamID)
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	if err := m.AttachStream(req.StreamID, c1); err != nil {
		t.Fatalf("AttachStream failed: %v", err)
	}
	// Second attach for same streamID must fail
	if err := m.AttachStream(req.StreamID, c1); err == nil {
		t.Fatal("expected error on duplicate AttachStream")
	}

	var dialed net.Conn
	select {
	case dialed = <-dialDone:
	case err := <-dialErr:
		t.Fatalf("Dial returned error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Dial to return")
	}
	defer dialed.Close()

	go func() {
		_, _ = io.WriteString(c2, "pong")
		_ = c2.Close()
	}()
	buf, err := io.ReadAll(dialed)
	if err != nil || string(buf) != "pong" {
		t.Fatalf("expected \"pong\" over paired stream, got %q (err=%v)", string(buf), err)
	}
}
