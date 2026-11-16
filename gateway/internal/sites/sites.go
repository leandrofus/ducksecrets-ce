package sites

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/google/uuid"
)

// StreamRequest is the control message sent by daemon to site connector.
type StreamRequest struct {
	Action   string `json:"action"` // "open_stream"
	StreamID string `json:"stream_id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

// Manager orchestrates reverse WebSocket tunnels from remote site connectors.
type Manager struct {
	mu             sync.RWMutex
	connectors     map[string]*websocket.Conn // siteID -> control ws
	pendingStreams map[string]chan net.Conn   // streamID -> conn channel
}

// New creates a new sites Manager.
func New() *Manager {
	return &Manager{
		connectors:     make(map[string]*websocket.Conn),
		pendingStreams: make(map[string]chan net.Conn),
	}
}

// Register adds an active control connection for a site and closes any displaced connection.
func (m *Manager) Register(siteID string, conn *websocket.Conn) {
	m.mu.Lock()
	old := m.connectors[siteID]
	m.connectors[siteID] = conn
	m.mu.Unlock()
	if old != nil && old != conn {
		_ = old.Close(websocket.StatusGoingAway, "replaced by new site connector")
	}
}

// Unregister removes a control connection. When conn is non-nil, only that exact
// connection is removed so an older disconnecting socket never clears a newer one.
// When conn is nil (e.g. site deletion), any active connection is closed and removed.
func (m *Manager) Unregister(siteID string, conn *websocket.Conn) {
	m.mu.Lock()
	cur, ok := m.connectors[siteID]
	var toClose *websocket.Conn
	if ok && (conn == nil || cur == conn) {
		delete(m.connectors, siteID)
		if conn == nil {
			toClose = cur
		}
	}
	m.mu.Unlock()
	if toClose != nil {
		_ = toClose.Close(websocket.StatusGoingAway, "site unregistered")
	}
}

// HasPendingStream reports whether a Dial request is currently waiting for streamID.
func (m *Manager) HasPendingStream(streamID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.pendingStreams[streamID]
	return ok
}

// IsOnline checks if a site has an active reverse tunnel connector.
func (m *Manager) IsOnline(siteID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.connectors[siteID]
	return ok
}

// Dial requests the site connector to dial the target host:port in its private network
// and returns a net.Conn bridged to that target.
func (m *Manager) Dial(ctx context.Context, siteID, host string, port int) (net.Conn, error) {
	m.mu.Lock()
	conn, ok := m.connectors[siteID]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("site %q is offline: no active connector agent running in target network", siteID)
	}

	streamID := "st_" + uuid.NewString()[:12]
	respCh := make(chan net.Conn, 1)
	m.pendingStreams[streamID] = respCh
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.pendingStreams, streamID)
		m.mu.Unlock()
	}()

	// Send control message down the reverse tunnel
	req := StreamRequest{
		Action:   "open_stream",
		StreamID: streamID,
		Host:     host,
		Port:     port,
	}

	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := wsjson.Write(writeCtx, conn, req); err != nil {
		return nil, fmt.Errorf("dispatching stream request to site connector: %w", err)
	}

	// Wait for the connector to dial target and open data stream
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("timeout waiting for site connector to establish stream %s", streamID)
	case pairedConn := <-respCh:
		if pairedConn == nil {
			return nil, fmt.Errorf("site connector failed to open stream to %s:%d", host, port)
		}
		return pairedConn, nil
	}
}

// AttachStream pairs an incoming data stream WebSocket from the site connector
// with the pending Dial request.
func (m *Manager) AttachStream(streamID string, conn net.Conn) error {
	m.mu.Lock()
	ch, ok := m.pendingStreams[streamID]
	if ok {
		delete(m.pendingStreams, streamID)
	}
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("no pending stream request with ID %q", streamID)
	}

	select {
	case ch <- conn:
		return nil
	default:
		return fmt.Errorf("pending stream %q already paired or cancelled", streamID)
	}
}
