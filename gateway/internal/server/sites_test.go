package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestSites_CRUD(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{
		"name": "Sites Test Project",
		"slug": "sites-test",
	}, &prj)

	// 1. Create a site connector
	var site createdSiteDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/sites", prj.ID), map[string]any{
		"name":        "prod-aws-vpc",
		"description": "Production AWS VPC Private Subnet",
	}, &site)

	if site.ID == "" || site.Name != "prod-aws-vpc" {
		t.Fatalf("unexpected site creation response: %+v", site)
	}
	if !strings.HasPrefix(site.Token, "duck_site_") {
		t.Fatalf("expected token starting with duck_site_, got %s", site.Token)
	}
	if site.Online {
		t.Fatal("expected newly created site to be offline")
	}

	// 2. List sites
	var sites []siteDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/sites", prj.ID), nil, &sites)
	if len(sites) != 1 || sites[0].ID != site.ID {
		t.Fatalf("expected 1 site in list, got %+v", sites)
	}
	if sites[0].Online {
		t.Fatal("expected site to be offline before connecting")
	}

	// 3. Delete site
	c.must(204, "DELETE", fmt.Sprintf("/projects/%s/sites/%s", prj.ID, site.ID), nil, nil)

	// 4. Verify site is deleted
	var afterDelete []siteDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/sites", prj.ID), nil, &afterDelete)
	if len(afterDelete) != 0 {
		t.Fatalf("expected 0 sites after deletion, got %d", len(afterDelete))
	}
}

func TestSites_ReverseTunnelProxy(t *testing.T) {
	// 1. Start a mock TCP service (echo server) representing an internal DB in a private VPC
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock TCP listener: %v", err)
	}
	defer echoListener.Close()

	mockTCPPort := echoListener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					// Echo back with prefix
					reply := append([]byte("ECHO:"), buf[:n]...)
					if _, err := c.Write(reply); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	// 2. Setup server and admin client
	ts := newTestServer(t)
	c := newClient(t, ts)
	c.login("admin", "admin-password")

	var prj projectDTO
	c.must(201, "POST", "/projects", map[string]any{
		"name": "Reverse Gateway Project",
		"slug": "reverse-gateway",
	}, &prj)

	// 3. Register site connector
	var site createdSiteDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/sites", prj.ID), map[string]any{
		"name":        "vpc-private-agent",
		"description": "Agent inside private subnet",
	}, &site)

	// 4. Start simulated Site Connector agent in a background goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentWSURL := strings.Replace(ts.URL, "http", "ws", 1) + fmt.Sprintf("/api/v1/sites/%s/connect", site.ID)
	dialOpts := &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + site.Token},
		},
	}

	controlWS, _, err := websocket.Dial(ctx, agentWSURL, dialOpts)
	if err != nil {
		t.Fatalf("site agent failed to connect control websocket: %v", err)
	}
	defer controlWS.Close(websocket.StatusNormalClosure, "agent stopping")

	// Agent loop: handle stream requests and bridge them
	go func() {
		for {
			_, msgBytes, err := controlWS.Read(ctx)
			if err != nil {
				return
			}

			var req struct {
				Action   string `json:"action"`
				StreamID string `json:"stream_id"`
				Host     string `json:"host"`
				Port     int    `json:"port"`
			}
			if err := json.Unmarshal(msgBytes, &req); err != nil {
				continue
			}

			if req.Action == "open_stream" {
				go func(streamID, host string, port int) {
					// 1. Dial local target service
					targetConn, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
					if err != nil {
						return
					}
					defer targetConn.Close()

					// 2. Dial reverse data stream to daemon
					streamURL := strings.Replace(ts.URL, "http", "ws", 1) + fmt.Sprintf("/api/v1/sites/%s/streams/%s", site.ID, streamID)
					streamWS, _, err := websocket.Dial(ctx, streamURL, dialOpts)
					if err != nil {
						return
					}
					defer streamWS.Close(websocket.StatusNormalClosure, "stream done")

					netConn := websocket.NetConn(ctx, streamWS, websocket.MessageBinary)
					defer netConn.Close()

					// 3. Bi-directional bridge
					var wg sync.WaitGroup
					wg.Add(2)
					go func() {
						defer wg.Done()
						io.Copy(netConn, targetConn)
					}()
					go func() {
						defer wg.Done()
						io.Copy(targetConn, netConn)
					}()
					wg.Wait()
				}(req.StreamID, req.Host, req.Port)
			}
		}
	}()

	// 5. Verify site is now ONLINE
	time.Sleep(50 * time.Millisecond)
	var sites []siteDTO
	c.must(200, "GET", fmt.Sprintf("/projects/%s/sites", prj.ID), nil, &sites)
	if len(sites) != 1 || !sites[0].Online {
		t.Fatalf("expected site to be online, got %+v", sites)
	}

	// 6. Register dynamic provider attached to this site_id
	var prov dynamicProviderDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic", prj.ID), map[string]any{
		"name":          "vpc-db",
		"engine":        "pam",
		"site_id":       site.ID,
		"enforced_port": 0,
		"config": map[string]any{
			"mode": "simulated",
			"host": "127.0.0.1",
			"port": mockTCPPort,
		},
	}, &prov)

	if prov.SiteID == nil || *prov.SiteID != site.ID {
		t.Fatalf("expected provider site_id to be %s, got %+v", site.ID, prov.SiteID)
	}

	// 7. Issue temporary credentials lease
	var issued issuedLeaseDTO
	c.must(201, "POST", fmt.Sprintf("/projects/%s/environments/dev/dynamic/%s/lease", prj.ID, prov.ID), map[string]any{
		"ttl_seconds": 3600,
	}, &issued)

	// 8. Connect client tunnel through daemon to the dynamic provider
	// The daemon will route via site.Dial(...) -> reverse WebSocket stream -> agent -> mock TCP echo server!
	clientTunnelURL := strings.Replace(ts.URL, "http", "ws", 1) + fmt.Sprintf("/api/v1/projects/%s/environments/dev/dynamic/%s/tunnel?lease_id=%s", prj.ID, prov.ID, issued.LeaseID)

	clientWS, _, err := websocket.Dial(ctx, clientTunnelURL, &websocket.DialOptions{
		HTTPClient: c.http,
	})
	if err != nil {
		t.Fatalf("failed to dial client tunnel: %v", err)
	}
	defer clientWS.Close(websocket.StatusNormalClosure, "client test done")

	clientConn := websocket.NetConn(ctx, clientWS, websocket.MessageBinary)
	defer clientConn.Close()

	// 9. Send payload through tunnel
	payload := "HELLO_REVERSE_SITE_GATEWAY"
	if _, err := clientConn.Write([]byte(payload)); err != nil {
		t.Fatalf("failed to write into client tunnel: %v", err)
	}

	// 10. Read echoed response
	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from client tunnel: %v", err)
	}

	expected := "ECHO:" + payload
	if string(buf[:n]) != expected {
		t.Fatalf("unexpected echo response: got %q, want %q", string(buf[:n]), expected)
	}
}
