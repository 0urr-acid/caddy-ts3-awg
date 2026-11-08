package ts3awg

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func freeListenTest(t *testing.T) string {
	t.Helper()
	conn := listenTest(t)
	address := conn.LocalAddr().String()
	conn.Close()
	return address
}

func appTest(t *testing.T, name string, server *Server) *App {
	t.Helper()
	a := &App{Servers: map[string]*Server{name: server}}
	if err := a.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatal(err)
	}
	a.logger = zap.NewNop().Named("ts3_awg")
	t.Cleanup(func() {
		if err := a.Stop(); err != nil {
			t.Error(err)
		}
	})
	return a
}

func TestReloadPreservesAWGSessionAndRejectsChangedLiveSettings(t *testing.T) {
	_, initiation, opts := vectorTest(t)
	ts, awg := listenTest(t), listenTest(t)
	server := &Server{Listen: freeListenTest(t), TeamSpeak: ts.LocalAddr().String(), AWG: awg.LocalAddr().String(), Initiation: opts}
	a1 := appTest(t, "vpn", server)
	if err := a1.Start(); err != nil {
		t.Fatal(err)
	}
	client := listenTest(t)
	front := a1.handles[0].relay.conn.LocalAddr().(*net.UDPAddr)
	for _, data := range [][]byte{firstDecoyTest(), []byte("second-decoy")} {
		sendTest(t, client, data, front)
		readTest(t, ts, data)
	}
	sendTest(t, client, initiation, front)
	backendAddr := readTest(t, awg, initiation)
	// A changed live config must fail without breaking the old active relay.
	changed := *server
	changed.MaxSessions = 128
	bad := appTest(t, "vpn", &changed)
	if err := bad.Start(); err == nil {
		t.Fatal("changed live relay silently replaced active sessions")
	}
	a2 := appTest(t, "vpn", server)
	if err := a2.Start(); err != nil {
		t.Fatal(err)
	}
	if a1.handles[0].relay != a2.handles[0].relay {
		t.Fatal("unchanged reload created a new UDP relay")
	}
	if err := a1.Stop(); err != nil {
		t.Fatal(err)
	}
	sendTest(t, client, []byte("data-after-reload"), front)
	gotBackend := readTest(t, awg, []byte("data-after-reload"))
	if gotBackend.String() != backendAddr.String() {
		t.Fatal("reload changed backend source socket")
	}
	sendTest(t, awg, []byte("reply-after-reload"), backendAddr)
	readTest(t, client, []byte("reply-after-reload"))
	if err := a2.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, ok := relays.References(a2.plans[0].key); ok {
		t.Fatal("listener leaked after final Stop")
	}
	rebound, err := net.ListenUDP("udp", front)
	if err != nil {
		t.Fatalf("listener was not released: %v", err)
	}
	rebound.Close()
}

func TestPartialStartRollsBackSharedReferences(t *testing.T) {
	_, _, opts := vectorTest(t)
	ts, awg, occupied := listenTest(t), listenTest(t), listenTest(t)
	s := &Server{Listen: freeListenTest(t), TeamSpeak: ts.LocalAddr().String(), AWG: awg.LocalAddr().String(), Initiation: opts}
	a1 := appTest(t, "a", s)
	if err := a1.Start(); err != nil {
		t.Fatal(err)
	}
	a2 := &App{Servers: map[string]*Server{
		"a": s,
		"z": {Listen: occupied.LocalAddr().String(), TeamSpeak: ts.LocalAddr().String(), AWG: awg.LocalAddr().String(), Initiation: opts},
	}}
	if err := a2.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatal(err)
	}
	a2.logger = zap.NewNop()
	if err := a2.Start(); err == nil {
		a2.Stop()
		t.Fatal("bound port unexpectedly accepted")
	}
	if refs, ok := relays.References(a1.plans[0].key); !ok || refs != 1 {
		t.Fatalf("rollback damaged old relay: refs=%d, exists=%t", refs, ok)
	}
	if a1.handles[0].relay.logger.Load() != a1.handles[0].relay.ownerLogs[a1] {
		t.Fatal("rollback did not restore old owner's logger")
	}
}

func TestValidationRejectsLoopAndInvalidNetwork(t *testing.T) {
	_, _, opts := vectorTest(t)
	for _, s := range []Server{
		{Listen: "tcp/:9987", TeamSpeak: "127.0.0.1:9988", AWG: "127.0.0.1:51820", Initiation: opts},
		{Listen: ":9987", TeamSpeak: "127.0.0.1:9987", AWG: "127.0.0.1:51820", Initiation: opts},
		{Listen: ":9987", TeamSpeak: "127.0.0.1:9988", AWG: "127.0.0.1:9988", Initiation: opts},
		{Listen: ":9987", TeamSpeak: "127.0.0.1:9988", AWG: "127.0.0.1:51820", Initiation: opts, IdleTimeout: caddy.Duration(time.Nanosecond)},
	} {
		if _, err := makePlan("bad", &s); err == nil {
			t.Fatalf("invalid relay accepted: listen=%s", s.Listen)
		}
	}
}

func TestRemoteBackendMayUseSamePortAsWildcardListener(t *testing.T) {
	_, _, opts := vectorTest(t)
	server := &Server{Listen: "udp/:9987", TeamSpeak: "203.0.113.10:9987", AWG: "127.0.0.1:51820", Initiation: opts}
	if _, err := makePlan("remote-ts", server); err != nil {
		t.Fatalf("remote TS3 on same port rejected: %v", err)
	}
}
