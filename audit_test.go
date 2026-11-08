package ts3awg

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestAuditThresholdAndNormalization(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core).Named("ts3_awg")
	audit := newSourceAudit(AuditConfig{Window: caddy.Duration(time.Second), Burst: 2, MaxSources: 2})
	now := time.Now()
	for port := uint16(2000); port < 2010; port++ {
		audit.observe(now, netip.AddrPortFrom(netip.MustParseAddr("::ffff:192.0.2.15"), port), logger)
	}
	if logs.Len() != 1 {
		t.Fatalf("expected one event per source window, got %d", logs.Len())
	}
	entry := logs.All()[0]
	fields := entry.ContextMap()
	if entry.LoggerName != "ts3_awg" || fields["event"] != "suspicious_connection" || fields["remote_ip"] != "192.0.2.15" || fields["reason"] != "session_start_rate" {
		t.Fatalf("wrong CrowdSec event: %+v", entry)
	}
	audit.observe(now.Add(time.Second), netip.MustParseAddrPort("192.0.2.15:2020"), logger)
	if logs.Len() != 1 {
		t.Fatal("new window triggered without exceeding threshold")
	}
	audit.observe(now, netip.MustParseAddrPort("192.0.2.16:2000"), logger)
	audit.observe(now, netip.MustParseAddrPort("192.0.2.17:2000"), logger)
	if len(audit.sources) != 2 {
		t.Fatalf("unbounded source cache: %d", len(audit.sources))
	}
	audit.prune(now.Add(4 * time.Second))
	if len(audit.sources) != 0 {
		t.Fatal("expired source windows not pruned")
	}
}

func TestTrafficOnExistingTupleDoesNotTriggerAudit(t *testing.T) {
	detector, initiation, _ := vectorTest(t)
	core, logs := observer.New(zap.WarnLevel)
	ts, _, front := startRelayLogged(t, detector, time.Second, zap.New(core), AuditConfig{Window: caddy.Duration(time.Second), Burst: 1, MaxSources: 100})
	client := listenTest(t)
	addr := front.LocalAddr().(*net.UDPAddr)
	// The first datagram creates a session. Subsequent non-I1 packets,
	// including malformed initiation, are not new connection attempts.
	for i := 0; i < 100; i++ {
		data := append([]byte(nil), initiation...)
		data[detector.padding+116] ^= 1
		sendTest(t, client, data, addr)
		readTest(t, ts, data)
	}
	if logs.Len() != 0 {
		t.Fatal("ordinary traffic or bad MAC1 generated a suspicious event")
	}
}
