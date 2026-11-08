package ts3awg

import (
	"bytes"
	"context"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"net"
	"testing"
	"time"
)

func listenTest(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func readTest(t *testing.T, c *net.UDPConn, expected []byte) *net.UDPAddr {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, addr, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], expected) {
		t.Fatalf("got %x, want %x", buf[:n], expected)
	}
	return addr
}

func sendTest(t *testing.T, c *net.UDPConn, p []byte, addr *net.UDPAddr) {
	t.Helper()
	if _, err := c.WriteToUDP(p, addr); err != nil {
		t.Fatal(err)
	}
}

func quietTest(t *testing.T, c *net.UDPConn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	_, _, err := c.ReadFromUDP(make([]byte, 65535))
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatalf("expected no datagram, got %v", err)
	}
}

func startRelay(t *testing.T, detector *initiationDetector, idle time.Duration) (ts, awg, front *net.UDPConn) {
	t.Helper()
	return startRelayLogged(t, detector, idle, zap.NewNop(), AuditConfig{Window: caddy.Duration(time.Second), Burst: 60, MaxSources: 100})
}

func startRelayLogged(t *testing.T, detector *initiationDetector, idle time.Duration, logger *zap.Logger, audit AuditConfig) (ts, awg, front *net.UDPConn) {
	t.Helper()
	ts, awg, front = listenTest(t), listenTest(t), listenTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	r := &sharedRelay{conn: front, plan: relayPlan{ts: ts.LocalAddr().(*net.UDPAddr), awg: awg.LocalAddr().(*net.UDPAddr), detector: detector, idle: idle, maxSessions: 8, audit: audit}}
	r.logger.Store(logger)
	go func() { done <- r.serve(ctx) }()

	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return
}

func firstDecoyTest() []byte {
	p := make([]byte, 34)
	copy(p, []byte("TS3INIT1"))
	p[12] = 0x88
	return p
}

func TestThirdPacketInitiation(t *testing.T) {
	for _, replyFirst := range []bool{false, true} {
		name := "without-TS-reply"
		if replyFirst {
			name = "with-TS-reply"
		}
		t.Run(name, func(t *testing.T) {
			detector, initiation, _ := vectorTest(t)
			ts, awg, front := startRelay(t, detector, time.Second)
			client, normal := listenTest(t), listenTest(t)
			addr := front.LocalAddr().(*net.UDPAddr)
			i1 := firstDecoyTest()
			sendTest(t, client, i1, addr)
			oldTSAddr := readTest(t, ts, i1)
			sendTest(t, client, []byte("second-decoy"), addr)
			readTest(t, ts, []byte("second-decoy"))
			if replyFirst {
				// Server datagrams must not count toward the third CLIENT packet.
				sendTest(t, ts, []byte("ts-response"), oldTSAddr)
				readTest(t, client, []byte("ts-response"))
			}
			sendTest(t, normal, i1, addr)
			normalAddr := readTest(t, ts, i1)
			if normalAddr.String() == oldTSAddr.String() {
				t.Fatal("shared TS socket")
			}
			sendTest(t, client, initiation, addr)
			awgAddr := readTest(t, awg, initiation)
			sendTest(t, awg, []byte("awg-response"), awgAddr)
			readTest(t, client, []byte("awg-response"))
			sendTest(t, ts, []byte("late-ts-response"), oldTSAddr)
			quietTest(t, client)
			sendTest(t, client, i1, addr)
			readTest(t, awg, i1)
			sendTest(t, client, []byte("encrypted-data"), addr)
			readTest(t, awg, []byte("encrypted-data"))
			sendTest(t, normal, []byte("ordinary-ts-command"), addr)
			readTest(t, ts, []byte("ordinary-ts-command"))
			sendTest(t, ts, []byte("ordinary-ts-reply"), normalAddr)
			readTest(t, normal, []byte("ordinary-ts-reply"))
		})
	}
}

func TestOnlyThirdPacketCheckedAndRetryResetsCounter(t *testing.T) {
	detector, initiation, _ := vectorTest(t)
	ts, awg, front := startRelay(t, detector, time.Second)
	client := listenTest(t)
	addr := front.LocalAddr().(*net.UDPAddr)
	// Even valid initiation at position 1 or 2 must follow the default TS route.
	for i := 0; i < 2; i++ {
		sendTest(t, client, initiation, addr)
		readTest(t, ts, initiation)
	}
	bad := bytes.Clone(initiation)
	bad[detector.padding+116] ^= 1
	sendTest(t, client, bad, addr)
	readTest(t, ts, bad)
	// A valid initiation at position 4 must NOT switch the session.
	sendTest(t, client, initiation, addr)
	readTest(t, ts, initiation)
	quietTest(t, awg)
	// A retransmitted I1 begins a new burst, allowing recovery on the same tuple.
	i1 := firstDecoyTest()
	sendTest(t, client, i1, addr)
	readTest(t, ts, i1)
	sendTest(t, client, []byte("second-decoy"), addr)
	readTest(t, ts, []byte("second-decoy"))
	sendTest(t, client, initiation, addr)
	readTest(t, awg, initiation)
}

func TestDefaultTSAndExpiredSessions(t *testing.T) {
	detector, initiation, _ := vectorTest(t)
	ts, awg, front := startRelay(t, detector, 30*time.Millisecond)
	client := listenTest(t)
	addr := front.LocalAddr().(*net.UDPAddr)
	for _, data := range [][]byte{[]byte("unknown"), []byte("second")} {
		sendTest(t, client, data, addr)
		readTest(t, ts, data)
	}
	sendTest(t, client, initiation, addr)
	readTest(t, awg, initiation)
	quietTest(t, awg)
	sendTest(t, client, []byte("new-ts-session"), addr)
	readTest(t, ts, []byte("new-ts-session"))
}
