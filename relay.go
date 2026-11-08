package ts3awg

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"go.uber.org/zap"
)

type session struct {
	conn         *net.UDPConn
	awg          bool
	clientPacket uint8
	lastClient   time.Time
}

type packet struct {
	client  netip.AddrPort
	backend *net.UDPConn
	data    []byte
	err     error
}

func isFirstDecoy(p []byte) bool {
	return len(p) == 34 && bytes.HasPrefix(p, []byte("TS3INIT1")) && p[12] == 0x88 && p[17] == 0
}

func readPackets(ctx context.Context, conn *net.UDPConn, client netip.AddrPort, backend bool, events chan<- packet) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFromUDPAddrPort(buf)
		p := packet{client: client, err: err}
		if backend {
			p.backend = conn
		} else if err == nil {
			p.client = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		}
		if err == nil {
			p.data = bytes.Clone(buf[:n])
		}
		select {
		case events <- p:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (r *sharedRelay) serve(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	sessions := make(map[netip.AddrPort]*session)
	var readers sync.WaitGroup
	defer func() {
		cancel()
		r.conn.Close()
		for _, s := range sessions {
			s.conn.Close()
		}
		readers.Wait()
	}()
	events := make(chan packet, 256)
	read := func(conn *net.UDPConn, client netip.AddrPort, backend bool) {
		readers.Add(1)
		go func() { defer readers.Done(); readPackets(ctx, conn, client, backend, events) }()
	}
	read(r.conn, netip.AddrPort{}, false)
	audit := newSourceAudit(r.plan.audit)
	openBackend := func(client netip.AddrPort, s *session, awg bool) (*session, error) {
		target := r.plan.ts
		if awg {
			target = r.plan.awg
		}
		conn, err := net.DialUDP("udp", nil, target)
		if err != nil {
			return s, err
		}
		if s == nil {
			s = new(session)
		} else {
			s.conn.Close()
		}
		s.conn, s.awg = conn, awg
		sessions[client] = s
		read(conn, client, true)
		fields := []zap.Field{zap.String("event", "route_selected"), zap.String("remote_ip", client.Addr().String()), zap.Uint16("remote_port", client.Port()), zap.String("backend", target.String())}
		if awg {
			r.logger.Load().Info("switched UDP flow to AWG", append(fields, zap.String("reason", "third_packet_initiation_mac1"))...)
		} else {
			r.logger.Load().Debug("opened provisional TeamSpeak flow", fields...)
		}
		return s, nil
	}
	interval := r.plan.idle / 2
	if interval > time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			for client, s := range sessions {
				if now.Sub(s.lastClient) >= r.plan.idle {
					s.conn.Close()
					delete(sessions, client)
				}
			}
			audit.prune(now)
		case p := <-events:
			s := sessions[p.client]
			if p.backend != nil {
				if s == nil || s.conn != p.backend {
					continue
				}
				if p.err != nil {
					r.logger.Load().Debug("backend read failed", zap.String("event", "backend_error"), zap.String("remote_ip", p.client.Addr().String()), zap.String("backend", s.conn.RemoteAddr().String()), zap.Error(p.err))
					s.conn.Close()
					delete(sessions, p.client)
					continue
				}
				if _, err := r.conn.WriteToUDPAddrPort(p.data, p.client); err != nil {
					r.logger.Load().Debug("UDP client write failed", zap.String("event", "client_write_error"), zap.String("remote_ip", p.client.Addr().String()), zap.Error(err))
				}
				continue
			}
			if p.err != nil {
				if ctx.Err() != nil || errors.Is(p.err, net.ErrClosed) {
					return nil
				}
				return p.err
			}
			now := time.Now()
			if s == nil || (!s.awg && isFirstDecoy(p.data)) {
				audit.observe(now, p.client, r.logger.Load())
			}
			if s == nil {
				if len(sessions) >= r.plan.maxSessions {
					continue
				}
				var err error
				s, err = openBackend(p.client, nil, false)
				if err != nil {
					r.logger.Load().Debug("TeamSpeak backend open failed", zap.String("event", "backend_error"), zap.Error(err))
					continue
				}
			}
			s.lastClient = now
			if !s.awg {
				if isFirstDecoy(p.data) {
					s.clientPacket = 0
				}
				if s.clientPacket < 4 {
					s.clientPacket++
				}
				if s.clientPacket == 3 && r.plan.detector.matches(p.data) {
					switched, err := openBackend(p.client, s, true)
					if err != nil {
						r.logger.Load().Debug("AWG backend open failed", zap.String("event", "backend_error"), zap.Error(err))
						continue
					}
					s = switched
				}
			}
			if _, err := s.conn.Write(p.data); err != nil {
				r.logger.Load().Debug("backend write failed", zap.String("event", "backend_error"), zap.String("remote_ip", p.client.Addr().String()), zap.Error(err))
				s.conn.Close()
				delete(sessions, p.client)
			}
		}
	}
}
