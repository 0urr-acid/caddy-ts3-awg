// Package ts3awg provides a standalone UDP TS3/AWG multiplexer for Caddy.
package ts3awg

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() { caddy.RegisterModule(App{}) }

// App owns UDP relays independently of Caddy's TCP listener wrappers and HTTP/3.
type App struct {
	Servers map[string]*Server `json:"servers,omitempty"`
	plans   []relayPlan
	handles []relayHandle
	logger  *zap.Logger
}

// Server configures one UDP listener and its two fixed backends.
type Server struct {
	Listen      string           `json:"listen"`
	TeamSpeak   string           `json:"teamspeak"`
	AWG         string           `json:"awg"`
	Initiation  InitiationConfig `json:"initiation"`
	IdleTimeout caddy.Duration   `json:"idle_timeout,omitempty"`
	MaxSessions int              `json:"max_sessions,omitempty"`
	Audit       *AuditConfig     `json:"audit,omitempty"`
}

// AuditConfig bounds source tracking and reports repeated session starts.
// It never treats a failed initiation check as a security event.
type AuditConfig struct {
	Window     caddy.Duration `json:"window,omitempty"`
	Burst      int            `json:"burst,omitempty"`
	MaxSources int            `json:"max_sources,omitempty"`
}

type relayPlan struct {
	name        string
	key         string
	network     string
	listen      *net.UDPAddr
	ts, awg     *net.UDPAddr
	detector    *initiationDetector
	idle        time.Duration
	maxSessions int
	audit       AuditConfig
	fingerprint [32]byte
}

type relayHandle struct {
	key   string
	relay *sharedRelay
}

// CaddyModule implements caddy.Module.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "ts3_awg", New: func() caddy.Module { return new(App) }}
}

// Provision validates configuration without opening sockets.
func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger(a)
	a.plans = nil
	if len(a.Servers) == 0 {
		return errors.New("ts3_awg: at least one server is required")
	}
	names := make([]string, 0, len(a.Servers))
	for name := range a.Servers {
		names = append(names, name)
	}
	sort.Strings(names)
	keys := make(map[string]bool)
	for _, name := range names {
		s := a.Servers[name]
		if s == nil || name == "" {
			return errors.New("ts3_awg: server name and configuration must be nonempty")
		}
		plan, err := makePlan(name, s)
		if err != nil {
			return fmt.Errorf("ts3_awg server %s: %w", name, err)
		}
		if keys[plan.key] {
			return fmt.Errorf("ts3_awg: duplicate listener %s", plan.key)
		}
		keys[plan.key] = true
		a.plans = append(a.plans, plan)
	}
	return nil
}

func makePlan(name string, input *Server) (relayPlan, error) {
	s := *input
	replacer := caddy.NewReplacer()
	for field, value := range map[string]*string{
		"listen": &s.Listen, "teamspeak": &s.TeamSpeak, "awg": &s.AWG,
		"server_public_key":     &s.Initiation.ServerPublicKey,
		"header_protection_key": &s.Initiation.HeaderProtectionKey,
	} {
		resolved, err := replacer.ReplaceOrErr(*value, true, true)
		if err != nil {
			return relayPlan{}, fmt.Errorf("%s: unresolved or empty placeholder", field)
		}
		*value = resolved
	}
	listen := s.Listen
	if !strings.Contains(listen, "/") {
		listen = "udp/" + listen
	}
	addr, err := caddy.ParseNetworkAddress(listen)
	if err != nil {
		return relayPlan{}, fmt.Errorf("listen: %w", err)
	}
	if addr.Network != "udp" && addr.Network != "udp4" && addr.Network != "udp6" {
		return relayPlan{}, errors.New("listen must use udp, udp4 or udp6")
	}
	if addr.StartPort == 0 || addr.PortRangeSize() != 1 {
		return relayPlan{}, errors.New("listen must specify one nonzero port")
	}
	if addr.Host != "" {
		if _, err := netip.ParseAddr(addr.Host); err != nil {
			return relayPlan{}, errors.New("listen host must be a literal IP address")
		}
	}
	listenAddr, err := net.ResolveUDPAddr(addr.Network, addr.JoinHostPort(0))
	if err != nil {
		return relayPlan{}, fmt.Errorf("listen: %w", err)
	}
	backend := func(field, value string) (*net.UDPAddr, error) {
		ap, err := netip.ParseAddrPort(value)
		if err != nil || ap.Port() == 0 || ap.Addr().IsUnspecified() || ap.Addr().IsMulticast() {
			return nil, fmt.Errorf("%s must be a literal unicast IP:port", field)
		}
		return net.UDPAddrFromAddrPort(ap), nil
	}
	ts, err := backend("teamspeak", s.TeamSpeak)
	if err != nil {
		return relayPlan{}, err
	}
	awg, err := backend("awg", s.AWG)
	if err != nil {
		return relayPlan{}, err
	}
	if ts.String() == awg.String() {
		return relayPlan{}, errors.New("teamspeak and awg must be different backends")
	}
	for _, target := range []*net.UDPAddr{ts, awg} {
		if target.Port != listenAddr.Port {
			continue
		}
		local := listenAddr.IP.Equal(target.IP)
		if len(listenAddr.IP) == 0 || listenAddr.IP.IsUnspecified() {
			// A wildcard covers local interfaces, not remote servers that happen
			// to use the same port (e.g. remote TS3 :9987 behind public :9987).
			local = target.IP.IsLoopback()
			if !local {
				addresses, err := net.InterfaceAddrs()
				if err != nil {
					return relayPlan{}, fmt.Errorf("checking local backend addresses: %w", err)
				}
				for _, address := range addresses {
					if ipnet, ok := address.(*net.IPNet); ok && ipnet.IP.Equal(target.IP) {
						local = true
						break
					}
				}
			}
			if addr.Network == "udp4" && target.IP.To4() == nil || addr.Network == "udp6" && target.IP.To4() != nil {
				local = false
			}
		}
		if local {
			return relayPlan{}, errors.New("a backend must not point back to this listener")
		}
	}
	detector, err := newDetector(s.Initiation)
	if err != nil {
		return relayPlan{}, fmt.Errorf("initiation: %w", err)
	}
	if s.IdleTimeout == 0 {
		s.IdleTimeout = caddy.Duration(2 * time.Minute)
	}
	if s.MaxSessions == 0 {
		s.MaxSessions = 1024
	}
	if s.IdleTimeout < caddy.Duration(time.Millisecond) || s.MaxSessions < 1 {
		return relayPlan{}, errors.New("idle_timeout must be >= 1ms and max_sessions must be positive")
	}
	audit := AuditConfig{}
	if s.Audit != nil {
		audit = *s.Audit
	}
	if audit.Window == 0 {
		audit.Window = caddy.Duration(10 * time.Second)
	}
	if audit.Burst == 0 {
		audit.Burst = 60
	}
	if audit.MaxSources == 0 {
		audit.MaxSources = 16384
	}
	if audit.Window < caddy.Duration(time.Millisecond) || audit.Burst < 1 || audit.MaxSources < 1 {
		return relayPlan{}, errors.New("audit window must be >= 1ms; burst and max_sources must be positive")
	}
	s.Audit = &audit
	s.Listen = addr.String()
	encoded, err := json.Marshal(struct {
		Name   string
		Server Server
	}{name, s})
	if err != nil {
		return relayPlan{}, err
	}
	return relayPlan{name: name, key: addr.String(), network: addr.Network,
		listen: listenAddr, ts: ts, awg: awg, detector: detector,
		idle: time.Duration(s.IdleTimeout), maxSessions: s.MaxSessions, audit: audit,
		fingerprint: sha256.Sum256(encoded)}, nil
}

var relays = caddy.NewUsagePool()

// Start opens listeners. Unchanged relays are shared across Caddy reloads,
// preserving established AWG mappings rather than reclassifying data as TS3.
func (a *App) Start() error {
	if len(a.handles) != 0 {
		return errors.New("ts3_awg already started")
	}
	for _, plan := range a.plans {
		plan := plan
		value, _, err := relays.LoadOrNew(plan.key, func() (caddy.Destructor, error) { return newSharedRelay(plan) })
		if err != nil {
			a.Stop()
			return fmt.Errorf("listen %s: %w", plan.key, err)
		}
		r := value.(*sharedRelay)
		if r.plan.fingerprint != plan.fingerprint || !r.running.Load() {
			relays.Delete(plan.key)
			a.Stop()
			return fmt.Errorf("listener %s already runs with different settings or has stopped; restart Caddy to change a live relay", plan.key)
		}
		r.addOwner(a, a.logger.With(zap.String("server", plan.name), zap.String("listen", plan.key)))
		a.handles = append(a.handles, relayHandle{plan.key, r})
	}
	return nil
}

// Stop releases this app's references; sockets close after their final owner.
func (a *App) Stop() error {
	var errs []error
	for _, handle := range a.handles {
		handle.relay.removeOwner(a)
		if _, err := relays.Delete(handle.key); err != nil {
			errs = append(errs, err)
		}
	}
	a.handles = nil
	return errors.Join(errs...)
}

// Cleanup also handles partial starts and validation-only loads.
func (a *App) Cleanup() error { return a.Stop() }

type sharedRelay struct {
	plan      relayPlan
	conn      *net.UDPConn
	cancel    context.CancelFunc
	done      chan struct{}
	running   atomic.Bool
	logger    atomic.Pointer[zap.Logger]
	ownersMu  sync.Mutex
	owners    []*App
	ownerLogs map[*App]*zap.Logger
}

func newSharedRelay(plan relayPlan) (*sharedRelay, error) {
	conn, err := net.ListenUDP(plan.network, plan.listen)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &sharedRelay{plan: plan, conn: conn, cancel: cancel, done: make(chan struct{}), ownerLogs: make(map[*App]*zap.Logger)}
	r.logger.Store(zap.NewNop())
	r.running.Store(true)
	go func() {
		defer close(r.done)
		defer r.running.Store(false)
		if err := r.serve(ctx); err != nil {
			r.logger.Load().Error("UDP relay stopped", zap.String("event", "listener_error"), zap.Error(err))
		}
	}()
	return r, nil
}

func (r *sharedRelay) addOwner(a *App, logger *zap.Logger) {
	r.ownersMu.Lock()
	defer r.ownersMu.Unlock()
	r.owners = append(r.owners, a)
	r.ownerLogs[a] = logger
	r.logger.Store(logger)
}

func (r *sharedRelay) removeOwner(a *App) {
	r.ownersMu.Lock()
	defer r.ownersMu.Unlock()
	delete(r.ownerLogs, a)
	for i, owner := range r.owners {
		if owner == a {
			r.owners = append(r.owners[:i], r.owners[i+1:]...)
			break
		}
	}
	if len(r.owners) != 0 {
		r.logger.Store(r.ownerLogs[r.owners[len(r.owners)-1]])
	}
}

func (r *sharedRelay) Destruct() error {
	r.cancel()
	r.conn.Close()
	<-r.done
	return nil
}

var (
	_ caddy.App          = (*App)(nil)
	_ caddy.Provisioner  = (*App)(nil)
	_ caddy.CleanerUpper = (*App)(nil)
	_ caddy.Destructor   = (*sharedRelay)(nil)
)
