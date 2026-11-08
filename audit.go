package ts3awg

import (
	"net/netip"
	"time"

	"go.uber.org/zap"
)

type sourceWindow struct {
	start    time.Time
	count    uint64
	reported bool
}

// sourceAudit is owned by the relay event loop. Only new tuples and pre-AWG
// I1 restarts are counted, never ordinary voice packets or failed MAC1 checks.
type sourceAudit struct {
	config  AuditConfig
	sources map[netip.Addr]sourceWindow
}

func newSourceAudit(config AuditConfig) *sourceAudit {
	return &sourceAudit{config: config, sources: make(map[netip.Addr]sourceWindow)}
}

func (a *sourceAudit) observe(now time.Time, client netip.AddrPort, logger *zap.Logger) {
	ip := client.Addr().Unmap()
	window, exists := a.sources[ip]
	if !exists && len(a.sources) >= a.config.MaxSources {
		return
	}
	if !exists || now.Sub(window.start) >= time.Duration(a.config.Window) {
		window = sourceWindow{start: now}
	}
	if window.count < ^uint64(0) {
		window.count++
	}
	if window.count > uint64(a.config.Burst) && !window.reported {
		window.reported = true
		logger.Warn("suspicious UDP connection rate",
			zap.String("event", "suspicious_connection"),
			zap.String("reason", "session_start_rate"),
			zap.String("remote_ip", ip.String()), zap.Uint16("remote_port", client.Port()),
			zap.Uint64("attempts", window.count), zap.Int("threshold", a.config.Burst),
			zap.Float64("window_seconds", time.Duration(a.config.Window).Seconds()))
	}
	a.sources[ip] = window
}

func (a *sourceAudit) prune(now time.Time) {
	for ip, window := range a.sources {
		if now.Sub(window.start) >= 2*time.Duration(a.config.Window) {
			delete(a.sources, ip)
		}
	}
}
