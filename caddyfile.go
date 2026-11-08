package ts3awg

import (
	"encoding/json"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() { httpcaddyfile.RegisterGlobalOption("ts3_awg", parseGlobalOption) }

func parseGlobalOption(d *caddyfile.Dispenser, existing any) (any, error) {
	a := new(App)
	if existing != nil {
		previous, ok := existing.(httpcaddyfile.App)
		if !ok {
			return nil, d.Err("invalid prior ts3_awg option")
		}
		if err := json.Unmarshal(previous.Value, a); err != nil {
			return nil, err
		}
	}
	if err := a.UnmarshalCaddyfile(d); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return httpcaddyfile.App{Name: "ts3_awg", Value: encoded}, nil
}

// UnmarshalCaddyfile implements the ts3_awg global option.
//
//	ts3_awg {
//	    server <name> {
//	        listen <udp-address>
//	        teamspeak <ip:port>
//	        awg <ip:port>
//	        initiation {
//	            server_public_key <base64-or-placeholder>
//	            s1 <bytes>
//	            h1 <uint32-or-min-max>
//	            header_protection_key <base64-or-placeholder>
//	            random_trailers <bool>
//	        }
//	        idle_timeout <duration>
//	        max_sessions <count>
//	        audit {
//	            window <duration>
//	            burst <count>
//	            max_sources <count>
//	        }
//	    }
//	}
func (a *App) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if a.Servers == nil {
		a.Servers = make(map[string]*Server)
	}
	for d.Next() {
		if len(d.RemainingArgs()) != 0 {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			if d.Val() != "server" {
				return d.Errf("unknown ts3_awg subdirective %q", d.Val())
			}
			var name string
			if !d.AllArgs(&name) {
				return d.ArgErr()
			}
			if _, exists := a.Servers[name]; exists {
				return d.Errf("duplicate ts3_awg server %q", name)
			}
			s := new(Server)
			seen := make(map[string]bool)
			for d.NextBlock(1) {
				field := d.Val()
				if seen[field] {
					return d.Errf("duplicate server field %q", field)
				}
				seen[field] = true
				switch field {
				case "initiation":
					if len(d.RemainingArgs()) != 0 {
						return d.ArgErr()
					}
					if err := parseInitiation(d, &s.Initiation); err != nil {
						return err
					}
				case "audit":
					if len(d.RemainingArgs()) != 0 {
						return d.ArgErr()
					}
					s.Audit = new(AuditConfig)
					if err := parseAudit(d, s.Audit); err != nil {
						return err
					}
				case "listen", "teamspeak", "awg", "idle_timeout", "max_sessions":
					var value string
					if !d.AllArgs(&value) {
						return d.ArgErr()
					}
					switch field {
					case "listen":
						s.Listen = value
					case "teamspeak":
						s.TeamSpeak = value
					case "awg":
						s.AWG = value
					case "idle_timeout":
						duration, err := caddy.ParseDuration(value)
						if err != nil || duration <= 0 {
							return d.Err("idle_timeout must be a positive duration")
						}
						s.IdleTimeout = caddy.Duration(duration)
					case "max_sessions":
						n, err := strconv.Atoi(value)
						if err != nil || n <= 0 {
							return d.Err("max_sessions must be positive")
						}
						s.MaxSessions = n
					}
				default:
					return d.Errf("unknown ts3_awg server field %q", field)
				}
			}
			a.Servers[name] = s
		}
	}
	return nil
}

func parseInitiation(d *caddyfile.Dispenser, opts *InitiationConfig) error {
	seen := make(map[string]bool)
	for d.NextBlock(2) {
		field := d.Val()
		if seen[field] {
			return d.Errf("duplicate initiation field %q", field)
		}
		seen[field] = true
		var value string
		if !d.AllArgs(&value) {
			return d.ArgErr()
		}
		switch field {
		case "server_public_key":
			opts.ServerPublicKey = value
		case "header_protection_key":
			opts.HeaderProtectionKey = value
		case "h1":
			opts.H1, _ = json.Marshal(value)
		case "s1":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return d.Err("s1 must be nonnegative")
			}
			opts.S1 = n
		case "random_trailers":
			b, err := strconv.ParseBool(value)
			if err != nil {
				return d.Err("random_trailers must be true or false")
			}
			opts.RandomTrailers = b
		default:
			return d.Errf("unknown initiation field %q", field)
		}
	}
	return nil
}

func parseAudit(d *caddyfile.Dispenser, audit *AuditConfig) error {
	seen := make(map[string]bool)
	for d.NextBlock(2) {
		field := d.Val()
		if seen[field] {
			return d.Errf("duplicate audit field %q", field)
		}
		seen[field] = true
		var value string
		if !d.AllArgs(&value) {
			return d.ArgErr()
		}
		switch field {
		case "window":
			duration, err := caddy.ParseDuration(value)
			if err != nil || duration <= 0 {
				return d.Err("audit window must be positive")
			}
			audit.Window = caddy.Duration(duration)
		case "burst", "max_sources":
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return d.Errf("%s must be positive", field)
			}
			if field == "burst" {
				audit.Burst = n
			} else {
				audit.MaxSources = n
			}
		default:
			return d.Errf("unknown audit field %q", field)
		}
	}
	return nil
}

var _ caddyfile.Unmarshaler = (*App)(nil)
