package ts3awg

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestCaddyfileAdapterAndPlaceholders(t *testing.T) {
	_, _, opts := vectorTest(t)
	t.Setenv("TEST_AWG_PUBLIC_KEY", opts.ServerPublicKey)
	t.Setenv("TEST_AWG_HEADER_KEY", opts.HeaderProtectionKey)
	input := `{
 ts3_awg {
  server vpn {
   listen :9987
   teamspeak 127.0.0.1:9988
   awg 127.0.0.1:51820
   initiation {
    server_public_key {env.TEST_AWG_PUBLIC_KEY}
    header_protection_key {env.TEST_AWG_HEADER_KEY}
    s1 24
    h1 100-200
    random_trailers true
   }
   idle_timeout 3m
   max_sessions 42
   audit {
    window 10s
    burst 60
    max_sources 256
   }
  }
 }
}
http://127.0.0.1:8080 {
 respond "ok"
}
`
	adapted, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Apps map[string]json.RawMessage `json:"apps"`
	}
	if err := json.Unmarshal(adapted, &document); err != nil {
		t.Fatal(err)
	}
	if _, ok := document.Apps["http"]; !ok {
		t.Fatal("plugin removed HTTP app")
	}
	var app App
	if err := json.Unmarshal(document.Apps["ts3_awg"], &app); err != nil {
		t.Fatal(err)
	}
	server := app.Servers["vpn"]
	if server == nil || server.MaxSessions != 42 || server.Audit.MaxSources != 256 {
		t.Fatal("Caddyfile settings lost")
	}
	if !strings.Contains(string(adapted), "{env.TEST_AWG_HEADER_KEY}") {
		t.Fatal("adapt expanded a secret instead of preserving its placeholder")
	}
	plan, err := makePlan("vpn", server)
	if err != nil {
		t.Fatal(err)
	}
	if plan.detector.padding != 24 || plan.detector.h1Low != 100 {
		t.Fatal("wrong detector parameters")
	}
	if strings.Contains(string(adapted), opts.HeaderProtectionKey) {
		t.Fatal("adapted JSON exposed environment secret")
	}
}

func TestCaddyfileRejectsUnknownAndDuplicateFields(t *testing.T) {
	for _, input := range []string{
		`ts3_awg { mystery x }`,
		"ts3_awg {\n server x {\n listen :9987\n listen :9988\n }\n}",
		"ts3_awg {\n server x {\n initiation {\n mystery value\n }\n }\n}",
		"ts3_awg {\n server x {\n audit {\n burst -1\n }\n }\n}",
		"ts3_awg {\n server x {\n max_sessions -1\n }\n}",
		"ts3_awg {\n server x {\n }\n server x {\n }\n}",
	} {
		t.Run(input, func(t *testing.T) {
			var app App
			if err := app.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatal("invalid Caddyfile accepted")
			}
		})
	}
}
