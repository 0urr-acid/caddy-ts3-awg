package ts3awg

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func vectorTest(t *testing.T) (*initiationDetector, []byte, InitiationConfig) {
	t.Helper()
	b, err := os.ReadFile("testdata/initiation.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		InitiationConfig
		PacketHex string `json:"packet_hex"`
	}
	if err := json.Unmarshal(b, &vector); err != nil {
		t.Fatal(err)
	}
	d, err := newDetector(vector.InitiationConfig)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := hex.DecodeString(vector.PacketHex)
	if err != nil {
		t.Fatal(err)
	}
	return d, packet, vector.InitiationConfig
}

func TestIndependentInitiationVector(t *testing.T) {
	d, packet, opts := vectorTest(t)
	original := bytes.Clone(packet)
	if !d.matches(packet) {
		t.Fatal("independent Python Noise initiation vector rejected")
	}
	if !bytes.Equal(packet, original) {
		t.Fatal("detector modified forwarded datagram")
	}
	for length := 0; length < d.padding+initiationSize; length++ {
		if d.matches(packet[:length]) {
			t.Fatalf("accepted truncated packet: %d", length)
		}
	}
	bad := bytes.Clone(packet)
	bad[d.padding+116] ^= 1
	if d.matches(bad) {
		t.Fatal("accepted wrong MAC1")
	}
	bad = bytes.Clone(packet)
	bad[0] ^= 1
	if d.matches(bad) {
		t.Fatal("accepted wrong header cipher nonce")
	}
	wrongKey := opts
	wrongKey.HeaderProtectionKey = opts.ServerPublicKey
	d2, err := newDetector(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if d2.matches(packet) {
		t.Fatal("accepted wrong header protection key")
	}
	wrongPublic := opts
	wrongPublic.ServerPublicKey = opts.HeaderProtectionKey
	d2, err = newDetector(wrongPublic)
	if err != nil {
		t.Fatal(err)
	}
	if d2.matches(packet) {
		t.Fatal("accepted MAC1 for another responder")
	}
	wrongType := opts
	wrongType.H1 = json.RawMessage(`"200-300"`)
	d2, err = newDetector(wrongType)
	if err != nil {
		t.Fatal(err)
	}
	if d2.matches(packet) {
		t.Fatal("accepted initiation type outside configured H1 range")
	}
	opts.RandomTrailers = false
	d2, err = newDetector(opts)
	if err != nil {
		t.Fatal(err)
	}
	if d2.matches(packet) {
		t.Fatal("accepted trailer when disabled")
	}
	if !d2.matches(packet[:d.padding+initiationSize]) {
		t.Fatal("rejected exact-length initiation")
	}
}

func TestDetectorConfigValidation(t *testing.T) {
	_, _, opts := vectorTest(t)
	for _, raw := range []string{`null`, `-1`, `1.5`, `4294967296`, `"4-2"`, `"1-2-3"`} {
		t.Run(raw, func(t *testing.T) {
			o := opts
			o.H1 = json.RawMessage(raw)
			if _, err := newDetector(o); err == nil {
				t.Fatal("invalid H1 accepted")
			}
		})
	}
	opts.S1 = 11
	if _, err := newDetector(opts); err == nil {
		t.Fatal("short header protection nonce accepted")
	}
}

func TestPlainInitiationVector(t *testing.T) {
	_, _, opts := vectorTest(t)
	b, err := os.ReadFile("testdata/initiation.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		PlainHex string `json:"plain_hex"`
	}
	if err := json.Unmarshal(b, &vector); err != nil {
		t.Fatal(err)
	}
	plain, err := hex.DecodeString(vector.PlainHex)
	if err != nil {
		t.Fatal(err)
	}
	opts.S1 = 0
	opts.H1 = json.RawMessage(`123`)
	opts.HeaderProtectionKey = ""
	opts.RandomTrailers = false
	d, err := newDetector(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !d.matches(plain) {
		t.Fatal("plain initiation with numeric H1 rejected")
	}
}
