package ts3awg

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"
)

const initiationSize = 148

// InitiationConfig describes the responder framing used to recognize AWG initiation.
type InitiationConfig struct {
	ServerPublicKey     string          `json:"server_public_key"`
	S1                  int             `json:"s1"`
	H1                  json.RawMessage `json:"h1"`
	HeaderProtectionKey string          `json:"header_protection_key"`
	RandomTrailers      bool            `json:"random_trailers"`
}

type initiationDetector struct {
	padding        int
	h1Low, h1High  uint32
	headerKey      []byte
	macKey         [32]byte
	randomTrailers bool
}

func newDetector(opts InitiationConfig) (*initiationDetector, error) {
	publicKey, err := base64.StdEncoding.DecodeString(opts.ServerPublicKey)
	if err != nil || len(publicKey) != 32 || bytes.Equal(publicKey, make([]byte, 32)) {
		return nil, errors.New("server_public_key must be a nonzero 32-byte base64 key")
	}
	if opts.S1 < 0 || opts.S1 > 65507-initiationSize {
		return nil, errors.New("s1 out of UDP size bounds")
	}
	d := &initiationDetector{padding: opts.S1, h1Low: 1, h1High: 1, randomTrailers: opts.RandomTrailers}
	if len(opts.H1) != 0 {
		spec := string(opts.H1)
		if opts.H1[0] == '"' {
			if err := json.Unmarshal(opts.H1, &spec); err != nil {
				return nil, fmt.Errorf("h1: %w", err)
			}
		}
		parts := strings.Split(spec, "-")
		if len(parts) > 2 {
			return nil, errors.New("h1 must be a uint32 or an inclusive min-max range")
		}
		lo, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("h1: %w", err)
		}
		hi := lo
		if len(parts) == 2 {
			hi, err = strconv.ParseUint(parts[1], 10, 32)
			if err != nil || hi < lo {
				return nil, errors.New("invalid h1 range")
			}
		}
		d.h1Low, d.h1High = uint32(lo), uint32(hi)
	}
	if opts.HeaderProtectionKey != "" {
		key, err := base64.StdEncoding.DecodeString(opts.HeaderProtectionKey)
		if err != nil || len(key) != 32 {
			return nil, errors.New("header_protection_key must be a 32-byte base64 key")
		}
		if !bytes.Equal(key, make([]byte, 32)) {
			if opts.S1 < chacha20.NonceSize {
				return nil, errors.New("s1 must be at least 12 with header protection")
			}
			d.headerKey = key
		}
	}
	// WG MAC1 key = BLAKE2s-256("mac1----" || responder public key).
	d.macKey = blake2s.Sum256(append([]byte("mac1----"), publicKey...))
	return d, nil
}

// AWG v3.1 encrypts the full 148-byte initiation with ChaCha20 counter 0,
// nonce = the first 12 padding bytes. Random trailers are outside the message
// and MAC1. See amneziawg-go v3.1.20260828 device/{send,noise-protocol,cookie}.go.
// This is classification, not peer authentication: the AWG backend still
// validates Noise, the configured peer, timestamp, replay protection and MAC2.
func (d *initiationDetector) matches(packet []byte) bool {
	expected := d.padding + initiationSize
	if len(packet) < expected || len(packet) > 65507 || (!d.randomTrailers && len(packet) != expected) {
		return false
	}
	var msg [initiationSize]byte
	copy(msg[:], packet[d.padding:expected])
	if len(d.headerKey) != 0 {
		cipher, err := chacha20.NewUnauthenticatedCipher(d.headerKey, packet[:chacha20.NonceSize])
		if err != nil {
			return false
		}
		cipher.XORKeyStream(msg[:], msg[:])
	}
	typ := binary.LittleEndian.Uint32(msg[:4])
	if typ < d.h1Low || typ > d.h1High {
		return false
	}
	mac, _ := blake2s.New128(d.macKey[:])
	mac.Write(msg[:116])
	return hmac.Equal(mac.Sum(nil), msg[116:132])
}
