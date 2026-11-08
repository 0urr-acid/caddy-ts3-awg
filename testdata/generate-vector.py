"""Independent Noise IK initiation fixture: Python hashlib + cryptography.

Deterministic private keys here are TEST DATA ONLY. No production keys are read.
Layout follows amneziawg-go v3.1.20260828 device/noise-protocol.go and send.go.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def digest(data):
    return hashlib.blake2s(data).digest()


def kdf(chain, data):
    temp = hmac.digest(chain, data, hashlib.blake2s)
    first = hmac.digest(temp, b"\x01", hashlib.blake2s)
    return first, hmac.digest(temp, first + b"\x02", hashlib.blake2s)


def public(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


server = X25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
client = X25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
ephemeral = X25519PrivateKey.from_private_bytes(bytes(range(65, 97)))
server_public = public(server)
chain = digest(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
transcript = digest(chain + b"WireGuard v1 zx2c4 Jason@zx2c4.com")
transcript = digest(transcript + server_public)
transcript = digest(transcript + public(ephemeral))
chain, _ = kdf(chain, public(ephemeral))
chain, key = kdf(chain, ephemeral.exchange(server.public_key()))
encrypted_static = ChaCha20Poly1305(key).encrypt(bytes(12), public(client), transcript)
transcript = digest(transcript + encrypted_static)
chain, key = kdf(chain, client.exchange(server.public_key()))
timestamp = struct.pack(">QI", 0x400000000000000A + 1794153080, 123456789)
encrypted_timestamp = ChaCha20Poly1305(key).encrypt(bytes(12), timestamp, transcript)
body = struct.pack("<II", 123, 0x12345678) + public(ephemeral) + encrypted_static + encrypted_timestamp
assert len(body) == 116
mac_key = digest(b"mac1----" + server_public)
msg = body + hashlib.blake2s(body, key=mac_key, digest_size=16).digest() + bytes(16)
header_key = bytes(range(101, 133))
padding = bytes(range(151, 175))
# cryptography's original ChaCha20 takes 16 state bytes. Counter 0 followed
# by the 12-byte IETF nonce gives the same initial state and first 148 bytes.
encryptor = Cipher(algorithms.ChaCha20(header_key, bytes(4) + padding[:12]), mode=None).encryptor()
packet = padding + encryptor.update(msg) + b"example-random-trailer"
fixture = {
    "server_public_key": base64.b64encode(server_public).decode(),
    "header_protection_key": base64.b64encode(header_key).decode(),
    "s1": 24, "h1": "100-200", "random_trailers": True,
    "packet_hex": packet.hex(), "plain_hex": msg.hex(),
}
Path(__file__).with_name("initiation.json").write_text(json.dumps(fixture, indent=2) + "\n")
