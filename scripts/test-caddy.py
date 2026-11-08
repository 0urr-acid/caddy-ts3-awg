#!/usr/bin/env python3
"""Exercise the built Caddy, UDP forwarding, HTTP coexistence and JSON audit logs."""
import argparse
from contextlib import ExitStack
import http.client
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]


def udp(stack):
    conn = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    conn.bind(("127.0.0.1", 0))
    conn.settimeout(2)
    return conn


def receive(conn, expected):
    data, source = conn.recvfrom(65535)
    assert data == expected, "datagram changed or routed incorrectly"
    return source


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as conn:
        conn.bind(("127.0.0.1", 0))
        return conn.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caddy", type=Path, default=ROOT / "bin/caddy")
    args = parser.parse_args()
    vector = json.loads((ROOT / "testdata/initiation.json").read_text())
    initiation = bytes.fromhex(vector["packet_hex"])
    with tempfile.TemporaryDirectory(prefix="caddy-ts3-awg-") as temp, ExitStack() as stack:
        work = Path(temp)
        ts, awg, client, normal = [udp(stack) for _ in range(4)]
        front = ("127.0.0.1", free_port(socket.SOCK_DGRAM))
        http_port = free_port(socket.SOCK_STREAM)
        logs = work / "security.json"
        config = """{
 admin off
 persist_config off
 ts3_awg {
  server vpn {
   listen 127.0.0.1:FRONT
   teamspeak 127.0.0.1:TS
   awg 127.0.0.1:AWG
   initiation {
    server_public_key PUBLIC_KEY
    header_protection_key HEADER_KEY
    s1 24
    h1 100-200
    random_trailers true
   }
   audit {
    window 10s
    burst 2
   }
  }
 }
 log security {
  include ts3_awg
  output file LOG_PATH
  format json
  level INFO
 }
}
http://127.0.0.1:HTTP_PORT {
 respond "ok"
}
"""
        for token, value in {"FRONT": front[1], "TS": ts.getsockname()[1],
                             "AWG": awg.getsockname()[1], "HTTP_PORT": http_port,
                             "PUBLIC_KEY": vector["server_public_key"],
                             "HEADER_KEY": vector["header_protection_key"], "LOG_PATH": str(logs)}.items():
            # Tokens are intentionally upper-case and occur only at value sites.
            config = config.replace(token, str(value))
        caddyfile = work / "Caddyfile"
        caddyfile.write_text(config)
        output = stack.enter_context((work / "caddy-output.log").open("w+"))
        process = subprocess.Popen([str(args.caddy.resolve()), "run", "--config", str(caddyfile), "--adapter", "caddyfile"],
                                   cwd=work, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    output.seek(0)
                    raise RuntimeError(output.read())
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", http_port, timeout=0.2)
                    conn.request("GET", "/")
                    response = conn.getresponse()
                    assert response.status == 200 and response.read() == b"ok"
                    conn.close()
                    break
                except (OSError, http.client.HTTPException):
                    time.sleep(0.02)
            else:
                raise RuntimeError("Caddy did not become ready")
            i1 = bytearray(34)
            i1[:8] = b"TS3INIT1"
            i1[12] = 0x88
            client.sendto(i1, front)
            ts_source = receive(ts, i1)
            client.sendto(b"second-decoy", front)
            receive(ts, b"second-decoy")
            ts.sendto(b"real-ts-response", ts_source)
            receive(client, b"real-ts-response")
            client.sendto(initiation, front)
            awg_source = receive(awg, initiation)
            awg.sendto(b"awg-response", awg_source)
            receive(client, b"awg-response")
            client.sendto(b"encrypted-data", front)
            receive(awg, b"encrypted-data")
            # Another ordinary client remains on TeamSpeak.
            for data in (b"normal-first", b"normal-second", b"normal-third"):
                normal.sendto(data, front)
                receive(ts, data)
            # A third source tuple crosses the test's configured audit threshold.
            flood = udp(stack)
            flood.sendto(b"new-tuple", front)
            receive(ts, b"new-tuple")
            deadline = time.monotonic() + 3
            events = []
            while time.monotonic() < deadline:
                if logs.exists():
                    events = [json.loads(line) for line in logs.read_text().splitlines() if line.strip()]
                    if any(event.get("event") == "suspicious_connection" for event in events):
                        break
                time.sleep(0.02)
            suspicious = [event for event in events if event.get("event") == "suspicious_connection"]
            assert len(suspicious) == 1, "missing or repeated audit event"
            event = suspicious[0]
            assert event["logger"] == "ts3_awg" and event["remote_ip"] == "127.0.0.1"
            assert event["reason"] == "session_start_rate" and event["attempts"] == 3
            assert event["threshold"] == 2 and isinstance(event["ts"], (float, int))
            assert vector["header_protection_key"] not in logs.read_text()
            print("Built Caddy: HTTP coexistence, third-packet UDP routing and JSON audit OK")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise RuntimeError("Caddy shutdown hung")


if __name__ == "__main__":
    main()
