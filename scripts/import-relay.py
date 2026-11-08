#!/usr/bin/env python3
"""Import standalone forwarder's relay.json into a private Caddy environment file."""
import argparse
import base64
import json
import os
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("relay", type=Path)
    parser.add_argument("--out", type=Path, default=Path(".env"))
    args = parser.parse_args()
    settings = json.loads(args.relay.read_text())
    public = settings["server_public_key"]
    header = settings.get("header_protection_key", "")
    for name, value in (("server_public_key", public), ("header_protection_key", header)):
        if name == "header_protection_key" and not value:
            continue
        if len(base64.b64decode(value, validate=True)) != 32:
            parser.error(f"{name} must contain a 32-byte base64 key")
    padding = settings.get("s1", 0)
    h1 = str(settings.get("h1", 1))
    trailers = settings.get("random_trailers", False)
    if type(padding) is not int or not 0 <= padding <= 65359:
        parser.error("invalid s1")
    if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", h1):
        parser.error("invalid h1")
    if type(trailers) is not bool:
        parser.error("random_trailers must be boolean")
    values = {"AWG_SERVER_PUBLIC_KEY": public, "AWG_HEADER_PROTECTION_KEY": header,
              "AWG_S1": str(padding), "AWG_H1": h1,
              "AWG_RANDOM_TRAILERS": str(trailers).lower()}
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        for key, value in values.items():
            stream.write(f'{key}="{value}"\n')
    print(f"Created private environment file: {args.out}")


if __name__ == "__main__":
    main()
