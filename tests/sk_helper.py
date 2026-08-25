#!/usr/bin/env python3
"""
sk_helper.py, stand in for a FIDO authenticator in the tests.

A security key signs differently from a plain Ed25519 key.  It hashes the
application string ("ssh:" by default), adds a flags byte and a signature
counter, and signs

    SHA256(application) || flags || counter || SHA256(message)

The public key carries the application, and the SSH signature carries the
flags and the counter after the raw 64 bytes.  This script does exactly
that with a software key, so the tests exercise the module's real
verification path without hardware.  It is a test helper, not part of the
installed tools.

Usage:
  sk_helper.py keygen <dir> [--type sk-ssh-ed25519@openssh.com]
                            [--application ssh:] [--comment sk]
      Writes <dir>/sk (raw private key) and <dir>/sk.pub (one
      authorized_keys line) and prints the public key line.

  sk_helper.py token <dir> [--flags 1] [--counter 7] [--at TS]
                           [--nonce HEX] [--application-override X]
                           [--cert FILE]
      Prints a v2 token whose signature field is the security key's
      signature: base64(sig64 || flags || counter).

SPDX-License-Identifier: MIT
"""

import argparse
import base64
import hashlib
import os
import secrets
import struct
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Rocky 9 ships a cryptography old enough to lack private_bytes_raw().
_RAW_PRIV = dict(encoding=serialization.Encoding.Raw,
                 format=serialization.PrivateFormat.Raw,
                 encryption_algorithm=serialization.NoEncryption())
_RAW_PUB = dict(encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw)

PREFIX_V2 = b"pg-sshkey-v2\x00"
PREFIX_V3 = b"pg-sshkey-v3\x00"


def sshstr(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def keygen(args) -> int:
    if not os.path.isdir(args.dir):
        sys.stderr.write(f"sk_helper.py: not a directory: {args.dir}\n")
        return 1
    key = Ed25519PrivateKey.generate()
    raw_priv = key.private_bytes(**_RAW_PRIV)
    raw_pub = key.public_key().public_bytes(**_RAW_PUB)
    with open(os.path.join(args.dir, "sk"), "wb") as f:
        f.write(raw_priv)
    os.chmod(os.path.join(args.dir, "sk"), 0o600)
    with open(os.path.join(args.dir, "sk.application"), "w") as f:
        f.write(args.application)

    blob = (sshstr(args.type.encode())
            + sshstr(raw_pub)
            + sshstr(args.application.encode()))
    line = f"{args.type} {base64.b64encode(blob).decode()} {args.comment}\n"
    with open(os.path.join(args.dir, "sk.pub"), "w") as f:
        f.write(line)
    sys.stdout.write(line)
    return 0


def token(args) -> int:
    if not os.path.exists(os.path.join(args.dir, "sk")):
        sys.stderr.write(
            f"sk_helper.py: no key in {args.dir}; run 'sk_helper.py keygen' first\n")
        return 1
    if not 0 <= args.counter <= 0xffffffff:
        sys.stderr.write("sk_helper.py: --counter must fit in 32 bits\n")
        return 1
    with open(os.path.join(args.dir, "sk"), "rb") as f:
        key = Ed25519PrivateKey.from_private_bytes(f.read())
    with open(os.path.join(args.dir, "sk.application")) as f:
        application = f.read()
    if args.application_override is not None:
        application = args.application_override

    ts = args.at if args.at is not None else int(time.time())
    nonce = args.nonce or secrets.token_bytes(32).hex()
    head = f"{ts}:{nonce}"
    prefix = PREFIX_V3 if args.cert else PREFIX_V2
    message = prefix + head.encode("ascii")

    counter = struct.pack(">I", args.counter)
    flags = bytes([args.flags])
    signed = (hashlib.sha256(application.encode()).digest()
              + flags + counter + hashlib.sha256(message).digest())
    sig = key.sign(signed) + flags + counter

    out = f"{head}:{base64.b64encode(sig).decode()}"
    if args.cert:
        with open(args.cert) as f:
            out += ":" + f.read().split()[1]
    print(out)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="sk_helper.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen")
    g.add_argument("dir")
    g.add_argument("--type", default="sk-ssh-ed25519@openssh.com")
    g.add_argument("--application", default="ssh:")
    g.add_argument("--comment", default="sk")
    g.set_defaults(func=keygen)

    t = sub.add_parser("token")
    t.add_argument("dir")
    t.add_argument("--flags", type=lambda v: int(v, 0), default=0x01)
    t.add_argument("--counter", type=lambda v: int(v, 0), default=7)
    t.add_argument("--at", type=int, default=None)
    t.add_argument("--nonce", default=None)
    t.add_argument("--application-override", default=None)
    t.add_argument("--cert", default=None)
    t.set_defaults(func=token)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
