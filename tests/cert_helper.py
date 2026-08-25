#!/usr/bin/env python3
"""
cert_helper.py, mint an OpenSSH certificate ssh-keygen would not write.

ssh-keygen validates what it signs, so it cannot produce a certificate
carrying a malformed source-address list, a critical option with trailing
bytes, or an option name it does not know.  A certificate authority is only
software, though, and a compromised or buggy one can sign anything.  This
script signs such certificates with a real CA key so the module can be
tested against them.

It is a test helper, not part of the installed tools.

Usage:
  cert_helper.py <ca_key> <user_pubkey> <out-cert.pub>
      [--key-id ID] [--principal NAME] [--serial N]
      [--valid-after SECS] [--valid-before SECS]   (offsets from now)
      [--critical NAME=VALUE]        repeatable, VALUE is wrapped as a string
      [--critical-raw NAME=HEX]      repeatable, HEX is the whole data field
                                     verbatim, framing included

Only Ed25519 CA keys and Ed25519 user keys are handled; that is what the
tests use.

SPDX-License-Identifier: MIT
"""

import argparse
import base64
import os
import struct
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CERT_TYPE = b"ssh-ed25519-cert-v01@openssh.com"
SSH_CERT_TYPE_USER = 1

_RAW_PRIV = dict(encoding=serialization.Encoding.Raw,
                 format=serialization.PrivateFormat.Raw,
                 encryption_algorithm=serialization.NoEncryption())
_RAW_PUB = dict(encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw)


def sshstr(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def read_openssh_private(path: str) -> Ed25519PrivateKey:
    key = serialization.load_ssh_private_key(open(path, "rb").read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit("cert_helper.py: only Ed25519 CA keys are handled")
    return key


def public_blob(pub_line: str) -> bytes:
    fields = pub_line.split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        sys.exit("cert_helper.py: only ssh-ed25519 user keys are handled")
    return base64.b64decode(fields[1])


def main() -> int:
    p = argparse.ArgumentParser(prog="cert_helper.py")
    p.add_argument("ca_key")
    p.add_argument("user_pubkey")
    p.add_argument("out")
    p.add_argument("--key-id", default="test-key")
    p.add_argument("--principal", action="append", default=None)
    p.add_argument("--serial", type=int, default=0)
    p.add_argument("--valid-after", type=int, default=-60)
    p.add_argument("--valid-before", type=int, default=300)
    p.add_argument("--critical", action="append", default=[])
    p.add_argument("--critical-raw", action="append", default=[])
    args = p.parse_args()

    ca = read_openssh_private(args.ca_key)
    ca_pub = ca.public_key().public_bytes(**_RAW_PUB)
    ca_blob = sshstr(b"ssh-ed25519") + sshstr(ca_pub)

    user_blob = public_blob(open(args.user_pubkey).read())
    # user_blob is "string ssh-ed25519 | string pk"; the certificate carries
    # the key material without the type, still framed as a string
    pk = user_blob[4 + 11:]

    principals = args.principal if args.principal else ["alice"]
    now = int(time.time())

    # An option entry is "string name | string data", and for the options
    # that carry a value the data field itself holds a string, so the value
    # is framed twice.
    options = []
    for spec in args.critical:
        name, _, value = spec.partition("=")
        options.append((name.encode(), sshstr(sshstr(value.encode()))))
    for spec in args.critical_raw:
        name, _, value = spec.partition("=")
        options.append((name.encode(), bytes.fromhex(value)))
    options.sort(key=lambda o: o[0])          # OpenSSH requires lexical order
    packed_options = b"".join(sshstr(n) + d for n, d in options)

    body = (sshstr(CERT_TYPE)
            + sshstr(os.urandom(32))          # nonce
            + pk                              # string pk, already framed
            + struct.pack(">Q", args.serial)
            + struct.pack(">I", SSH_CERT_TYPE_USER)
            + sshstr(args.key_id.encode())
            + sshstr(b"".join(sshstr(x.encode()) for x in principals))
            + struct.pack(">Q", now + args.valid_after)
            + struct.pack(">Q", now + args.valid_before)
            + sshstr(packed_options)
            + sshstr(b"")                     # extensions
            + sshstr(b"")                     # reserved
            + sshstr(ca_blob))

    signature = ca.sign(body)
    blob = body + sshstr(sshstr(b"ssh-ed25519") + sshstr(signature))

    with open(args.out, "w") as f:
        f.write(f"{CERT_TYPE.decode()} {base64.b64encode(blob).decode()} {args.key_id}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
