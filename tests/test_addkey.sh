#!/usr/bin/env bash
# test_addkey.sh, pg_sshkey_addkey as an administrator runs it.
#
# The tool had no test of its own until an end-to-end run found it refusing
# security keys, and a review then found it reporting the wrong key count and
# rejecting the stdin form its own usage text advertises.
#
# It insists on root, so the checks re-exec under fakeroot with the keys
# directory in a temporary tree.  Without fakeroot they skip rather than
# fail: nothing here needs real privilege.
#
# SPDX-License-Identifier: MIT
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ADDKEY=${PAM_PG_SSHKEY_BUILDDIR:-$ROOT}/pg_sshkey_addkey
[[ -x "$ADDKEY" ]] || ADDKEY=$ROOT/src/pg_sshkey_addkey

if [[ "$EUID" -ne 0 ]]; then
    if command -v fakeroot >/dev/null 2>&1; then
        exec fakeroot "$0" "$@"
    fi
    echo "=== pg_sshkey_addkey ==="
    echo "  skip  fakeroot is not installed (the tool requires root)"
    exit 0
fi

PASS=0
FAIL=0
pass() { echo "  ok    $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL  $1"; [[ -n "${2:-}" ]] && sed 's/^/          /' <<<"$2"; FAIL=$((FAIL+1)); }
check() { # <name> <command...>
    local name=$1; shift
    local out; out=$("$@" 2>&1)
    if [[ $? -eq 0 ]]; then pass "$name"; else fail "$name" "$out"; fi
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

KEYS=$WORK/keys
run() { "$ADDKEY" -d "$KEYS" "$@"; }

ssh-keygen -q -t ed25519 -N '' -C plain -f "$WORK/plain" </dev/null
python3 "$ROOT/tests/sk_helper.py" keygen "$WORK" >/dev/null

echo "=== pg_sshkey_addkey ==="

# ── a security key registers, and the count says so ─────────────────────────
out=$(run alice "$WORK/sk.pub" 2>&1)
if grep -q '^sk-ssh-ed25519@openssh.com ' "$KEYS/alice/authorized_keys" 2>/dev/null; then
    pass "a security key is written to authorized_keys"
else
    fail "a security key is written to authorized_keys" "$out"
fi
if grep -q "now has 1 authorized key" <<<"$out"; then
    pass "the key count counts a security key"
else
    fail "the key count counts a security key" "$out"
fi

# ── appending keeps both, and the count follows ─────────────────────────────
out=$(run -a alice "$WORK/plain.pub" 2>&1)
if [[ "$(grep -c . "$KEYS/alice/authorized_keys")" == "2" ]] && \
   grep -q "now has 2 authorized key" <<<"$out"; then
    pass "appending a second key updates the count"
else
    fail "appending a second key updates the count" "$out"
fi

# ── --list names both types ─────────────────────────────────────────────────
out=$(run --list alice 2>&1)
if grep -q "ED25519-SK" <<<"$out" && grep -q "plain" <<<"$out"; then
    pass "--list shows a security key and a plain key"
else
    fail "--list shows a security key and a plain key" "$out"
fi

# ── a literal key string, the form the usage text advertises ────────────────
out=$(run bob "$(cat "$WORK/sk.pub")" 2>&1)
if grep -q '^sk-' "$KEYS/bob/authorized_keys" 2>/dev/null; then
    pass "a literal security key string is accepted"
else
    fail "a literal security key string is accepted" "$out"
fi

# ── stdin, also advertised ──────────────────────────────────────────────────
out=$(run carol - < "$WORK/plain.pub" 2>&1)
if grep -q '^ssh-ed25519 ' "$KEYS/carol/authorized_keys" 2>/dev/null; then
    pass "a key on stdin is accepted"
else
    fail "a key on stdin is accepted" "$out"
fi

# ── the unsupported security key type is refused, by name ───────────────────
python3 "$ROOT/tests/sk_helper.py" keygen "$WORK" \
    --type sk-ecdsa-sha2-nistp256@openssh.com >/dev/null
out=$(run dave "$WORK/sk.pub" 2>&1)
if [[ ! -e "$KEYS/dave/authorized_keys" ]] && grep -q "sk-ecdsa" <<<"$out"; then
    pass "sk-ecdsa is refused and nothing is written"
else
    fail "sk-ecdsa is refused and nothing is written" "$out"
fi

# ── --remove ────────────────────────────────────────────────────────────────
out=$(run --remove alice 2>&1)
if [[ ! -e "$KEYS/alice/authorized_keys" ]]; then
    pass "--remove deletes the file"
else
    fail "--remove deletes the file" "$out"
fi

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
