#!/usr/bin/env bash
# lib.sh, shared helpers for the in-container e2e checks.
# SPDX-License-Identifier: MIT

# Server log location differs per packaging
if [[ -z "${PGLOG:-}" ]]; then
    . /etc/os-release
    case "$ID" in
      ubuntu|debian) PGLOG=/var/log/postgresql/postgresql-18-main.log ;;
      *)             PGLOG=/var/lib/pgsql/data/log/postgresql-$(date +%a).log ;;
    esac
fi
CHAL_DIR=/var/run/pg_sshkey
SRC=/opt/pam_pg_sshkey

E2E_PASS=0
E2E_FAIL=0

pass() { echo "PASS $1"; E2E_PASS=$((E2E_PASS+1)); }
fail() { echo "FAIL $1"; sed 's/^/      /' <<<"$2"; E2E_FAIL=$((E2E_FAIL+1)); }

# run_check <name>: runs check_<name>; it must print a reason on failure.
run_check() {
    local name=$1 out rc
    if [[ -n "${E2E_ONLY:-}" && "$E2E_ONLY" != "$name" ]]; then return 0; fi
    out=$("check_$name" 2>&1); rc=$?
    if [[ $rc -eq 0 ]]; then pass "$name"; else fail "$name" "$out"; fi
}

summary() {
    echo
    echo "$E2E_PASS passed, $E2E_FAIL failed"
    [[ $E2E_FAIL -eq 0 ]]
}

# ── running commands as a test user ──────────────────────────────────────────
# Login shell so $USER/$HOME are the user's (pg_sshkey_connect reads both).
as_user() { local u=$1; shift; runuser -l "$u" -c "$*"; }
as_alice() { as_user alice "$@"; }
as_bob()   { as_user bob   "$@"; }

# ── journald (pam_syslog output) ─────────────────────────────────────────────
journal_mark()  { journalctl --show-cursor -n0 -q 2>/dev/null | sed -n 's/^-- cursor: *//p'; }
journal_since() { journalctl --sync 2>/dev/null || true; journalctl --after-cursor="$1" --no-pager -o cat 2>/dev/null; }
expect_journal() {   # <cursor> <substring>
    local tries=0
    until journal_since "$1" | grep -Fq -- "$2"; do
        tries=$((tries+1)); [[ $tries -ge 10 ]] && break; sleep 0.3
    done
    if ! journal_since "$1" | grep -Fq -- "$2"; then
        echo "journal lacks: $2"
        echo "journal (pam_pg_sshkey lines since mark):"
        journal_since "$1" | grep -F pam_pg_sshkey | tail -5 | sed 's/^/  /'
        return 1
    fi
}

# ── PostgreSQL server log ────────────────────────────────────────────────────
pglog_mark()  { stat -c %s "$PGLOG"; }
pglog_since() { tail -c +"$(( $1 + 1 ))" "$PGLOG"; }
expect_pglog() {     # <offset> <substring>
    local tries=0
    until pglog_since "$1" | grep -Fq -- "$2"; do
        tries=$((tries+1)); [[ $tries -ge 10 ]] && break; sleep 0.3
    done
    pglog_since "$1" | grep -Fq -- "$2" || { echo "pg log lacks: $2"; pglog_since "$1" | tail -5 | sed 's/^/  /'; return 1; }
}
expect_no_pglog() {  # <offset> <substring>
    if pglog_since "$1" | grep -Fq -- "$2"; then echo "pg log unexpectedly contains: $2"; return 1; fi
}
