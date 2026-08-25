#!/usr/bin/env bash
# check.sh, the end-to-end assertions.  Runs INSIDE the e2e container as
# root after provision.sh.  Each check is one vertical slice.
#
# Env:  E2E_ONLY=<name>   run a single check
#
# SPDX-License-Identifier: MIT
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

restore_chal_dir() { chown postgres:postgres "$CHAL_DIR"; chmod 1733 "$CHAL_DIR"; }
# A revocation list left behind by an interrupted check would lock users out
# of every check after it, so it is emptied on the way out as well.
restore_state() {
    restore_chal_dir
    : > /etc/pg_sshkeys/revoked_keys 2>/dev/null || true
}
trap restore_state EXIT

PSQL_TCP="psql -h 127.0.0.1 -U alice -d alice -tA"
PSQL_TCP_CAROL="psql -h 127.0.0.1 -U carol -d carol -tA"
CAROL_CERT=/home/carol/.ssh/id_ed25519-cert.pub

# ── 2.1 ──────────────────────────────────────────────────────────────────────
check_tcp_connect_as_alice() {
    local cur off; cur=$(journal_mark); off=$(pglog_mark)
    local out; out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
    # it must have been OUR module that let her in, not another hba method
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key" || return 1
    expect_no_pglog "$off" 'PAM authentication failed'
}
# ── 2.2 ──────────────────────────────────────────────────────────────────────
check_local_socket_connect_as_alice() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "pg_sshkey_connect -- -tAc 'select current_user'" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
    # Ubuntu's default `local all all peer` would also admit alice: prove PAM did it
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key"
}
# ── 2.3 ──────────────────────────────────────────────────────────────────────
check_pg_sshkey_query() {
    local out; out=$(as_alice "pg_sshkey_query -h 127.0.0.1 -q 'select current_user'" 2>&1) || { echo "$out"; return 1; }
    grep -q alice <<<"$out" || { echo "got: $out"; return 1; }
}
# ── 2.4 ──────────────────────────────────────────────────────────────────────
check_python_module_connect() {
    local out; out=$(as_alice "PYTHONPATH=$SRC/src python3 -c \"
from pam_pg_sshkey import connect
c = connect(user='alice', dbname='alice', host='127.0.0.1')
cur = c.cursor(); cur.execute('select current_user'); print(cur.fetchone()[0])\"" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
}
# ── 2.5 ──────────────────────────────────────────────────────────────────────
check_wrong_key_rejected() {
    local cur off; cur=$(journal_mark); off=$(pglog_mark)
    if as_alice "pg_sshkey_connect -h 127.0.0.1 -i ~/.ssh/id_wrong -- -tAc 'select 1'" >/dev/null 2>&1; then
        echo "connected with an unregistered key"; return 1
    fi
    expect_journal "$cur" "pam_pg_sshkey: authentication failed for 'alice'" || return 1
    expect_pglog  "$off" 'PAM authentication failed for user "alice"'
}
# ── 2.6 + 2.7 ────────────────────────────────────────────────────────────────
check_replayed_token_rejected() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "
        chal=\$(pg_sshkey_challenge $CHAL_DIR) || exit 9
        tok=\$(pg_sshkey_sign \"\$chal\" ~/.ssh/id_ed25519) || exit 9
        echo \"chal=\$chal\"
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' 2>&1 && echo first=ok || echo first=fail
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo second=ok || echo second=fail
    " 2>&1)
    grep -q '^first=ok'    <<<"$out" || { echo "first use did not succeed:"; echo "$out"; return 1; }
    grep -q '^second=fail' <<<"$out" || { echo "REPLAY SUCCEEDED:"; echo "$out"; return 1; }
    expect_journal "$cur" "challenge not found or expired for 'alice'" || return 1
    local chal; chal=$(sed -n 's/^chal=//p' <<<"$out")
    [[ -n "$chal" && ! -e "$CHAL_DIR/$chal" ]] || { echo "nonce $chal still present after successful auth"; return 1; }
}
check_nonce_deleted_after_auth() {
    local out; out=$(as_alice "
        chal=\$(pg_sshkey_challenge $CHAL_DIR) || exit 9
        tok=\$(pg_sshkey_sign \"\$chal\" ~/.ssh/id_ed25519) || exit 9
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' >/dev/null 2>&1 || exit 8
        echo \"\$chal\"
    " 2>&1) || { echo "auth failed: $out"; return 1; }
    [[ ! -e "$CHAL_DIR/$out" ]] || { echo "nonce $out still present"; return 1; }
}
# ── 2.8 ──────────────────────────────────────────────────────────────────────
check_bob_without_keys_rejected() {
    local cur; cur=$(journal_mark)
    if as_bob "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select 1'" >/dev/null 2>&1; then
        echo "bob connected with no authorized_keys"; return 1
    fi
    expect_journal "$cur" "pam_pg_sshkey: no authorized_keys for 'bob'"
}
# ── 2.9 ──────────────────────────────────────────────────────────────────────
check_malformed_token_rejected() {
    local cur; cur=$(journal_mark)
    if as_alice "PGPASSWORD=garbage $PSQL_TCP -c 'select 1'" >/dev/null 2>&1; then
        echo "garbage password accepted"; return 1
    fi
    expect_journal "$cur" "pam_pg_sshkey: malformed token for 'alice'"
}
# ── 2.10 ─────────────────────────────────────────────────────────────────────
check_root_owned_chal_dir_fails_closed() {
    local cur rc=0; cur=$(journal_mark)
    chown root:root "$CHAL_DIR"; chmod 1733 "$CHAL_DIR"
    local out; out=$(as_alice "
        chal=\$(pg_sshkey_challenge $CHAL_DIR) || exit 9
        tok=\$(pg_sshkey_sign \"\$chal\" ~/.ssh/id_ed25519) || exit 9
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo first=ok || echo first=fail
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo second=ok || echo second=fail
        echo \"chal=\$chal\"
    " 2>&1)
    restore_chal_dir
    local chal; chal=$(sed -n 's/^chal=//p' <<<"$out"); rm -f "$CHAL_DIR/$chal"
    grep -q '^first=fail'  <<<"$out" || { echo "auth succeeded although the nonce could not be consumed:"; echo "$out"; rc=1; }
    grep -q '^second=fail' <<<"$out" || { echo "REPLAY SUCCEEDED:"; echo "$out"; rc=1; }
    expect_journal "$cur" "could not delete challenge" || rc=1
    return $rc
}
# ── 2.11 ─────────────────────────────────────────────────────────────────────
check_umask_077_client_still_authenticates() {
    local out
    out=$(as_alice "umask 077; pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) \
        || { echo "C tools: $out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "C tools got: $out"; return 1; }
    out=$(as_alice "PYTHONPATH=$SRC/src python3 -c \"
import os; os.umask(0o077)
from pam_pg_sshkey import connect
c = connect(user='alice', dbname='alice', host='127.0.0.1')
cur = c.cursor(); cur.execute('select current_user'); print(cur.fetchone()[0])\"" 2>&1) \
        || { echo "python: $out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "python got: $out"; return 1; }
}
# ── 2.12 ─────────────────────────────────────────────────────────────────────
check_rsa_key_connect() {
    pg_sshkey_addkey alice /home/alice/.ssh/id_ed25519.pub >/dev/null || { echo "addkey failed"; return 1; }
    pg_sshkey_addkey -a alice /home/alice/.ssh/id_rsa_pem.pub >/dev/null || { echo "addkey -a failed"; return 1; }
    local out; out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -i ~/.ssh/id_rsa_pem -- -tAc 'select current_user'" 2>&1) \
        || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
}

# ── v1 still accepted: explicit legacy flow via the server nonce file ───────
check_v1_token_still_accepted() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "pg_sshkey_connect --v1 -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key"
}
# ── v2: replay of a self-issued token is rejected ───────────────────────────
check_v2_replay_rejected() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "
        tok=\$(pg_sshkey_sign ~/.ssh/id_ed25519) || exit 9
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo first=ok || echo first=fail
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo second=ok || echo second=fail
        echo \"nonce=\$(cut -d: -f2 <<<\"\$tok\")\"
    " 2>&1)
    grep -q '^first=ok'    <<<"$out" || { echo "first use did not succeed:"; echo "$out"; return 1; }
    grep -q '^second=fail' <<<"$out" || { echo "REPLAY SUCCEEDED:"; echo "$out"; return 1; }
    expect_journal "$cur" "replayed token for 'alice'" || return 1
    local nonce; nonce=$(sed -n 's/^nonce=//p' <<<"$out")
    [[ -f "$CHAL_DIR/$nonce" ]] || { echo "nonce marker $nonce not recorded"; return 1; }
    local owner; owner=$(stat -c %U:%a "$CHAL_DIR/$nonce")
    [[ "$owner" == "postgres:600" ]] || { echo "marker is $owner, expected postgres:600"; return 1; }
}
# ── v2: works with a private 0700 directory (no world-writable dir needed) ──
check_v2_private_0700_dir() {
    chmod 0700 "$CHAL_DIR"
    local rc=0 out
    # v1 clients cannot even create their nonce any more ...
    if as_alice "pg_sshkey_challenge $CHAL_DIR" >/dev/null 2>&1; then echo "v1 nonce creation succeeded in a 0700 dir?!"; rc=1; fi
    # ... but v2 logs in, and replays are still caught
    out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "v2 connect: $out"; rc=1; }
    [[ "$out" == "alice" ]] || { echo "v2 got: $out"; rc=1; }
    out=$(as_alice "PYTHONPATH=$SRC/src python3 -c \"
from pam_pg_sshkey import connect
c = connect(user='alice', dbname='alice', host='127.0.0.1')
cur = c.cursor(); cur.execute('select current_user'); print(cur.fetchone()[0])\"" 2>&1) || { echo "python: $out"; rc=1; }
    [[ "$out" == "alice" ]] || { echo "python got: $out"; rc=1; }
    restore_chal_dir
    return $rc
}
# ── v2: expired / future tokens rejected by the server clock ────────────────
check_v2_timestamp_window() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "
        old=\$(pg_sshkey_sign --at \$(( \$(date +%s) - 120 )) ~/.ssh/id_ed25519)
        fut=\$(pg_sshkey_sign --at \$(( \$(date +%s) + 300 )) ~/.ssh/id_ed25519)
        PGPASSWORD=\$old $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo old=ok || echo old=fail
        PGPASSWORD=\$fut $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo fut=ok || echo fut=fail
    " 2>&1)
    grep -q '^old=fail' <<<"$out" || { echo "EXPIRED TOKEN ACCEPTED: $out"; return 1; }
    grep -q '^fut=fail' <<<"$out" || { echo "FUTURE TOKEN ACCEPTED: $out"; return 1; }
    expect_journal "$cur" "expired or clock skew"
}
# ── v2: unwritable marker dir fails closed ─────────────────────────────────
check_v2_unrecordable_nonce_fails_closed() {
    local cur; cur=$(journal_mark)
    chown root:root "$CHAL_DIR"; chmod 0500 "$CHAL_DIR"
    local out; out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select 1'" 2>&1) && { restore_chal_dir; echo "AUTH SUCCEEDED with an unrecordable nonce"; return 1; }
    restore_chal_dir
    expect_journal "$cur" "could not record nonce"
}

# ── sweeper: stale nonces from anyone vanish on the next authentication ─────
check_stale_nonces_swept() {
    local stale1=$CHAL_DIR/4444444444444444444444444444444444444444444444444444444444444444
    local stale2=$CHAL_DIR/5555555555555555555555555555555555555555555555555555555555555555
    local live=$CHAL_DIR/6666666666666666666666666666666666666666666666666666666666666666
    for f in $stale1 $stale2; do printf '%s\n%s\n' "$(( $(date +%s) - 3600 ))" "$(basename $f)" > "$f"; chown bob "$f"; touch -d '1 hour ago' "$f"; done
    printf '%s\n%s\n' "$(date +%s)" "$(basename $live)" > "$live"; chown bob "$live"
    local out; out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select 1'" 2>&1) || { echo "$out"; rm -f $live; return 1; }
    local rc=0
    [[ ! -e $stale1 && ! -e $stale2 ]] || { echo "stale nonces survived an authentication"; rc=1; }
    [[ -e $live ]] || { echo "a live nonce belonging to another user was removed"; rc=1; }
    rm -f $stale1 $stale2 $live
    return $rc
}
# ── python replication connections (logical + physical) ─────────────────────
check_python_replication_connect() {
    local out; out=$(as_alice "PYTHONPATH=$SRC/src python3 -c \"
from pam_pg_sshkey import connect_replication
c = connect_replication(user='alice', dbname='alice', host='127.0.0.1')            # logical
cur = c.cursor(); cur.execute('IDENTIFY_SYSTEM'); print('logical', cur.fetchone()[0] != '')
c = connect_replication(user='alice', host='127.0.0.1', replication='yes')         # physical, libpq spelling
cur = c.cursor(); cur.execute('IDENTIFY_SYSTEM'); print('physical', cur.fetchone()[0] != '')\"" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == $'logical True\nphysical True' ]] || { echo "got: $out"; return 1; }
}
# ── pg_sshkey_query: bad SQL is a clean error ───────────────────────────────
check_pg_sshkey_query_bad_sql_clean_error() {
    local out; out=$(as_alice "pg_sshkey_query -h 127.0.0.1 -q 'SELEC 1'" 2>&1) && { echo "bad SQL exited 0"; return 1; }
    grep -q '^error: Query failed' <<<"$out" || { echo "no clean error line: $out"; return 1; }
    ! grep -q Traceback <<<"$out" || { echo "traceback leaked: $out"; return 1; }
}
# ── remote-client flow: nonce minted on the server over ssh ─────────────────
SSH_CHAL="ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o LogLevel=ERROR alice@127.0.0.1 pg_sshkey_challenge $CHAL_DIR"
check_ssh_challenge_cmd_connect() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "pg_sshkey_connect --v1 --challenge-cmd '$SSH_CHAL' -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "shell: $out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "shell got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key" || return 1
    out=$(as_alice "PYTHONPATH=$SRC/src python3 -c \"
from pam_pg_sshkey import connect
c = connect(user='alice', dbname='alice', host='127.0.0.1', challenge_cmd='$SSH_CHAL')
cur = c.cursor(); cur.execute('select current_user'); print(cur.fetchone()[0])\"" 2>&1) || { echo "python: $out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "python got: $out"; return 1; }
}

# ── certificates (v3): carol has NO authorized_keys, only a CA-signed key ───
check_cert_connect_as_carol() {
    [[ ! -e /etc/pg_sshkeys/carol/authorized_keys ]] || { echo "carol has an authorized_keys file; the check would not prove the certificate path"; return 1; }
    local cur off; cur=$(journal_mark); off=$(pglog_mark)
    local out; out=$(as_carol "pg_sshkey_connect --cert $CAROL_CERT -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "carol" ]] || { echo "got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'carol' authenticated with certificate 'carol-key'" || return 1
    expect_no_pglog "$off" 'PAM authentication failed'
}
check_cert_python_connect() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_carol "PYTHONPATH=$SRC/src python3 -c \"
from pam_pg_sshkey import connect
c = connect(user='carol', dbname='carol', host='127.0.0.1', cert_path='$CAROL_CERT')
cur = c.cursor(); cur.execute('select current_user'); print(cur.fetchone()[0])\"" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "carol" ]] || { echo "got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'carol' authenticated with certificate"
}
check_cert_pg_sshkey_query() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_carol "pg_sshkey_query --cert $CAROL_CERT -h 127.0.0.1 -q 'select current_user'" 2>&1) || { echo "$out"; return 1; }
    grep -q carol <<<"$out" || { echo "got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'carol' authenticated with certificate"
}
check_cert_untrusted_ca_rejected() {
    local cur; cur=$(journal_mark)
    if as_carol "pg_sshkey_connect --cert ~/.ssh/id_ed25519_untrusted-cert.pub -h 127.0.0.1 -- -tAc 'select 1'" >/dev/null 2>&1; then
        echo "connected with a certificate from an untrusted CA"; return 1
    fi
    expect_journal "$cur" "pam_pg_sshkey: certificate for 'carol' rejected: not signed by a trusted CA"
}
check_cert_expired_rejected() {
    local cur; cur=$(journal_mark)
    if as_carol "pg_sshkey_connect --cert ~/.ssh/id_ed25519_expired-cert.pub -h 127.0.0.1 -- -tAc 'select 1'" >/dev/null 2>&1; then
        echo "connected with an expired certificate"; return 1
    fi
    expect_journal "$cur" "pam_pg_sshkey: certificate for 'carol' rejected: expired"
}
check_cert_wrong_principal_rejected() {
    local cur; cur=$(journal_mark)
    if as_carol "pg_sshkey_connect --cert ~/.ssh/id_ed25519_bob-cert.pub -h 127.0.0.1 -- -tAc 'select 1'" >/dev/null 2>&1; then
        echo "connected with a certificate whose only principal is bob"; return 1
    fi
    expect_journal "$cur" "pam_pg_sshkey: certificate for 'carol' rejected: principal 'carol' not listed"
}
check_cert_replay_rejected() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_carol "
        tok=\$(pg_sshkey_sign --cert $CAROL_CERT ~/.ssh/id_ed25519) || exit 9
        PGPASSWORD=\$tok $PSQL_TCP_CAROL -c 'select 1' >/dev/null 2>&1 && echo first=ok || echo first=fail
        PGPASSWORD=\$tok $PSQL_TCP_CAROL -c 'select 1' >/dev/null 2>&1 && echo second=ok || echo second=fail
        echo \"nonce=\$(cut -d: -f2 <<<\"\$tok\")\"
    " 2>&1)
    grep -q '^first=ok'    <<<"$out" || { echo "first use did not succeed:"; echo "$out"; return 1; }
    grep -q '^second=fail' <<<"$out" || { echo "REPLAY SUCCEEDED:"; echo "$out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: replayed token for 'carol' (nonce already used)" || return 1
    local nonce; nonce=$(sed -n 's/^nonce=//p' <<<"$out")
    [[ -f "$CHAL_DIR/$nonce" ]] || { echo "nonce marker $nonce not recorded"; return 1; }
}
check_cert_alice_key_without_cert_still_works() {
    grep -q 'trusted_ca_keys=/etc/pg_sshkeys/trusted_ca_keys' /etc/pam.d/postgresql \
        || { echo "trusted_ca_keys is not set in /etc/pam.d/postgresql; the check would not prove coexistence"; return 1; }
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "v2: $out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "v2 got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key" || return 1
    cur=$(journal_mark)
    out=$(as_alice "pg_sshkey_connect --v1 -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "v1: $out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "v1 got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key"
}

# ── ssh-agent signing ───────────────────────────────────────────────────────
# Run <cmd> as alice with a private ssh-agent holding <key>.  The agent is
# killed on the way out, so each check starts from nothing.
as_alice_with_agent() {   # <keyname> <ask|-> <command...>
    local key=$1 ask=$2; shift 2
    local addcmd="ssh-add ~/.ssh/$key </dev/null >/dev/null 2>&1"
    [[ "$ask" == "ask" ]] && addcmd="SSH_ASKPASS=/usr/local/bin/e2e-askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 $addcmd"
    as_alice "
        eval \$(ssh-agent -s) >/dev/null
        trap 'ssh-agent -k >/dev/null 2>&1' EXIT
        timeout 20 sh -c '$addcmd' || exit 9
        $*
    "
}
# An earlier check rewrites alice's authorized_keys, so every check that
# needs id_agent registers it first.  Appending twice is harmless, so this
# only adds when the key is absent.
ensure_agent_key_registered() {
    grep -qf /home/alice/.ssh/id_agent.pub /etc/pg_sshkeys/alice/authorized_keys 2>/dev/null \
        || pg_sshkey_addkey -a alice /home/alice/.ssh/id_agent.pub >/dev/null
}
check_agent_connect_as_alice() {
    ensure_agent_key_registered || { echo "addkey failed"; return 1; }
    local cur off; cur=$(journal_mark); off=$(pglog_mark)
    # id_agent, not the default identity: a client that ignored --agent would
    # sign with ~/.ssh/id_ed25519 and the journal would name that key instead
    local out; out=$(as_alice_with_agent id_agent - \
        "pg_sshkey_connect --agent ~/.ssh/id_agent.pub -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) \
        || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key id_agent" || return 1
    expect_no_pglog "$off" 'PAM authentication failed'
}
check_agent_passphrase_key_connects() {
    # register the key here: an earlier check rewrites alice's authorized_keys
    pg_sshkey_addkey -a alice /home/alice/.ssh/id_locked.pub >/dev/null || { echo "addkey failed"; return 1; }
    # id_locked has a passphrase: without an agent there is no way in
    local out; out=$(as_alice "pg_sshkey_connect -i ~/.ssh/id_locked -h 127.0.0.1 -- -tAc 'select 1'" 2>&1) \
        && { echo "an encrypted key file authenticated without an agent"; return 1; }
    local cur; cur=$(journal_mark)
    out=$(as_alice_with_agent id_locked ask \
        "pg_sshkey_connect --agent ~/.ssh/id_locked.pub -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) \
        || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
    # name the key: signing with the default id_ed25519 would also say "alice"
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key id_locked"
}
check_agent_rsa_key_connects() {
    # proves the client asks the agent for rsa-sha2-256, not SHA-1
    pg_sshkey_addkey -a alice /home/alice/.ssh/id_rsa_pem.pub >/dev/null || { echo "addkey failed"; return 1; }
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice_with_agent id_rsa_pem - \
        "pg_sshkey_connect --agent ~/.ssh/id_rsa_pem.pub -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) \
        || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key id_rsa_pem"
}
check_agent_certificate_connects() {
    [[ ! -e /etc/pg_sshkeys/carol/authorized_keys ]] || { echo "carol has an authorized_keys file"; return 1; }
    local cur; cur=$(journal_mark)
    # id_agent with its own certificate: the default identity is not certified
    # by it, so ignoring --agent fails the login instead of passing silently
    local out; out=$(as_user carol "
        eval \$(ssh-agent -s) >/dev/null
        trap 'ssh-agent -k >/dev/null 2>&1' EXIT
        timeout 20 ssh-add ~/.ssh/id_agent </dev/null >/dev/null 2>&1 || exit 9
        pg_sshkey_connect --agent ~/.ssh/id_agent.pub --cert ~/.ssh/id_agent-cert.pub -h 127.0.0.1 -- -tAc 'select current_user'
    " 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "carol" ]] || { echo "got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'carol' authenticated with certificate 'carol-agent'"
}
check_agent_query_and_python_connect() {
    ensure_agent_key_registered || { echo "addkey failed"; return 1; }
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice_with_agent id_agent - \
        "pg_sshkey_query --agent ~/.ssh/id_agent.pub -h 127.0.0.1 -q 'select current_user'" 2>&1) \
        || { echo "query: $out"; return 1; }
    grep -q alice <<<"$out" || { echo "query got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key id_agent" || return 1
    cur=$(journal_mark)
    out=$(as_alice_with_agent id_agent - \
        "PYTHONPATH=$SRC/src python3 -c \"
from pam_pg_sshkey import connect
c = connect(user='alice', dbname='alice', host='127.0.0.1',
            agent_pubkey='/home/alice/.ssh/id_agent.pub')
cur = c.cursor(); cur.execute('select current_user'); print(cur.fetchone()[0])\"" 2>&1) \
        || { echo "python: $out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "python got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key id_agent"
}
check_agent_absent_is_a_clean_error() {
    local out; out=$(as_alice "unset SSH_AUTH_SOCK; pg_sshkey_connect --agent ~/.ssh/id_agent.pub -h 127.0.0.1 -- -tAc 'select 1'" 2>&1) \
        && { echo "connected with no agent running"; return 1; }
    grep -q "SSH_AUTH_SOCK is not set" <<<"$out" || { echo "unclear error: $out"; return 1; }
}

# ── source-address ──────────────────────────────────────────────────────────
# PostgreSQL reports the client address in PAM_RHOST, so these checks pass
# only if the module reads the real thing: the harness cannot fake it here.
check_cert_source_address_permitted() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_carol "pg_sshkey_connect --cert ~/.ssh/id_ed25519_here-cert.pub -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) \
        || { echo "$out"; return 1; }
    [[ "$out" == "carol" ]] || { echo "got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'carol' authenticated with certificate 'carol-here'"
}
check_cert_source_address_refused() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_carol "pg_sshkey_connect --cert ~/.ssh/id_ed25519_there-cert.pub -h 127.0.0.1 -- -tAc 'select 1'" 2>&1) \
        && { echo "a certificate pinned to another network authenticated"; return 1; }
    expect_journal "$cur" "client address 127.0.0.1 is not permitted by source-address 10.0.0.0/8"
}
check_cert_source_address_local_socket_refused() {
    # On the unix socket PostgreSQL sets no PAM_RHOST at all, so the module
    # cannot know where the client is and refuses the pinned certificate.
    local cur; cur=$(journal_mark)
    local out; out=$(as_carol "pg_sshkey_connect --cert ~/.ssh/id_ed25519_here-cert.pub -- -tAc 'select 1'" 2>&1) \
        && { echo "a pinned certificate authenticated over the local socket"; return 1; }
    expect_journal "$cur" "the client address is not known" || return 1
    # an unpinned certificate over the same socket is unaffected
    out=$(as_carol "pg_sshkey_connect --cert $CAROL_CERT -- -tAc 'select current_user'" 2>&1) \
        || { echo "unpinned: $out"; return 1; }
    [[ "$out" == "carol" ]] || { echo "unpinned got: $out"; return 1; }
}

# ── revocation ──────────────────────────────────────────────────────────────
REVOKED=/etc/pg_sshkeys/revoked_keys
clear_revocations() { : > "$REVOKED"; chown root:postgres "$REVOKED"; chmod 640 "$REVOKED"; }
check_revoked_key_rejected() {
    ensure_agent_key_registered || { echo "addkey failed"; return 1; }
    # it works before the key is revoked
    local out; out=$(as_alice_with_agent id_agent - \
        "pg_sshkey_connect --agent ~/.ssh/id_agent.pub -h 127.0.0.1 -- -tAc 'select 1'" 2>&1) \
        || { echo "before: $out"; return 1; }
    local cur; cur=$(journal_mark)
    cat /home/alice/.ssh/id_agent.pub > "$REVOKED"; chmod 640 "$REVOKED"
    out=$(as_alice_with_agent id_agent - \
        "pg_sshkey_connect --agent ~/.ssh/id_agent.pub -h 127.0.0.1 -- -tAc 'select 1'" 2>&1) \
        && { clear_revocations; echo "a revoked key authenticated"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: key for 'alice' is revoked" || { clear_revocations; return 1; }
    # and the other keys still work while it is revoked
    out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) \
        || { clear_revocations; echo "another key was locked out: $out"; return 1; }
    clear_revocations
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
}
check_revoked_certificate_rejected() {
    local cur; cur=$(journal_mark)
    cat /home/carol/.ssh/id_ed25519.pub > "$REVOKED"; chmod 640 "$REVOKED"
    local out; out=$(as_carol "pg_sshkey_connect --cert $CAROL_CERT -h 127.0.0.1 -- -tAc 'select 1'" 2>&1) \
        && { clear_revocations; echo "a revoked certified key authenticated"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: certificate for 'carol' rejected: key is revoked" || { clear_revocations; return 1; }
    clear_revocations
}
check_unreadable_revocation_list_fails_closed() {
    local cur; cur=$(journal_mark)
    mv "$REVOKED" "$REVOKED.away"
    local out; out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select 1'" 2>&1) \
        && { mv "$REVOKED.away" "$REVOKED"; echo "authenticated with an unreadable revocation list"; return 1; }
    mv "$REVOKED.away" "$REVOKED"
    expect_journal "$cur" "cannot read revoked_keys"
}

# ── security keys ───────────────────────────────────────────────────────────
SK_HELPER="python3 $SRC/tests/sk_helper.py"
ensure_sk_key_registered() {
    grep -qf /home/alice/.ssh/sk.pub /etc/pg_sshkeys/alice/authorized_keys 2>/dev/null \
        || pg_sshkey_addkey -a alice /home/alice/.ssh/sk.pub >/dev/null
}
check_security_key_connect() {
    ensure_sk_key_registered || { echo "addkey failed"; return 1; }
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "
        tok=\$($SK_HELPER token ~/.ssh) || exit 9
        PGPASSWORD=\$tok psql -h 127.0.0.1 -U alice -d alice -tAc 'select current_user'
    " 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key sk"
}
check_security_key_without_presence_rejected() {
    ensure_sk_key_registered || { echo "addkey failed"; return 1; }
    # the same key with the bit set logs in, so the refusal is the bit and
    # not a key the server never knew about
    local ok; ok=$(as_alice "
        tok=\$($SK_HELPER token ~/.ssh) || exit 9
        PGPASSWORD=\$tok psql -h 127.0.0.1 -U alice -d alice -tAc 'select current_user'
    " 2>&1) || { echo "the key does not work at all: $ok"; return 1; }
    [[ "$ok" == "alice" ]] || { echo "got: $ok"; return 1; }
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "
        tok=\$($SK_HELPER token ~/.ssh --flags 0) || exit 9
        PGPASSWORD=\$tok psql -h 127.0.0.1 -U alice -d alice -tAc 'select 1'
    " 2>&1) && { echo "a signature with no user presence authenticated"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: authentication failed for 'alice'"
}
check_security_key_counter_is_not_checked() {
    # documented: the module does not track the authenticator's counter, so
    # a lower counter than a previous login still authenticates
    ensure_sk_key_registered || { echo "addkey failed"; return 1; }
    local out; out=$(as_alice "
        hi=\$($SK_HELPER token ~/.ssh --counter 900) || exit 9
        PGPASSWORD=\$hi psql -h 127.0.0.1 -U alice -d alice -tAc 'select 1' >/dev/null || exit 8
        lo=\$($SK_HELPER token ~/.ssh --counter 1) || exit 9
        PGPASSWORD=\$lo psql -h 127.0.0.1 -U alice -d alice -tAc 'select current_user'
    " 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
}
check_revoked_security_key_rejected() {
    ensure_sk_key_registered || { echo "addkey failed"; return 1; }
    local cur; cur=$(journal_mark)
    cat /home/alice/.ssh/sk.pub > "$REVOKED"; chmod 640 "$REVOKED"
    local out; out=$(as_alice "
        tok=\$($SK_HELPER token ~/.ssh) || exit 9
        PGPASSWORD=\$tok psql -h 127.0.0.1 -U alice -d alice -tAc 'select 1'
    " 2>&1) && { clear_revocations; echo "a revoked security key authenticated"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: key for 'alice' is revoked" || { clear_revocations; return 1; }
    clear_revocations
}

echo "=== pam_pg_sshkey e2e ($(. /etc/os-release; echo "$PRETTY_NAME"), $(runuser -u postgres -- psql -tAc 'show server_version')) ==="
run_check tcp_connect_as_alice
run_check local_socket_connect_as_alice
run_check pg_sshkey_query
run_check python_module_connect
run_check wrong_key_rejected
run_check replayed_token_rejected
run_check nonce_deleted_after_auth
run_check bob_without_keys_rejected
run_check malformed_token_rejected
run_check root_owned_chal_dir_fails_closed
run_check umask_077_client_still_authenticates
run_check rsa_key_connect
run_check v1_token_still_accepted
run_check v2_replay_rejected
run_check v2_private_0700_dir
run_check v2_timestamp_window
run_check v2_unrecordable_nonce_fails_closed
run_check stale_nonces_swept
run_check python_replication_connect
run_check pg_sshkey_query_bad_sql_clean_error
run_check ssh_challenge_cmd_connect
run_check cert_connect_as_carol
run_check cert_python_connect
run_check cert_pg_sshkey_query
run_check cert_untrusted_ca_rejected
run_check cert_expired_rejected
run_check cert_wrong_principal_rejected
run_check cert_replay_rejected
run_check cert_alice_key_without_cert_still_works
run_check agent_connect_as_alice
run_check agent_passphrase_key_connects
run_check agent_rsa_key_connects
run_check agent_certificate_connects
run_check agent_query_and_python_connect
run_check agent_absent_is_a_clean_error
run_check cert_source_address_permitted
run_check cert_source_address_refused
run_check cert_source_address_local_socket_refused
run_check revoked_key_rejected
run_check revoked_certificate_rejected
run_check unreadable_revocation_list_fails_closed
run_check security_key_connect
run_check security_key_without_presence_rejected
run_check security_key_counter_is_not_checked
run_check revoked_security_key_rejected
summary
