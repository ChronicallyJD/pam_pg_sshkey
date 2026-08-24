#!/usr/bin/env bash
# provision.sh, runs INSIDE the e2e container as root.  Idempotent.
#
# Installs PostgreSQL + build deps, builds and installs pam_pg_sshkey from
# /opt/pam_pg_sshkey, configures pg_hba.conf for PAM, and creates the test
# users/roles/keys the checks rely on.
#
# Env:
#   E2E_SKIP_HBA=1   leave pg_hba.conf untouched (used to observe the red
#                    state of the first connect check)
#
# SPDX-License-Identifier: MIT
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

SRC=/opt/pam_pg_sshkey
CHAL_DIR=/var/run/pg_sshkey
. /etc/os-release

log() { echo "provision: $*"; }

case "$ID" in
  ubuntu|debian)
    PGVER=18
    PGHBA=/etc/postgresql/$PGVER/main/pg_hba.conf
    PGBIN=/usr/lib/postgresql/$PGVER/bin/postgres
    PKGS="postgresql-$PGVER libssl-dev libpam0g-dev gcc make pkg-config python3 python3-psycopg2
          python3-cryptography python3-bcrypt openssh-client openssh-server file"
    missing=0; for pkg in $PKGS; do dpkg -s "$pkg" >/dev/null 2>&1 || missing=1; done
    if [[ $missing -eq 1 ]]; then
        log "installing packages"
        apt-get update -qq
        apt-get install -y -qq $PKGS >/dev/null
    fi
    reload_pg() { pg_ctlcluster $PGVER main reload; }
    ;;
  rocky|rhel|almalinux|centos|fedora)
    PGVER=16
    PGHBA=/var/lib/pgsql/data/pg_hba.conf
    PGBIN=/usr/bin/postgres
    PKGS="postgresql-server postgresql openssl-devel pam-devel gcc make pkgconf-pkg-config
          python3 python3-psycopg2 python3-cryptography openssh-clients openssh-server file which hostname"
    missing=0; for pkg in $PKGS; do rpm -q "$pkg" >/dev/null 2>&1 || missing=1; done
    if [[ $missing -eq 1 ]]; then
        log "installing packages"
        dnf -y -q module enable postgresql:$PGVER >/dev/null 2>&1 || true
        dnf -y -q install $PKGS >/dev/null
        dnf -y -q install python3-bcrypt >/dev/null 2>&1 || log "python3-bcrypt unavailable (passphrase-key tests will skip)"
    fi
    [[ -f /var/lib/pgsql/data/PG_VERSION ]] || postgresql-setup --initdb >/dev/null
    systemctl enable --now postgresql >/dev/null 2>&1
    reload_pg() { systemctl reload postgresql; }
    ;;
  *)
    echo "provision: unsupported distro '$ID' (add a case branch)" >&2; exit 1 ;;
esac

# psql as the postgres OS user (sudo may not be installed on every image)
pg() { runuser -u postgres -- psql "$@"; }

# ── PG must be built with PAM ────────────────────────────────────────────────
ldd "$PGBIN" | grep -q libpam || { echo "provision: $PGBIN is not linked against libpam" >&2; exit 1; }
systemctl is-active --quiet postgresql || systemctl start postgresql
until pg -tAc 'select 1' >/dev/null 2>&1; do sleep 0.5; done

# ── build + install from source ──────────────────────────────────────────────
log "building and installing from $SRC"
make -C "$SRC" clean >/dev/null
make -C "$SRC" >/dev/null
make -C "$SRC" install >/dev/null
make -C "$SRC" install-conf >/dev/null
# install-conf ships the auth line without trusted_ca_keys; the e2e checks
# need it.  Appended once, after the challenge_dir continuation line.
PAMCONF=/etc/pam.d/postgresql
if ! grep -qE '^[^#]*trusted_ca_keys=' "$PAMCONF"; then
    log "adding trusted_ca_keys to $PAMCONF"
    sed -i 's|^\([[:space:]]*challenge_dir=[^[:space:]]*\)[[:space:]]*$|\1 \\\n            trusted_ca_keys=/etc/pg_sshkeys/trusted_ca_keys|' "$PAMCONF"
    grep -q 'trusted_ca_keys=/etc/pg_sshkeys/trusted_ca_keys' "$PAMCONF" \
        || { echo "provision: could not add trusted_ca_keys to $PAMCONF (no challenge_dir= line?)" >&2; exit 1; }
fi
install -d -m 1733 -o postgres -g postgres "$CHAL_DIR"
chown postgres:postgres "$CHAL_DIR"; chmod 1733 "$CHAL_DIR"

# ── pg_hba.conf ──────────────────────────────────────────────────────────────
hba_block() {
    echo '# pam_pg_sshkey-e2e BEGIN'
    echo 'local   all   postgres                 peer'
    echo 'local   all   all                      pam   pamservice=postgresql'
    echo 'host    all   all   127.0.0.1/32       pam   pamservice=postgresql'
    echo 'host    replication   all   127.0.0.1/32   pam   pamservice=postgresql'
    echo '# pam_pg_sshkey-e2e END'
}
if [[ -z "${E2E_SKIP_HBA:-}" ]]; then
    # Regenerate the block on every run so edits to it take effect on an
    # existing container; the original file (minus our block) is preserved.
    [[ -f "$PGHBA.e2e.bak" ]] || cp "$PGHBA" "$PGHBA.e2e.bak"
    rest=$(sed '/# pam_pg_sshkey-e2e BEGIN/,/# pam_pg_sshkey-e2e END/d' "$PGHBA")
    if [[ "$(hba_block; printf '%s\n' "$rest")" != "$(cat "$PGHBA")" ]]; then
        log "writing pam lines to $PGHBA"
        { hba_block; printf '%s\n' "$rest"; } > "$PGHBA"
    fi
fi
reload_pg
bad=$(pg -tAc "select count(*) from pg_hba_file_rules where error is not null")
[[ "$bad" == "0" ]] || { echo "provision: pg_hba.conf has $bad bad rule(s)" >&2; pg -c "select line_number, error from pg_hba_file_rules where error is not null"; exit 1; }

# ── OS users, roles, databases ───────────────────────────────────────────────
for u in alice bob carol; do
    id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
    pg -tAc "select 1 from pg_roles where rolname='$u'" | grep -q 1 \
        || pg -qc "create role $u login"
    pg -tAc "select 1 from pg_database where datname='$u'" | grep -q 1 \
        || runuser -u postgres -- createdb -O "$u" "$u"
done

# alice may open replication connections (logical + physical checks)
pg -qc "alter role alice replication"

# ── keys ─────────────────────────────────────────────────────────────────────
gen() { # <user> <name> <ssh-keygen args...>
    local u=$1 n=$2; shift 2
    runuser -l "$u" -c "mkdir -p -m 700 ~/.ssh; [ -f ~/.ssh/$n ] || ssh-keygen -q $* -N '' -C $n -f ~/.ssh/$n"
}
gen alice id_ed25519 -t ed25519
gen alice id_wrong   -t ed25519
gen alice id_rsa_pem -t rsa -b 2048 -m PEM
gen bob   id_ed25519 -t ed25519
gen carol id_ed25519 -t ed25519

# alice's ed25519 key is registered; id_wrong, id_rsa_pem, bob's and carol's
# keys are not (id_rsa_pem is registered by the rsa check itself; carol
# authenticates with a certificate only).
pg_sshkey_addkey alice /home/alice/.ssh/id_ed25519.pub >/dev/null
pg_sshkey_addkey --remove bob   >/dev/null 2>&1 || true
pg_sshkey_addkey --remove carol >/dev/null 2>&1 || true

# ── certificate authorities ──────────────────────────────────────────────────
# Private CA keys live under /root (outside authorized_keys_dir so the key
# scanner never sees them).  Only trusted_ca is published to the module.
CA_DIR=/root/pam_pg_sshkey_e2e_ca
TRUSTED_CA_KEYS=/etc/pg_sshkeys/trusted_ca_keys
install -d -m 700 "$CA_DIR"
for ca in trusted_ca untrusted_ca; do
    [[ -f "$CA_DIR/$ca" ]] || ssh-keygen -q -t ed25519 -N '' -C "$ca" -f "$CA_DIR/$ca"
done
if ! cmp -s "$CA_DIR/trusted_ca.pub" "$TRUSTED_CA_KEYS" 2>/dev/null; then
    log "writing $TRUSTED_CA_KEYS"
    install -m 640 -o root -g postgres "$CA_DIR/trusted_ca.pub" "$TRUSTED_CA_KEYS"
fi
chown root:postgres "$TRUSTED_CA_KEYS"; chmod 640 "$TRUSTED_CA_KEYS"

# sign <user> <name> <ca> <ssh-keygen -s args...>
# Copies ~/.ssh/id_ed25519.pub to ~/.ssh/<name>.pub and signs it, producing
# ~/.ssh/<name>-cert.pub.  Re-signs when the user key or the CA key is newer
# than the certificate, so regenerated keys never leave a stale certificate.
sign() {
    local u=$1 n=$2 ca=$3; shift 3
    local home; home=$(getent passwd "$u" | cut -d: -f6)
    local pub=$home/.ssh/id_ed25519.pub copy=$home/.ssh/$n.pub cert=$home/.ssh/$n-cert.pub
    if [[ "$copy" != "$pub" ]] && ! cmp -s "$pub" "$copy"; then cp "$pub" "$copy"; chown "$u:$u" "$copy"; chmod 644 "$copy"; fi
    if [[ ! -f "$cert" || "$pub" -nt "$cert" || "$CA_DIR/$ca" -nt "$cert" ]]; then
        rm -f "$cert"
        ssh-keygen -q -s "$CA_DIR/$ca" "$@" "$copy"
        chown "$u:$u" "$cert"; chmod 644 "$cert"
    fi
}
# carol's certificate, trusted CA, principal carol, valid from a minute ago for a year
sign carol id_ed25519           trusted_ca   -I carol-key       -n carol -V -1m:+52w
# same key, signed by the CA the module does not trust
sign carol id_ed25519_untrusted untrusted_ca -I carol-untrusted -n carol -V -1m:+52w
# same key, trusted CA, expired an hour ago
sign carol id_ed25519_expired   trusted_ca   -I carol-expired   -n carol -V -2h:-1h
# same key, trusted CA, but only principal bob is listed
sign carol id_ed25519_bob       trusted_ca   -I carol-as-bob    -n bob   -V -1m:+52w

# ── sshd: lets alice mint a nonce "on the server" via ssh (remote-client flow) ──
runuser -l alice -c 'grep -qf ~/.ssh/id_ed25519.pub ~/.ssh/authorized_keys 2>/dev/null || cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys'
systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null \
    || systemctl start ssh 2>/dev/null || systemctl start sshd

log "done"
