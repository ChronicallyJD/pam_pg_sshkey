#!/usr/bin/env bash
# run_incus.sh, host side driver for the PostgreSQL end-to-end tests.
#
# Launches (or reuses) a dedicated incus container, pushes the repository
# SOURCE into it (never build artifacts), provisions PostgreSQL + the module,
# and runs tests/e2e/check.sh.  Never touches any other container.
#
#   tests/e2e/run_incus.sh            provision + check (idempotent)
#   tests/e2e/run_incus.sh --fresh    destroy first, then run
#   tests/e2e/run_incus.sh --destroy  delete the container and exit
#
# Env:  E2E_CONTAINER (default pam-sshkey-e2e)
#       E2E_IMAGE     (default images:ubuntu/26.04)
#       E2E_ONLY      run a single check
#       E2E_SKIP_HBA  leave pg_hba.conf alone (observe the red state)
#
# SPDX-License-Identifier: MIT
set -euo pipefail

C=${E2E_CONTAINER:-pam-sshkey-e2e}
IMAGE=${E2E_IMAGE:-images:ubuntu/26.04}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

die() { echo "run_incus: $*" >&2; exit 1; }
command -v incus >/dev/null || die "incus not found (make test does not need it; make e2e does)"

destroy() { if incus info "$C" >/dev/null 2>&1; then echo "run_incus: deleting $C"; incus delete -f "$C"; fi; }

case "${1:-}" in
  --destroy) destroy; exit 0 ;;
  --fresh)   destroy; shift ;;
  "") ;;
  *) die "unknown option: $1" ;;
esac

if ! incus info "$C" >/dev/null 2>&1; then
    echo "run_incus: launching $C from $IMAGE"
    incus launch "$IMAGE" "$C" >/dev/null
elif [[ "$(incus list -f csv -c n,s | awk -F, -v c="$C" '$1==c{print $2}')" != "RUNNING" ]]; then
    incus start "$C"
fi

echo -n "run_incus: waiting for $C"
for _ in $(seq 1 90); do
    if incus exec "$C" -- sh -c 'getent hosts images.linuxcontainers.org >/dev/null 2>&1 && { systemctl is-system-running --quiet 2>/dev/null || systemctl is-system-running 2>/dev/null | grep -q degraded; }'; then
        echo " ready"; break
    fi
    echo -n "."; sleep 1
done

# minimal images may lack tar/gzip
incus exec "$C" -- sh -c 'command -v tar >/dev/null && command -v gzip >/dev/null' \
    || incus exec "$C" -- sh -c 'dnf -y -q install tar gzip >/dev/null 2>&1 || apt-get install -y -qq tar gzip >/dev/null'

echo "run_incus: pushing source"
( cd "$ROOT" && git ls-files -co --exclude-standard -z | tar --null -T - -czf - ) \
  | incus exec "$C" -- sh -c 'rm -rf /opt/pam_pg_sshkey && mkdir -p /opt/pam_pg_sshkey && tar xzf - -C /opt/pam_pg_sshkey && chmod -R a+rX /opt/pam_pg_sshkey'

incus exec "$C" --env DEBIAN_FRONTEND=noninteractive --env "E2E_SKIP_HBA=${E2E_SKIP_HBA:-}" \
    -- bash /opt/pam_pg_sshkey/tests/e2e/provision.sh

incus exec "$C" --env "E2E_ONLY=${E2E_ONLY:-}" -- bash /opt/pam_pg_sshkey/tests/e2e/check.sh
