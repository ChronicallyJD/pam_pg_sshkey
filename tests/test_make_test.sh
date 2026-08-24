#!/usr/bin/env bash
# test_make_test.sh, asserts that `make test` actually runs every suite
# docs/INSTALL.md §5 promises, and that no build outputs are tracked in git.
#
# Standalone (not part of `make test` itself, it inspects `make -n test`).
# Run from anywhere:  tests/test_make_test.sh
#
# SPDX-License-Identifier: MIT
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fails=0
ok()   { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; fails=$((fails+1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else fail "$name"; fi; }

dry=$(make -n test 2>/dev/null)

echo "=== make test wiring ==="
check "make -n test invokes tests/test_system" \
    grep -q 'tests/test_system' <<<"$dry"
check "test_system is invoked with the build dir on PATH" \
    grep -Eq 'PATH=[^;&|]*tests/test_system' <<<"$dry"
check "make -n test invokes tests/test_python_module.py" \
    grep -q 'tests/test_python_module.py' <<<"$dry"
check "make -n test invokes tests/test_ssh_cert" \
    grep -q 'tests/test_ssh_cert' <<<"$dry"
check "make -n test invokes tests/test_pam_module" \
    grep -q 'tests/test_pam_module' <<<"$dry"
check "make -n test invokes tests/test_pg_sshkey_query.py" \
    grep -q 'tests/test_pg_sshkey_query.py' <<<"$dry"
check "make -n test invokes tests/test_docs.sh" \
    grep -q 'tests/test_docs.sh' <<<"$dry"

echo "=== artifact hygiene ==="
check "no ELF binaries tracked in git" bash -c '! git ls-files -z | xargs -0 file -b 2>/dev/null | grep -q "^ELF"'
check "no build outputs tracked in git" bash -c \
    '! git ls-files | grep -Eq "^(pam_pg_sshkey\.so|pg_sshkey_(sign|challenge|connect|addkey|query)|src/.*\.o|tests/test_(challenge_store|key_parser|sig_verify|ssh_cert|integration|system|pam_module))$"'

echo "=== behavioural ==="
out=$(make test 2>&1)
check "make test really runs test_system (tool pipeline header present)" \
    grep -q '=== system (tool pipeline) ===' <<<"$out"
check "make test runs the python suite to OK" \
    grep -Eq '^OK( \([^)]*\))?$' <<<"$out"

echo
if [ "$fails" -eq 0 ]; then echo "all ok"; exit 0; fi
echo "$fails check(s) FAILED"; exit 1
