# Makefile, pam_pg_sshkey
#
# Must be run from the project root (the directory containing this file).
# If you invoke make from elsewhere, use:
#   make -C /path/to/pam_pg_sshkey
#
# Targets:
#   all            Build PAM module + helper tools (default)
#   test / check   Build and run unit + integration tests
#   install        Install files system-wide (run as root)
#   install-conf   Install /etc/pam.d/postgresql
#   uninstall      Remove installed files
#   clean          Remove build artifacts
#
# Overridable variables:
#   CC, CFLAGS, PAM_LIB_DIR, BIN_DIR, PAM_CONF_DIR, KEY_DIR, CHAL_DIR, DESTDIR

# ── Locate the Makefile and enforce correct working directory ──────────────
# $(abspath) + $(lastword) resolves the Makefile's real directory even when
# invoked as "make -f ../Makefile" or from a symlink.
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# If make's CWD doesn't match the Makefile's directory, re-invoke with -C.
ifneq ($(abspath .),$(MAKEFILE_DIR:/=))
.PHONY: _redirect
_redirect:
	$(MAKE) -C "$(MAKEFILE_DIR)" $(MAKECMDGOALS)
# Suppress all other rules so make doesn't try to build anything here.
%:
	@true
else

# ── Everything below runs only when CWD == project root ───────────────────

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -Wpedantic -O2
PYTHON  ?= python3

CRYPTO_CFLAGS := $(shell pkg-config --cflags libcrypto 2>/dev/null)
CRYPTO_LIBS   := $(shell pkg-config --libs   libcrypto 2>/dev/null || echo -lcrypto)
PAM_CFLAGS    := -I/usr/include/security

# Debian/Ubuntu: /lib/<triplet>/security.  RHEL/Fedora: /lib64/security.
PAM_LIB_DIR  ?= $(shell if [ -d /lib64/security ]; then echo /lib64/security; \
                        else echo /lib/$$($(CC) -dumpmachine)/security; fi)
BIN_DIR      ?= /usr/local/bin
PAM_CONF_DIR ?= /etc/pam.d
KEY_DIR      ?= /etc/pg_sshkeys
CHAL_DIR     ?= /var/run/pg_sshkey

S := src
T := tests

PAM_SRCS := $S/pam_pg_sshkey.c $S/challenge_store.c \
            $S/key_parser.c    $S/sig_verify.c $S/ssh_cert.c
PAM_OBJS := $(PAM_SRCS:.c=.o)

TEST_BINS := $T/test_challenge_store $T/test_key_parser \
             $T/test_sig_verify      $T/test_ssh_cert    \
             $T/test_integration     $T/test_system      \
             $T/test_pam_module

.PHONY: all test check install install-conf uninstall clean e2e e2e-clean e2e-shell e2e-rocky e2e-rocky-clean

all: pam_pg_sshkey.so pg_sshkey_sign pg_sshkey_challenge pg_sshkey_connect pg_sshkey_addkey pg_sshkey_query

# ── Connect wrapper script ───────────────────────────────────────────────────
pg_sshkey_connect: $S/pg_sshkey_connect
	cp $S/pg_sshkey_connect pg_sshkey_connect
	chmod +x pg_sshkey_connect

# ── Key management script ────────────────────────────────────────────────────
pg_sshkey_addkey: $S/pg_sshkey_addkey
	cp $S/pg_sshkey_addkey pg_sshkey_addkey
	chmod +x pg_sshkey_addkey

# ── Python query utility ─────────────────────────────────────────────────────
pg_sshkey_query: $S/pg_sshkey_query.py
	cp $S/pg_sshkey_query.py pg_sshkey_query
	chmod +x pg_sshkey_query

# ── Compile .c → .o (static pattern rule, explicit, unambiguous) ──────────
$(PAM_OBJS): $S/%.o: $S/%.c
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) $(PAM_CFLAGS) -fPIC -c -o $@ $<

# ── PAM shared library ──────────────────────────────────────────────────────
pam_pg_sshkey.so: $(PAM_OBJS)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $^ $(CRYPTO_LIBS) -lpam

# ── Standalone binaries (compiled directly from .c, no intermediate .o) ────
pg_sshkey_sign: $S/pg_sshkey_sign.c $S/ssh_agent.c
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) -o $@ $^ $(CRYPTO_LIBS)

pg_sshkey_challenge: $S/pg_sshkey_challenge.c $S/challenge_store.c
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) -o $@ $^ $(CRYPTO_LIBS)

# ── Test binaries ───────────────────────────────────────────────────────────
TFLAGS := $(CFLAGS) $(CRYPTO_CFLAGS) $(PAM_CFLAGS) \
          -g -fsanitize=address,undefined -I$S -I$T
TLIBS  := $(CRYPTO_LIBS)

$T/test_challenge_store: $T/test_challenge_store.c $S/challenge_store.c
	$(CC) $(TFLAGS) -o $@ $^ $(TLIBS)

$T/test_key_parser: $T/test_key_parser.c $S/key_parser.c $S/challenge_store.c
	$(CC) $(TFLAGS) -o $@ $^ $(TLIBS)

$T/test_sig_verify: $T/test_sig_verify.c $S/sig_verify.c $S/key_parser.c
	$(CC) $(TFLAGS) -o $@ $^ $(TLIBS)

$T/test_ssh_cert: $T/test_ssh_cert.c $S/ssh_cert.c $S/key_parser.c
	$(CC) $(TFLAGS) -o $@ $^ $(TLIBS)

$T/test_integration: $T/test_integration.c \
                     $S/challenge_store.c $S/key_parser.c $S/sig_verify.c
	$(CC) $(TFLAGS) -o $@ $^ $(TLIBS)

$T/test_system: $T/test_system.c
	$(CC) $(TFLAGS) -o $@ $^ $(TLIBS)

# libpam-seam harness: loads the production pam_pg_sshkey.so through libpam.
# Built WITHOUT sanitizers, the object under test is the uninstrumented .so
# dlopen'ed by libpam; instrumenting the harness would only add noise.
TFLAGS_NOSAN := $(CFLAGS) $(PAM_CFLAGS) -g -I$S -I$T -Wno-format-truncation

$T/test_pam_module: $T/test_pam_module.c pam_pg_sshkey.so pg_sshkey_challenge pg_sshkey_sign
	$(CC) $(TFLAGS_NOSAN) -rdynamic -o $@ $< -lpam

# ── test / check ─────────────────────────────────────────────────────────────
# Depends on `all` so every suite exercises freshly built binaries:
# test_system execs pg_sshkey_challenge/pg_sshkey_sign from the build dir.
test check: all $(TEST_BINS)
	@echo ""
	@echo "=== test_challenge_store ==="; $T/test_challenge_store
	@echo ""
	@echo "=== test_key_parser ===";      $T/test_key_parser
	@echo ""
	@echo "=== test_sig_verify ===";      $T/test_sig_verify
	@echo ""
	@echo "=== test_ssh_cert ===";        $T/test_ssh_cert
	@echo ""
	@echo "=== test_integration ===";     $T/test_integration
	@echo ""
	@echo "=== test_pam_module ===";      PAM_PG_SSHKEY_BUILDDIR=$(CURDIR) $T/test_pam_module
	@echo ""
	@echo "=== test_system ===";          PATH="$(CURDIR):$$PATH" $T/test_system
	@echo ""
	@echo "=== test_python_module ===";   $(PYTHON) $T/test_python_module.py
	@echo ""
	@echo "=== test_pg_sshkey_query ===";  $(PYTHON) $T/test_pg_sshkey_query.py
	@echo ""
	@echo "=== test_docs ===";            $T/test_docs.sh
	@echo ""
	@echo "All test suites complete."

# ── e2e: real PostgreSQL in a dedicated incus container ───────────────────
# Not part of `make test`; requires incus on the host.  See tests/e2e/.
E2E_CONTAINER ?= pam-sshkey-e2e
E2E_IMAGE     ?= images:ubuntu/26.04

e2e:
	E2E_CONTAINER=$(E2E_CONTAINER) E2E_IMAGE=$(E2E_IMAGE) $T/e2e/run_incus.sh

e2e-clean:
	E2E_CONTAINER=$(E2E_CONTAINER) $T/e2e/run_incus.sh --destroy

e2e-shell:
	incus exec $(E2E_CONTAINER) -- bash -l

# Same checks on RHEL-family packaging (PostgreSQL 16 module stream)
E2E_ROCKY_CONTAINER ?= pam-sshkey-e2e-rocky9
E2E_ROCKY_IMAGE     ?= images:rockylinux/9

e2e-rocky:
	E2E_CONTAINER=$(E2E_ROCKY_CONTAINER) E2E_IMAGE=$(E2E_ROCKY_IMAGE) $T/e2e/run_incus.sh

e2e-rocky-clean:
	E2E_CONTAINER=$(E2E_ROCKY_CONTAINER) $T/e2e/run_incus.sh --destroy

# ── Install ───────────────────────────────────────────────────────────────────
install: all
	install -d $(DESTDIR)$(PAM_LIB_DIR)
	install -m 755 pam_pg_sshkey.so $(DESTDIR)$(PAM_LIB_DIR)/
	install -d $(DESTDIR)$(BIN_DIR)
	install -m 755 pg_sshkey_sign      $(DESTDIR)$(BIN_DIR)/
	install -m 755 pg_sshkey_challenge $(DESTDIR)$(BIN_DIR)/
	install -m 755 pg_sshkey_connect   $(DESTDIR)$(BIN_DIR)/
	install -m 755 pg_sshkey_addkey    $(DESTDIR)$(BIN_DIR)/
	install -m 755 pg_sshkey_query     $(DESTDIR)$(BIN_DIR)/
	install -d -m 750 -o root -g postgres $(DESTDIR)$(KEY_DIR)
	# Challenge dir: sticky-bit world-write so any user can create nonces
	# but only the owner of each file can delete it.
	# The postgres user (PAM module) is the owner of the directory so it
	# can read and unlink any file inside regardless of sticky bit.
	install -d -m 1733 -o postgres -g postgres $(DESTDIR)$(CHAL_DIR)
	# Install tmpfiles.d config so systemd recreates the directory at boot
	install -d $(DESTDIR)/usr/lib/tmpfiles.d
	printf 'd /var/run/pg_sshkey 1733 postgres postgres -\n' > /tmp/pg_sshkey_tmpfiles
	install -m 644 /tmp/pg_sshkey_tmpfiles $(DESTDIR)/usr/lib/tmpfiles.d/pg_sshkey.conf

install-conf:
	@if [ -f $(PAM_CONF_DIR)/postgresql ]; then \
	    echo "Backing up $(PAM_CONF_DIR)/postgresql → postgresql.bak"; \
	    cp $(PAM_CONF_DIR)/postgresql $(PAM_CONF_DIR)/postgresql.bak; \
	fi
	install -m 644 config/pam.d/postgresql $(PAM_CONF_DIR)/postgresql
	@echo ""
	@echo "Remember to update pg_hba.conf:"
	@echo "  host all all 0.0.0.0/0 pam pamservice=postgresql"

# ── Uninstall ─────────────────────────────────────────────────────────────────
uninstall:
	rm -f $(DESTDIR)$(PAM_LIB_DIR)/pam_pg_sshkey.so
	rm -f $(DESTDIR)$(BIN_DIR)/pg_sshkey_sign
	rm -f $(DESTDIR)$(BIN_DIR)/pg_sshkey_challenge
	rm -f $(DESTDIR)$(BIN_DIR)/pg_sshkey_connect
	rm -f $(DESTDIR)$(BIN_DIR)/pg_sshkey_addkey
	rm -f $(DESTDIR)$(BIN_DIR)/pg_sshkey_query

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	rm -f $S/*.o
	rm -f pam_pg_sshkey.so pg_sshkey_sign pg_sshkey_challenge pg_sshkey_connect pg_sshkey_addkey pg_sshkey_query
	rm -f $(TEST_BINS)
	rm -rf $S/__pycache__ $T/__pycache__

endif  # CWD guard
