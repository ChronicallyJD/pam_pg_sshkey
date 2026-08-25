# Installation

This page covers building pam_pg_sshkey from source and installing it on the
PostgreSQL server. It assumes a Linux host with PostgreSQL already installed.
Client machines need only the `pg_sshkey_sign` and `pg_sshkey_connect` tools,
or the Python module; see [User guide](user-guide.md).

## Requirements

- PostgreSQL built with PAM support. Distribution packages are. To confirm on
  a server built from source, run `pg_config --configure` and look for
  `--with-pam`.
- Linux-PAM 1.4 or later (the test harness uses `pam_start_confdir`).
- A C compiler, `make`, and `pkg-config`.
- OpenSSL development headers (`libssl-dev` on Debian and Ubuntu,
  `openssl-devel` on RHEL and Fedora).
- PAM development headers (`libpam0g-dev` on Debian and Ubuntu, `pam-devel`
  on RHEL and Fedora).
- Optional, for the Python module and `pg_sshkey_query`: Python 3.9 or later
  with `cryptography` and `psycopg2`. Passphrase-protected OpenSSH keys also
  need `bcrypt`.

The end-to-end suite runs on Ubuntu 26.04 with PostgreSQL 18 and on Rocky
Linux 9 with PostgreSQL 16. Other Debian-family and RHEL-family releases use
the same packaging paths and are expected to work; they are not in the tested
matrix.

Debian and Ubuntu:

```sh
sudo apt install build-essential libssl-dev libpam0g-dev pkg-config
```

RHEL, Rocky, Fedora:

```sh
sudo dnf install gcc make openssl-devel pam-devel pkgconf-pkg-config
```

## Build

```sh
make
```

This produces `pam_pg_sshkey.so`, the signing tool `pg_sshkey_sign`, and
copies of the scripts `pg_sshkey_connect`, `pg_sshkey_addkey`, and
`pg_sshkey_query` in the repository root. Build outputs are not tracked by
git.

Run `make test` before installing; it needs neither root nor PostgreSQL.
See [Testing](testing.md).

## Install

```sh
sudo make install
sudo make install-conf
```

`make install` copies these files:

| File | Destination |
| --- | --- |
| `pam_pg_sshkey.so` | `/lib/<triplet>/security/` on Debian and Ubuntu, `/lib64/security/` on RHEL and Fedora |
| `pg_sshkey_sign`, `pg_sshkey_connect`, `pg_sshkey_addkey`, `pg_sshkey_query` | `/usr/local/bin/` |
| tmpfiles.d rule | `/usr/lib/tmpfiles.d/pg_sshkey.conf` |

and creates these directories:

| Directory | Owner | Mode | Purpose |
| --- | --- | --- | --- |
| `/etc/pg_sshkeys` | `root:postgres` | `0750` | Root of the per-user `authorized_keys` tree |
| `/var/run/pg_sshkey` | `postgres:postgres` | `0700` | Record of the nonces already used. Only the module writes here; see [Security](security.md#file-permissions) |

`make install-conf` installs `/etc/pam.d/postgresql`, backing up an existing
file to `postgresql.bak`. Then configure PostgreSQL: [Configuration](configuration.md).

The install paths can be overridden: `PAM_LIB_DIR`, `BIN_DIR`,
`PAM_CONF_DIR`, `KEY_DIR`, `CHAL_DIR`, and `DESTDIR` for staged installs.

## After a reboot

`/var/run` is a tmpfs. The installed tmpfiles.d rule recreates the nonce
directory at boot:

```text
d /var/run/pg_sshkey 0700 postgres postgres -
```

To recreate it by hand:

```sh
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/pg_sshkey.conf
```

## Uninstall

```sh
sudo make uninstall
sudo mv /etc/pam.d/postgresql.bak /etc/pam.d/postgresql
sudo systemctl reload postgresql
```

`make uninstall` removes the module and the tools. It leaves
`/etc/pg_sshkeys`, `/var/run/pg_sshkey`, and
`/usr/lib/tmpfiles.d/pg_sshkey.conf` in place.
