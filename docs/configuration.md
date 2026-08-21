# Configuration

This page covers the two files PostgreSQL and PAM read to use pam_pg_sshkey:
`pg_hba.conf` and `/etc/pam.d/postgresql`. It assumes the module is
installed ([Installation](installation.md)).

## pg_hba.conf

Add `pam` rules ahead of the default rules. PostgreSQL uses the first rule
that matches, so a `pam` rule placed after a `scram-sha-256` rule for the
same clients never applies.

```text
# TYPE  DATABASE      USER   ADDRESS        METHOD  OPTIONS
local   all           all                   pam     pamservice=postgresql
host    all           all    0.0.0.0/0      pam     pamservice=postgresql
host    replication   all    0.0.0.0/0      pam     pamservice=postgresql
```

The `OPTIONS` column is separate from the `METHOD` column. A line with
`pamservice=postgresql` in the method position fails to parse, and PostgreSQL
reports `invalid authentication method "pamservice=postgresql"`.

Keep a `peer` rule for the `postgres` superuser on the local socket so
administration continues to work without a key:

```text
local   all           postgres              peer
```

Check the file and reload:

```sql
SELECT line_number, error FROM pg_hba_file_rules WHERE error IS NOT NULL;
```

```sh
sudo systemctl reload postgresql
```

Use `hostssl` rather than `host` on networks you do not control. The token
travels as the password, and PostgreSQL sends it in clear text unless the
connection is encrypted.

## The PAM service file

`make install-conf` installs this file as `/etc/pam.d/postgresql`:

```text
auth    required    pam_pg_sshkey.so \
            authorized_keys_dir=/etc/pg_sshkeys \
            challenge_dir=/var/run/pg_sshkey

account required    pam_permit.so
```

PostgreSQL calls the `auth` stack and then the `account` stack. The `account`
stack is `pam_permit.so` because a database role need not be an OS account.

### Module options

| Option | Default | Meaning |
| --- | --- | --- |
| `authorized_keys_dir=<dir>` | `/etc/pg_sshkeys` | Keys are read from `<dir>/<username>/authorized_keys` |
| `challenge_dir=<dir>` | `/var/run/pg_sshkey` | Where used nonces are recorded (and where v1 nonce files are read) |
| `debug` | off | Log each step at `LOG_DEBUG` to the `authpriv` facility |

Turn `debug` on only while diagnosing a problem; it logs the challenge of
every attempt.

## Roles

PAM authenticates; PostgreSQL authorizes. The role must exist, and it needs
no password:

```sql
CREATE ROLE alice LOGIN;
```

A replication subscriber additionally needs the `REPLICATION` attribute; see
[Replication](replication.md).
