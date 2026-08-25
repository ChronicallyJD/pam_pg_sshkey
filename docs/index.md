# pam_pg_sshkey documentation

pam_pg_sshkey is a PAM module that authenticates PostgreSQL users with SSH
public keys. The server holds the public keys; the client signs a timestamped
one-time token with its private key and sends it as the PostgreSQL password.
These pages cover installing the module, configuring PostgreSQL, connecting
from the shell and from Python, and operating it securely.

## Where to start

| If you want to | Read |
| --- | --- |
| Build and install the module on a server | [Installation](installation.md) |
| Tell PostgreSQL and PAM to use it | [Configuration](configuration.md) |
| Register a key and connect, with a key file, an ssh-agent, a security key, or a CA-signed certificate | [User guide](user-guide.md) |
| Authenticate from a Python application | [Python](python.md) |
| Run a logical replication subscriber without a stored password | [Replication](replication.md) |
| Look up a token format, a tool option, or a log message | [Reference](reference.md) |
| Understand the trust model and harden a deployment | [Security](security.md) |
| Diagnose a failed login | [Troubleshooting](troubleshooting.md) |
| Run the tests or verify a change | [Testing](testing.md) |

## What is verified

Every claim in these pages is backed by a test. `make test` runs on the build
host without root or PostgreSQL and loads the production module through
libpam the way PostgreSQL does. `make e2e` and `make e2e-rocky` authenticate
real OS users against PostgreSQL 18 on Ubuntu 26.04 and PostgreSQL 16 on
Rocky Linux 9 in dedicated containers. [Testing](testing.md) lists what each
suite proves.
