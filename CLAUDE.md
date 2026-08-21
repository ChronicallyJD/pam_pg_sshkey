# pam_pg_sshkey working rules

Rules for anyone, human or agent, changing this repository. They were learned on
this project and its siblings (`../pgcolumnar`, `../articles`); when an edit or
a review reveals a new preference, record it here and say what prompted it.

## Prove, don't trust

A claim about this code is true when a test at a real seam shows it, and a fix is
done when its check goes red with the fix removed.

- **Seams.** `tests/test_pam_module.c` loads the production `pam_pg_sshkey.so`
  through libpam exactly as PostgreSQL does. `tests/e2e/` authenticates real
  OS users against real PostgreSQL (`make e2e`, `make e2e-rocky`). Test new
  behaviour there first; unit tests of the library files are supporting
  evidence, not proof. The RSA parser was wrong for the project's whole life
  while every RSA unit test passed, because those tests built the key object
  by hand instead of parsing an `authorized_keys` line.
- **Red first.** Write the check, watch it fail for the stated reason, then
  change the code. Read the failure text; a check that fails for a different
  reason proves nothing.
- **Removal proof.** For every fix, mutate it away (a `sed` in the container
  copy or on the host), rebuild, and name the check that fails. Recording the
  e2e checks' reds this way is what caught `pg_sshkey_query` validating the
  v2 token against the v1 shape before it shipped.
- **Rebuild before believing.** `make` trusts mtimes; a restored source file
  older than its object is "up to date" and the mutated binary stays
  installed. `make clean && make` after any mutation round.
- **Measure the work, not the intent.** A positive connect proves PAM did the
  work only when the journal carries `pam_pg_sshkey: user '<u>' authenticated
  with key`; Ubuntu's default `local all all peer` also admits the user.
- When one instance of a claim turns out false, grep for the same phrasing
  everywhere before calling it fixed (the SHA-512 digest table lived in four
  files).
- **Verify a commit series with every check, not just `make test`.** Check each
  commit out in a worktree and run `make test && tests/test_make_test.sh`.
  The 1.1.0 release commits were verified with `make test` alone, and the
  commit titled "Stop tracking build outputs" had re-added them (a `git add
  -u` on files `make test` had just rebuilt). CI caught it after the push.

## Documentation rules

Follow `../articles/CLAUDE.md` for prose and `../pgcolumnar/docs/` for the
shape of a technical page. `tests/test_docs.sh` enforces the mechanical part
and runs in `make test`.

- **Hard rules.** No em dashes; use a period, comma, or colon. No emoji, check
  marks, or a bolded "Important:" or "Note:" callout. No exclamation marks. Sentence
  case for every heading ("Build and install"). Fenced code declares its
  language. Every relative link resolves.
- **Sentences.** Short and declarative, present tense for general claims, plain
  words a 10th grader reads without a glossary. Cut throat-clearing and
  hedging intensifiers ("strongly", "seriously", "simply"). Every sentence
  earns its place.
- **Facts.** Exact versions, paths, modes, and numbers, taken from the code or
  a test run, never retyped from memory. State what is verified (the e2e
  matrix) rather than what is believed to work. Put a feature's limitation in
  the paragraph that describes the feature.
- **Pages.** Each page opens with one or two sentences saying what it covers
  and what it assumes, and owns one question. `README.md` says what the
  project is, shows a quick start, and points at `docs/` through a table;
  it repeats nothing the pages say. `docs/index.md` is the "where to start"
  table.
- **Reference data** goes in tables with a header row and `| --- |` rule;
  procedures go in numbered steps only when order matters.
- **Changelog.** Keep a Changelog format, `## [x.y.z] - YYYY-MM-DD` with a
  hyphen. An entry says what a user observes and names the test that covers
  it. One changelog, at the repository root.
- **Voice.** Direct and even. Describe a defect plainly ("RSA keys never
  authenticated through the module"), without drama and without softening.

## Environment

- Host has `libpam0g-dev`, `libssl-dev`, `ssh-keygen`, Python with
  `cryptography` and `psycopg2` but no `bcrypt` (four Python tests skip).
  `make test` needs none of: root, PostgreSQL, incus.
- End-to-end runs in dedicated incus containers only: `pam-sshkey-e2e`
  (Ubuntu 26.04, PostgreSQL 18) and `pam-sshkey-e2e-rocky9` (Rocky 9,
  PostgreSQL 16). Never use the user's other containers. `make e2e-clean`
  and `make e2e-rocky-clean` delete them; `E2E_ONLY=<check> make e2e` runs
  one check.
- `incus list <name>` filters by prefix; match names exactly in scripts.
- Running `python3 -c "import pam_pg_sshkey"` from the repository root loads
  `./pam_pg_sshkey.so` instead of `src/pam_pg_sshkey.py`. Run from `src/` or
  another directory.
- Commit only when asked. Build outputs are untracked (`.gitignore`); keep
  them that way.

## Documents and what each owns

| Document | Owns |
| --- | --- |
| `README.md` | What the project is, quick start, pointers |
| `docs/index.md` | Where to start |
| `docs/*.md` | One question per page (install, configure, use, Python, replication, reference, security, troubleshooting, testing) |
| `CHANGELOG.md` | What changed, per release |
| This file | How to work here |
