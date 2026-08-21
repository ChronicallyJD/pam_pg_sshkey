#!/usr/bin/env bash
# test_docs.sh, mechanical checks for the documentation rules in CLAUDE.md.
#
# Checks every tracked *.md file (plus untracked ones in docs/):
#   - no em dashes (U+2014)
#   - no emoji / check-mark glyphs / box-drawing-free prose is not required
#   - no bold callout shouting ("**Important:**", "**Note:**")
#   - no exclamation marks in prose
#   - fenced code blocks declare a language
#   - relative links resolve to a file (and a heading, when an anchor is given)
#   - headings are sentence case (heuristic, with an allowlist of proper nouns)
#
# Run from anywhere:  tests/test_docs.sh
# SPDX-License-Identifier: MIT
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

FINDINGS=$(mktemp); trap 'rm -f "$FINDINGS"' EXIT
EMDASH=$'\xe2\x80\x94'   # written as bytes so a repository-wide sweep cannot rewrite it
problem() { printf '  FAIL  %s\n' "$1" | tee -a "$FINDINGS"; }

if [[ $# -gt 0 ]]; then FILES=("$@")
else mapfile -t FILES < <( { git ls-files '*.md'; git ls-files -o --exclude-standard '*.md'; } | sort -u ); fi

# ── em dashes, glyphs, callouts, exclamation ─────────────────────────────────
for f in "${FILES[@]}"; do
    grep -n -- "$EMDASH" "$f"       | sed "s|^|$f:|" | while read -r l; do problem "em dash: $l"; done
    grep -n -P '[\x{2713}\x{2714}\x{2717}\x{2718}\x{274C}\x{2705}\x{1F300}-\x{1FAFF}]' "$f" \
                                    | sed "s|^|$f:|" | while read -r l; do problem "emoji/glyph: $l"; done
    grep -n -E '\*\*(Important|Note|Warning|Critical|NOTE|IMPORTANT)[:!]?\*\*' "$f" \
                                    | sed "s|^|$f:|" | while read -r l; do problem "callout shouting: $l"; done
    # exclamation marks outside code fences / inline code
    awk -v f="$f" '
        /^```/ { infence = !infence; next }
        infence { next }
        { line=$0; gsub(/`[^`]*`/, "", line); if (line ~ /!/ && line !~ /!\[/) printf "exclamation: %s:%d: %s\n", f, NR, $0 }
    ' "$f" | while read -r l; do problem "$l"; done
done

# ── fenced code blocks declare a language ────────────────────────────────────
for f in "${FILES[@]}"; do
    awk -v f="$f" '
        /^```/ { if (!infence) { if ($0 ~ /^```[ \t]*$/) printf "fence without language: %s:%d\n", f, NR }
                 infence = !infence }
    ' "$f" | while read -r l; do problem "$l"; done
done

# ── relative links resolve ───────────────────────────────────────────────────
slug() { # GitHub-style heading slug
    printf '%s' "$1" | tr 'A-Z' 'a-z' | sed -E 's/`//g; s/[^a-z0-9 _-]//g; s/ /-/g'
}
for f in "${FILES[@]}"; do
    dir=$(dirname "$f")
    grep -o -E '\]\(([^)#:]+)?(#[^)]+)?\)' "$f" | sed -E 's/^\]\(//; s/\)$//' | sort -u | while read -r link; do
        [[ -z "$link" ]] && continue
        target=${link%%#*}; anchor=${link#*#}; [[ "$anchor" == "$link" ]] && anchor=""
        if [[ -n "$target" ]]; then
            path="$dir/$target"; [[ "$target" == /* ]] && path=".$target"
            [[ -e "$path" ]] || { problem "broken link in $f: $link"; continue; }
        else
            path="$f"
        fi
        if [[ -n "$anchor" && "$path" == *.md ]]; then
            # collect first: grep -q would close the pipe on the first match and
            # pipefail would then report a found anchor as missing
            slugs=$(grep -E '^#{1,6} ' "$path" | sed -E 's/^#+ //' | while read -r h; do slug "$h"; echo; done)
            grep -qx -- "$anchor" <<<"$slugs" || problem "anchor not found in $f: $link"
        fi
    done
done

# ── sentence-case headings ───────────────────────────────────────────────────
ALLOW='PostgreSQL|PAM|SSH|RSA|Ed25519|Python|Ubuntu|Rocky|Linux|RHEL|Debian|Fedora|OpenSSH|OpenSSL|TLS|API|TCP|CLI|SQL|PEM|PKCS|I|MIT|Apache|Parquet|Iceberg|GitHub|CI|HOME|PATH|Makefile|NTP|Unix|IP|Rocky Linux|Claude|JD'
for f in "${FILES[@]}"; do
    grep -n -E '^#{1,6} ' "$f" | while IFS=: read -r n h; do
        text=$(sed -E 's/^#+ //; s/`[^`]*`//g; s/\[[^]]*\]\([^)]*\)//g' <<<"$h")
        # words after the first that start with a capital and are not allowed
        bad=$(awk -v allow="$ALLOW" '
            { n=split(allow, a, "|"); for (i=1;i<=n;i++) ok[a[i]]=1
              for (i=2;i<=NF;i++) { w=$i; gsub(/[^A-Za-z0-9.-]/, "", w); if (w ~ /^[A-Z]/ && !(w in ok) && w !~ /^[A-Z0-9.]+$/ && w !~ /^v[0-9]/) printf "%s ", w } }' <<<"$text")
        [[ -n "$bad" ]] && problem "heading not sentence case: $f:$n: $h ($bad)"
    done
done

fails=$(wc -l < "$FINDINGS")
echo
if [[ $fails -eq 0 ]]; then echo "docs ok"; exit 0; fi
echo "$fails documentation problem(s)"; exit 1
