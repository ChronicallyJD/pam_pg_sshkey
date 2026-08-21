# pam_pg_sshkey logo

Brand assets for pam_pg_sshkey. The mark is a key drawn from the same rounded
shapes as the pgColumnar bars: a blue bow and shaft, with the two teeth of the
bit in amber. It shares the pgColumnar palette so the two projects read as a
family. All files are self-contained SVG with no external fonts or images.

| File | Use |
| --- | --- |
| `pam_pg_sshkey-logo.svg` | Horizontal lockup (mark plus wordmark) for light backgrounds |
| `pam_pg_sshkey-logo-dark.svg` | Horizontal lockup for dark backgrounds |
| `pam_pg_sshkey-mark.svg` | Mark only, for favicons and avatars; holds its shape down to 16 px |

## Palette

| Role | Value |
| --- | --- |
| Key blue | `#5B8DEF` to `#2B5FD0` (vertical gradient) |
| Key blue on dark | `#7AA2F7` to `#3B6FE0` |
| Accent amber (the bit) | `#F7B733` to `#F59E0B` |
| Wordmark ink | `#1F2A44` on light, `#F2F4F8` on dark |
| Tagline | `#5A6478` on light, `#9AA4B8` on dark |

The wordmark is set in a system sans-serif stack (`Segoe UI`, `Roboto`,
`Helvetica`, `Arial`), with `pg` in key blue. To lock the wordmark independent
of installed fonts, convert its text to paths in a vector editor.

## Theme-aware embedding

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="logo/pam_pg_sshkey-logo-dark.svg">
  <img src="logo/pam_pg_sshkey-logo.svg" alt="pam_pg_sshkey" width="420">
</picture>
```

## Rendering a PNG

```sh
python3 -c "import cairosvg; cairosvg.svg2png(url='logo/pam_pg_sshkey-mark.svg', write_to='mark-256.png', output_width=256)"
```
