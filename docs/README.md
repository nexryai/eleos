# Eleos documentation

MDX documentation for the Eleos implementation in the parent directory, built
with Astro and Fumapress. The Notebook layout keeps search, the language switch
and the GitHub link in the top bar.

## Development

```sh
pnpm install --frozen-lockfile
pnpm dev
```

English: `/en/`, Japanese: `/ja/`, Simplified Chinese: `/zh-CN/`.
The root redirects to English. Search indexes and sidebars are separate for each
language; missing translations do not fall back to another language.

## Editing

Pages live in `content/<locale>/*.mdx`; `meta.json` sets their sidebar order.
Keep the same slugs and command/configuration examples in all three languages.
Use links with the current locale prefix. UI labels live in `src/i18n.ts`.

Verify behavior against `../main.go`, `../internal/config/config.go`,
`../internal/firewall/`, `../systemd/eleos.service` and `../snap/` when updating
the docs. Installation commands are based on `../README.md`. Update translations
together when the implementation changes.

`fumadocs-core` and `fumadocs-ui` are pinned to 16.18.3 because the installed
Astro integration uses APIs removed in 16.19.0. Upgrade the integration and both
packages together, then check the generated pages.

`src/markdown.mjs` preserves fenced code as `pre > code` to work around the
installed integration's code-tag renaming on Satteri. Astro's highlighter is
disabled so Fumadocs handles syntax highlighting and the copy-button wrapper.

## Checks

```sh
pnpm types:check
pnpm test
```

`pnpm test` builds the site and checks translation coverage, example parity,
internal links, language metadata, Notebook navigation and localized search data.
It does not apply firewall rules or change the host's network configuration.

## Release deployment

The `release` workflow builds documentation from the released tag with Node.js 24
and pnpm 10.33.0. It merges `docs/dist` into the same Pages artifact as the signed
APT and pacman repositories. Documentation is the site root at
`https://nexryai.github.io/eleos/`; there is no separate package landing page.
Package paths (`pool/`, `dists/`, `pacman/`) and public-key URLs stay unchanged.
The current signing-key fingerprint is published as
`eleos-archive-keyring.fingerprint`.

To reproduce the Pages build locally:

```sh
DOCS_SITE_URL=https://nexryai.github.io DOCS_BASE_PATH=/eleos pnpm test
```

These variables set Astro's `site` and `base`; local development defaults to `/`.
The regression tests also verify deployed page/asset URLs and repository-path
collisions. The combined deployment is skipped if `APT_GPG_PRIVATE_KEY` is absent,
so a docs-only deployment cannot replace the package repositories.
