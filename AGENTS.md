# AGENTS.md

## Commit guidelines

- Make signed commits (`git commit -S`) frequently, in small, focused increments.

## Testing

- Write tests whenever possible. Prefer adding tests alongside new code and bug fixes.

## Releasing

- Push a `v<version>` tag. The `release` workflow builds the binary archives,
  `.deb` packages and Arch packages, publishes the APT and pacman repositories
  on GitHub Pages, and commits the updated `packaging/arch/PKGBUILD`,
  `packaging/arch/.SRCINFO` and `eleos.spec` back to `main` (with `[skip ci]`).
  No local packaging script needs to be run. The metadata commit is created
  through the GitHub GraphQL API so it is signed (main requires signed commits).
- COPR derives the RPM version from the checked-out tag in `.copr/Makefile`;
  branch builds fall back to the `Version` committed in `eleos.spec`.
- The snap version comes from `version: git` in `snap/snapcraft.yaml`.
- A tag with a hyphen (`v0.61-fix3`) is published as `pkgver=0.61_fix3`,
  because makepkg rejects hyphens in `pkgver`.
