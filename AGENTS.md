# AGENTS.md

## Commit guidelines

- Make signed commits (`git commit -S`) frequently, in small, focused increments.

## Testing

- Write tests whenever possible. Prefer adding tests alongside new code and bug fixes.

## Releasing

- Before tagging `v<version>`, run `packaging/arch/update-pkgbuild.sh <version>` and commit the updated `packaging/arch/PKGBUILD` and `.SRCINFO`. The release workflow builds its own tag-pinned copy, but the checked-in files are what AUR clients (`paru`, `yay`) and other `.SRCINFO` consumers read.
- The `release` workflow builds Arch packages for `x86_64` and `aarch64`, attaches them to the GitHub Release, and republishes the signed pacman repository on GitHub Pages next to the APT repository.
