#!/usr/bin/env bash
# Update pkgver and sha256sums in packaging/arch/{PKGBUILD,.SRCINFO} for a
# release. The script downloads the tag tarball, so run it *after* the
# v<version> tag is pushed, then commit the result.
#
# Usage: packaging/arch/update-pkgbuild.sh <version>
set -euo pipefail

[[ $# -eq 1 ]] || {
	echo "usage: $0 <version>" >&2
	exit 2
}

tag="${1#v}"
case "$tag" in
	[0-9]*) ;;
	*) echo "invalid version: $tag" >&2; exit 2 ;;
esac

# makepkg rejects a pkgver with hyphens, but release tags can contain them
# (v0.61-fix3). The tag is what the URL needs; pkgver is the normalised form.
pkgver="${tag//-/_}"

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
url="https://github.com/nexryai/eleos/archive/refs/tags/v${tag}.tar.gz"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

for tool in curl sha256sum makepkg sed; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "missing required tool: $tool" >&2
		exit 1
	}
done

echo "Downloading $url"
curl -fsSL --retry 3 "$url" -o "$tmp"
sha="$(sha256sum "$tmp" | cut -d' ' -f1)"

# pkgrel goes back to 1 on every version bump (a pkgrel that stays above 1
# would make the new version look like a rebuild of the previous one). The
# source line is always written out with the actual tag, because the tag and the
# normalised pkgver differ when the tag has a hyphen.
sed -E -i \
	-e "s/^pkgver=.*/pkgver=${pkgver}/" \
	-e "s/^pkgrel=.*/pkgrel=1/" \
	-e "s/^sha256sums=.*/sha256sums=('${sha}')/" \
	-e "s|^source=.*|source=(\"eleos-${pkgver}.tar.gz::${url}\")|" \
	"$dir/PKGBUILD"

# .SRCINFO is derived from the PKGBUILD, so let makepkg generate it instead of
# patching it by hand (hand edits drift as soon as a field is added).
(
	cd "$dir"
	makepkg --printsrcinfo >.SRCINFO.tmp
	mv .SRCINFO.tmp .SRCINFO
)

echo "Updated packaging/arch to ${pkgver} (tag v${tag}, sha256 ${sha})"
