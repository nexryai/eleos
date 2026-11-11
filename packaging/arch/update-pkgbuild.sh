#!/usr/bin/env bash
# Update pkgver and sha256sums in packaging/arch/{PKGBUILD,.SRCINFO} for a
# release. Run this before tagging, then commit the result with the release.
#
# Usage: packaging/arch/update-pkgbuild.sh <version>
set -euo pipefail

[[ $# -eq 1 ]] || {
	echo "usage: $0 <version>" >&2
	exit 2
}

version="${1#v}"
case "$version" in
	[0-9]*) ;;
	*) echo "invalid version: $version" >&2; exit 2 ;;
esac

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
url="https://github.com/nexryai/eleos/archive/refs/tags/v${version}.tar.gz"

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
# would make the new version look like a rebuild of the previous one).
sed -E -i \
	-e "s/^pkgver=.*/pkgver=${version}/" \
	-e "s/^pkgrel=.*/pkgrel=1/" \
	-e "s/^sha256sums=.*/sha256sums=('${sha}')/" \
	"$dir/PKGBUILD"

# .SRCINFO is derived from the PKGBUILD, so let makepkg generate it instead of
# patching it by hand (hand edits drift as soon as a field is added).
(
	cd "$dir"
	makepkg --printsrcinfo >.SRCINFO.tmp
	mv .SRCINFO.tmp .SRCINFO
)

echo "Updated packaging/arch to ${version} (sha256 ${sha})"
