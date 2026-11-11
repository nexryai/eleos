#!/usr/bin/env bash
# Build the eleos Arch Linux package from the upstream release tarball.
#
# This script must run inside an Arch Linux environment (or the
# archlinux:latest container) with base-devel, go and curl installed. The
# release workflow calls it in a throwaway container so the host needs no Arch
# tooling. aarch64 is cross-compiled on x86_64 (Go produces native binaries,
# and makepkg is told the target CARCH).
#
# Usage: packaging/arch/build.sh <version> <arch> [output-dir]
#   version     release version without the leading "v" (e.g. 0.8.5)
#   arch        x86_64 or aarch64
#   output-dir  directory for the .pkg.tar.zst (default: dist)
set -euo pipefail

usage() {
	echo "usage: $0 <version> <arch> [output-dir]" >&2
	exit 2
}

[[ $# -ge 2 && $# -le 3 ]] || usage

version="${1#v}"
arch="$2"
outdir="${3:-dist}"

case "$version" in
	[0-9]*) ;;
	*) echo "invalid version: $version" >&2; exit 2 ;;
esac
case "$arch" in
	x86_64 | aarch64) ;;
	*) echo "unsupported arch: $arch" >&2; exit 2 ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pkgname=eleos

for tool in makepkg sha256sum curl; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "missing required tool: $tool" >&2
		exit 1
	}
done

mkdir -p "$outdir"
outdir="$(cd "$outdir" && pwd)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

url="https://github.com/nexryai/eleos/archive/refs/tags/v${version}.tar.gz"
tarball="$work/${pkgname}-${version}.tar.gz"
echo "Downloading $url"
curl -fsSL --retry 3 "$url" -o "$tarball"
sha="$(sha256sum "$tarball" | cut -d' ' -f1)"

# Pin a copy of the PKGBUILD to the exact tag being released. The checked-in
# PKGBUILD is kept in sync by update-pkgbuild.sh for users, but the release
# must not depend on that manual bump having happened.
sed -E \
	-e "s/^pkgver=.*/pkgver=${version}/" \
	-e "s/^pkgrel=.*/pkgrel=1/" \
	-e "s/^sha256sums=.*/sha256sums=('${sha}')/" \
	"$script_dir/PKGBUILD" >"$work/PKGBUILD"

cross=false
if [[ "$arch" != "$(uname -m)" ]]; then
	cross=true
fi

# Keep every build artifact inside the temporary directory and make makepkg
# emit the package with the requested architecture name.
{
	echo 'source /etc/makepkg.conf'
	printf 'PKGDEST=%q\n' "$outdir"
	printf 'SRCDEST=%q\n' "$work"
	printf 'BUILDDIR=%q\n' "$work/build"
	echo "PKGEXT='.pkg.tar.zst'"
	if $cross; then
		printf 'CARCH=%q\n' "$arch"
		printf 'CHOST=%q\n' "$arch-unknown-linux-gnu"
	fi
} >"$work/makepkg.conf"

# Build dependencies (base-devel, go) are expected to be installed already (the
# release workflow installs them in the container), so makepkg is not asked to
# resolve them. Packages are signed afterwards by the caller.
makepkg_args=(--config "$work/makepkg.conf" --noconfirm)
if $cross; then
	makepkg_args+=(--nocheck)
fi

cd "$work"
if [[ $EUID -eq 0 ]]; then
	# makepkg refuses to run as root. In the CI container the bind-mounted
	# checkout is owned by uid 1000, so the builder user can write there.
	if ! id -u builder >/dev/null 2>&1; then
		useradd -m builder
	fi
	chown -R builder "$work" "$outdir"
	runuser -u builder -- makepkg "${makepkg_args[@]}"
else
	makepkg "${makepkg_args[@]}"
fi

shopt -s nullglob
packages=("$outdir"/"${pkgname}-${version}"-*.pkg.tar.zst)
shopt -u nullglob
if [[ ${#packages[@]} -eq 0 ]]; then
	echo "makepkg produced no package in $outdir" >&2
	exit 1
fi

printf 'Built:\n'
printf '  %s\n' "${packages[@]}"
