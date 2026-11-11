#!/usr/bin/env bash
# Build a Debian package from an already built elctl binary.
#
# Usage: build-deb.sh <debian-arch> <binary> <version> <output-dir>
# Example: build-deb.sh amd64 elctl-amd64 0.8.4 dist
set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo "usage: $0 <debian-arch> <binary> <version> <output-dir>" >&2
    exit 2
fi

ARCH="$1"
BINARY="$2"
VERSION="$3"
OUTDIR="$4"

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

install -d "$ROOT/DEBIAN" \
    "$ROOT/usr/bin" \
    "$ROOT/usr/lib/systemd/system" \
    "$ROOT/etc" \
    "$ROOT/usr/share/doc/eleos"

install -m 0755 "$BINARY" "$ROOT/usr/bin/elctl"
install -m 0644 systemd/eleos.service "$ROOT/usr/lib/systemd/system/eleos.service"
install -m 0644 config.default.yml "$ROOT/etc/eleos.yml"
install -m 0644 LICENSE "$ROOT/usr/share/doc/eleos/copyright"

cat > "$ROOT/DEBIAN/control" <<EOF
Package: eleos
Version: ${VERSION}-1
Architecture: ${ARCH}
Maintainer: nexryai <nexryai@users.noreply.github.com>
Section: net
Priority: optional
Depends: systemd
Homepage: https://github.com/nexryai/eleos
Description: Lightweight nftables firewall that operates via netlink
 eleos is a lightweight and simple firewall that manipulates nftables
 directly through netlink. It does not depend on the nft(8) command and
 needs no external API access to generate or apply rules.
EOF

echo /etc/eleos.yml > "$ROOT/DEBIAN/conffiles"

cat > "$ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF

cat > "$ROOT/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop eleos.service >/dev/null 2>&1 || true
    systemctl disable eleos.service >/dev/null 2>&1 || true
fi
exit 0
EOF

cat > "$ROOT/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF

chmod 0755 "$ROOT/DEBIAN/postinst" "$ROOT/DEBIAN/prerm" "$ROOT/DEBIAN/postrm"

mkdir -p "$OUTDIR"
dpkg-deb --root-owner-group --build "$ROOT" \
    "${OUTDIR}/eleos_${VERSION}-1_${ARCH}.deb"
