#!/usr/bin/env bash
# Build the release files: an opkg package of trassa for each router processor, install.sh for the
# router and SHA256SUMS. Needs Go and GNU tar.
#
#   tools/package.sh <version> [directory]      e.g. tools/package.sh 0.1.0 (into dist/)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VERSION=${1:-}
OUT=${2:-dist}
if ! [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "Usage: tools/package.sh <version> [directory], the version as 0.1.0" >&2
	exit 1
fi
# The same package from the same commit: file times are the commit's.
EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
umask 022

# The router processors as Entware names them, and the Go build settings for each.
TARGETS=(
	"aarch64-3.10 GOARCH=arm64"
	"mipsel-3.4 GOARCH=mipsle GOMIPS=softfloat"
	"mips-3.4 GOARCH=mips GOMIPS=softfloat"
)

# targz <directory> <file>: the directory's contents as ./..., owned by root, in name order.
targz() {
	tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" --format=gnu \
		-C "$1" -cf - . | gzip -9n >"$2"
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
rm -rf "$OUT"
mkdir -p "$OUT"

for target in "${TARGETS[@]}"; do
	read -r arch goenv <<<"$target"
	pkg=$work/$arch
	data=$pkg/data
	mkdir -p "$data/opt/sbin" "$data/opt/etc/init.d" "$data/opt/etc/ndm/netfilter.d" \
		"$data/opt/etc/ndm/iflayerchanged.d" "$data/opt/share/trassa" "$pkg/control"
	# shellcheck disable=SC2086 # $goenv is a list of variable assignments
	env GOOS=linux CGO_ENABLED=0 $goenv go build -trimpath -buildvcs=false \
		-ldflags "-s -w -X main.version=$VERSION" -o "$data/opt/sbin/trassa" ./cmd/trassa
	install -m 755 deploy/S99trassa "$data/opt/etc/init.d/S99trassa"
	install -m 755 deploy/50-trassa-netfilter.sh "$data/opt/etc/ndm/netfilter.d/50-trassa.sh"
	install -m 755 deploy/50-trassa-iflayer.sh "$data/opt/etc/ndm/iflayerchanged.d/50-trassa.sh"
	# The default rules: postinst copies them to /opt/etc/trassa on a first install only.
	install -m 644 rules/rules.conf "$data/opt/share/trassa/rules.conf"

	cat >"$pkg/control/control" <<EOF
Package: trassa
Version: $VERSION
Depends: iptables, ipset
Source: https://github.com/ufna/keenetic-trassa
License: MIT
Section: net
URL: https://github.com/ufna/keenetic-trassa
Maintainer: https://github.com/ufna/keenetic-trassa/issues
Architecture: $arch
Installed-Size: $(find "$data" -type f -printf '%s\n' | awk '{ s += $1 } END { print s }')
Description:  Flexible routing for Keenetic routers: sites through a WireGuard tunnel or straight
 to the ISP by domain name, mask and address, with the rules edited on a web page.
EOF
	install -m 755 deploy/opkg/postinst deploy/opkg/prerm "$pkg/control/"
	targz "$data" "$pkg/data.tar.gz"
	targz "$pkg/control" "$pkg/control.tar.gz"
	echo 2.0 >"$pkg/debian-binary"
	# An opkg package is a gzipped tar of these three, in this order (as OpenWrt's ipkg-build makes it).
	tar --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" --format=gnu -C "$pkg" \
		-cf - ./debian-binary ./data.tar.gz ./control.tar.gz | gzip -9n >"$OUT/trassa_${VERSION}_$arch.ipk"
done

sed "s/@VERSION@/$VERSION/" deploy/install.sh >"$OUT/install.sh"
chmod 755 "$OUT/install.sh"
(cd "$OUT" && sha256sum -- *.ipk install.sh >SHA256SUMS)
ls -l "$OUT"
