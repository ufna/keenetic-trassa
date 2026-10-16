#!/usr/bin/env bash
# Test the release files without a router (needs Go, GNU tar and Docker):
# - the packages for the routers' processors: layout, control fields, processor of the program,
#   and that the same commit gives the same files;
# - Entware's own opkg (x64 build, in a Debian container) with packages of trassa built for x64:
#   a first install with the dependencies, the same version again, an upgrade while trassa runs,
#   removal, an install over a copy from tools/deploy.sh; install.sh's output read through a pipe,
#   as ssh without a terminal reads it, must end;
# - install.sh under busybox ash, the routers' shell: which package it takes for each Entware
#   architecture, Keenetic's "_kn" ones included.
#
#   tools/package-test.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
DEBIAN=debian:bookworm-slim
BUSYBOX=busybox:1.36
ENTWARE=http://bin.entware.net/x64-k3.2/installer

say() { echo ">>> $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

say "release packages"
tools/package.sh 0.0.1 "$work/dist" >/dev/null
cp "$work/dist/SHA256SUMS" "$work/sums"
tools/package.sh 0.0.1 "$work/dist" >/dev/null
cmp -s "$work/sums" "$work/dist/SHA256SUMS" || fail "two builds of the same commit differ"
for arch in "aarch64-3.10:LSB.*aarch64" "mipsel-3.4:LSB.*MIPS" "mips-3.4:MSB.*MIPS"; do
	name=${arch%%:*} machine=${arch##*:}
	pkg=$work/dist/trassa_0.0.1_$name.ipk
	x=$work/x-$name
	mkdir -p "$x"
	[ "$(tar -tzf "$pkg" | tr '\n' ' ')" = "./debian-binary ./data.tar.gz ./control.tar.gz " ] ||
		fail "$name: an opkg package holds debian-binary, data.tar.gz, control.tar.gz in this order"
	tar -xzf "$pkg" -C "$x"
	tar -xzf "$x/control.tar.gz" -C "$x"
	grep -qx "Architecture: $name" "$x/control" || fail "$name: Architecture in control"
	grep -qx "Version: 0.0.1" "$x/control" || fail "$name: Version in control"
	[ -x "$x/postinst" ] && [ -x "$x/prerm" ] || fail "$name: postinst and prerm must be executable"
	# Lists first, then grep: grep -q stops reading early, and pipefail would take that for a failure.
	files=$(tar -tzf "$x/data.tar.gz")
	for f in ./opt/sbin/trassa ./opt/etc/init.d/S99trassa ./opt/etc/ndm/netfilter.d/50-trassa.sh \
		./opt/etc/ndm/iflayerchanged.d/50-trassa.sh ./opt/share/trassa/rules.conf; do
		grep -qx "$f" <<<"$files" || fail "$name: $f missing"
	done
	tar -xzf "$x/data.tar.gz" -C "$x" ./opt/sbin/trassa
	kind=$(file -b "$x/opt/sbin/trassa")
	grep -q "$machine.*statically linked" <<<"$kind" || fail "$name: the program is not a static $machine build: $kind"
done
grep -qx 'TRASSA_VERSION=0.0.1' "$work/dist/install.sh" || fail "install.sh carries the version"

say "Entware's opkg, in a container"
for v in 0.0.1 0.0.2; do
	TRASSA_TARGETS="x64-3.2 GOARCH=amd64" tools/package.sh "$v" "$work/t/v$v" >/dev/null
done
curl -fsS -o "$work/t/opkg" "$ENTWARE/opkg"
curl -fsS -o "$work/t/opkg.conf" "$ENTWARE/opkg.conf"
chmod 755 "$work/t/opkg"
cp tools/package-test/entware.sh "$work/t/"
docker run --rm -v "$work/t:/t:ro" "$DEBIAN" bash /t/entware.sh || fail "Entware flows"

say "install.sh under busybox ash"
cp tools/package-test/arch.sh "$work/dist/"
docker run --rm -v "$work/dist:/t:ro" "$BUSYBOX" sh /t/arch.sh || fail "install.sh's choice of package"

say "all package tests passed"
