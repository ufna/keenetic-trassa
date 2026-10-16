#!/bin/sh
# Install or upgrade trassa on a Keenetic or Netcraze router with Entware: takes the package for
# the router's processor from the release, checks it and installs it with opkg. Run it on the
# router as root:
#
#   curl -fsSL https://github.com/ufna/keenetic-trassa/releases/latest/download/install.sh | sh
#
# The release build writes its version below; each release's install.sh installs that release.
set -eu

TRASSA_VERSION=@VERSION@
TRASSA_URL=https://github.com/ufna/keenetic-trassa/releases/download/v$TRASSA_VERSION
PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

die() {
	echo "trassa: $*" >&2
	exit 1
}

[ "$(id -u)" = 0 ] || die "run this on the router as root"
command -v opkg >/dev/null || die "opkg not found: trassa needs Entware on the router"

# The package for the router's processor, by Entware's architecture.
arch=$(opkg print-architecture | awk '$1 == "arch" && $2 != "all" && $2 != "noarch" { print $2; exit }')
case "$arch" in
aarch64*) arch=aarch64-3.10 ;;
mipsel*) arch=mipsel-3.4 ;;
mips*) arch=mips-3.4 ;;
*) die "Entware architecture '${arch:-unknown}': trassa is built for aarch64, mipsel and mips" ;;
esac
pkg=trassa_${TRASSA_VERSION}_$arch.ipk

# fetch <url> <file>: GitHub serves HTTPS only, which Entware's curl can do (opkg install curl).
fetch() {
	if command -v curl >/dev/null; then
		curl -fsSL -o "$2" "$1"
	else
		wget -q -O "$2" "$1"
	fi
}

tmp=$(mktemp -d /tmp/trassa-install.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
echo "trassa $TRASSA_VERSION for $arch: downloading"
if ! { fetch "$TRASSA_URL/$pkg" "$tmp/$pkg" && fetch "$TRASSA_URL/SHA256SUMS" "$tmp/SHA256SUMS"; }; then
	die "cannot download $TRASSA_URL/$pkg; install curl first: opkg update && opkg install curl"
fi
if command -v sha256sum >/dev/null; then
	(cd "$tmp" && grep " $pkg\$" SHA256SUMS | sha256sum -c - >/dev/null) || die "$pkg does not match its checksum"
else
	echo "trassa: sha256sum not found, the checksum is not checked" >&2
fi

# trassa needs iptables and ipset from Entware; opkg finds them in its package lists.
if ! opkg status iptables | grep -q '^Status:.* installed' || ! opkg status ipset | grep -q '^Status:.* installed'; then
	opkg update
fi
# A copy installed from source by tools/deploy.sh is not a package yet, and opkg (all but recent
# Entware builds) refuses to overwrite files that no package owns.
if [ -e /opt/sbin/trassa ] && ! opkg status trassa | grep -q '^Status:.* installed'; then
	opkg install --force-overwrite "$tmp/$pkg"
else
	opkg install "$tmp/$pkg"
fi
echo "trassa $TRASSA_VERSION is installed. It starts in observe mode: see https://github.com/ufna/keenetic-trassa#observe-first-then-route"
