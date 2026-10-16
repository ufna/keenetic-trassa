#!/bin/sh
# Runs in a busybox container for tools/package-test.sh: which package the release's install.sh
# (in /t) takes for each Entware architecture. opkg and curl are stand-ins in /opt/bin, which comes
# first in install.sh's PATH; curl refuses every download, so install.sh stops and names the file it
# wanted.

fail() {
	echo "FAIL: $*"
	exit 1
}

mkdir -p /opt/bin
cat >/opt/bin/curl <<'EOF'
#!/bin/sh
exit 22
EOF
cat >/opt/bin/opkg <<'EOF'
#!/bin/sh
[ "$1" = print-architecture ] && cat /tmp/architectures
exit 0
EOF
chmod 755 /opt/bin/curl /opt/bin/opkg

# check "<print-architecture output>" <the package's architecture, or "none">
check() {
	echo "$1" >/tmp/architectures
	out=$(sh /t/install.sh 2>&1)
	if [ "$2" = none ]; then
		echo "$out" | grep -q 'trassa is built for aarch64, mipsel and mips' || fail "$1: $out"
	else
		echo "$out" | grep -q "/trassa_0.0.1_$2.ipk;" || fail "$1: want $2, got: $out"
	fi
	echo "ok: $(echo "$1" | tr '\n' ' ')-> $2"
}

# Keenetic's Entware lists its own "_kn" architecture after the plain one.
check "arch all 100
arch aarch64-3.10 150
arch aarch64-3.10_kn 200" aarch64-3.10
check "arch all 100
arch noarch 1
arch mipsel-3.4 150
arch mipsel-3.4_kn 200" mipsel-3.4
check "arch all 100
arch mips-3.4 150
arch mips-3.4_kn 200" mips-3.4
check "arch aarch64-3.10_kn 200" aarch64-3.10
check "arch all 100
arch x64-3.2 160" none
check "arch all 100" none
echo "install.sh picks the right package"
