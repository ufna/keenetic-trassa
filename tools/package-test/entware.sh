#!/bin/bash
# Runs in a Debian container for tools/package-test.sh: Entware (x64) in /opt, then install.sh and
# opkg with the test packages in /t/v0.0.1 and /t/v0.0.2. There is no router here: the daemon cannot
# bind its packet queue and keeps being restarted by its supervisor, which is enough for these flows.
set -u -o pipefail

step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*"
	tail -20 /tmp/trassa.log 2>/dev/null
	exit 1
}
# procs: command lines of trassa's processes (the daemon, the page and the init script's loops).
procs() {
	for p in /proc/[0-9]*; do
		[ "$p" = "/proc/$$" ] && continue
		tr '\0' ' ' <"$p/cmdline" 2>/dev/null
		echo
	done | grep -E '^(/opt/sbin/trassa|sh /opt/etc/init.d/S99trassa)' || true
}
# stale: trassa processes still running a program file that has been replaced.
stale() {
	for p in /proc/[0-9]*; do
		readlink "$p/exe" 2>/dev/null | grep -q '^/opt/sbin/trassa (deleted)' && echo "${p#/proc/}"
	done
}
# install <version>: the release's install.sh, as the README runs it, read through a pipe like ssh
# without a terminal reads it; a supervisor holding the pipe would make this hang. x64 is mapped to
# the test packages' architecture.
install() {
	sed 's/^aarch64\*) arch=aarch64-3.10 ;;/&\nx64*) arch=x64-3.2 ;;/' "/t/v$1/install.sh" |
		timeout 300 sh 2>&1 | timeout 300 cat
}

step "Entware"
apt-get update -qq >/dev/null && apt-get install -y -qq wget >/dev/null 2>&1 || fail "apt-get install wget"
mkdir -p /opt/bin /opt/etc /opt/lib/opkg /opt/tmp /opt/var/lock
cp /t/opkg /opt/bin/opkg && cp /t/opkg.conf /opt/etc/opkg.conf
export PATH=/opt/sbin:/opt/bin:$PATH
opkg update >/dev/null && opkg install entware-opt >/dev/null 2>&1 || fail "Entware's base packages"
echo "Entware architectures: $(opkg print-architecture | tr '\n' ' ')"

# The release files come from GitHub: this curl serves them from /t/v<version> instead.
cat >/usr/bin/curl <<'EOF'
#!/bin/sh
url= out=
while [ $# -gt 0 ]; do
	case "$1" in
	-o) out=$2; shift 2 ;;
	--connect-timeout | --speed-limit | --speed-time) shift 2 ;;
	-*) shift ;;
	*) url=$1; shift ;;
	esac
done
v=${url%/*}
cp "/t/${v##*/}/${url##*/}" "$out"
EOF
chmod 755 /usr/bin/curl

step "first install, with iptables and ipset from Entware"
install 0.0.1 || fail "install.sh: exit $? (124: it hung)"
opkg status trassa | grep -q '^Status:.* installed' || fail "trassa is not an installed package"
trassa version | grep -qx 'trassa 0.0.1' || fail "version: $(trassa version)"
for f in /opt/sbin/trassa /opt/etc/init.d/S99trassa /opt/etc/ndm/netfilter.d/50-trassa.sh \
	/opt/etc/ndm/iflayerchanged.d/50-trassa.sh /opt/etc/trassa/rules.conf /opt/etc/trassa/web.args; do
	[ -e "$f" ] || fail "missing $f"
done
[ -d /opt/etc/trassa/lists ] || fail "missing /opt/etc/trassa/lists"
grep -qx -- '-listen 192.168.1.1:8090' /opt/etc/trassa/web.args ||
	fail "without br0 the page address is 192.168.1.1: $(cat /opt/etc/trassa/web.args)"
cmp -s /opt/etc/trassa/rules.conf /opt/share/trassa/rules.conf || fail "the default rules"
sleep 2
[ -n "$(procs)" ] || fail "trassa did not start"

step "the page of the package answers"
echo "-listen 127.0.0.1:8090" >/opt/etc/trassa/web.args
sh /opt/etc/init.d/S99trassa restart >/dev/null 2>&1 </dev/null
sleep 2
wget -q -O /tmp/page.html http://127.0.0.1:8090/ && grep -q '<title>trassa</title>' /tmp/page.html ||
	fail "no page on 127.0.0.1:8090"

step "the same version again"
out=$(install 0.0.1) || fail "the same version again: exit $?"
echo "$out" | grep -q 'is up to date' || fail "the same version is not left alone: $out"

step "upgrade while trassa runs: the owner's rules and page address stay"
echo "# the owner's edit" >>/opt/etc/trassa/rules.conf
install 0.0.2 || fail "upgrade: exit $? (124: it hung)"
trassa version | grep -qx 'trassa 0.0.2' || fail "upgraded version: $(trassa version)"
grep -q "the owner's edit" /opt/etc/trassa/rules.conf || fail "the upgrade replaced the owner's rules"
grep -qx -- '-listen 127.0.0.1:8090' /opt/etc/trassa/web.args || fail "the upgrade replaced web.args"
sleep 2
[ -z "$(stale)" ] || fail "processes still run the replaced program: $(stale)"
wget -q -O /dev/null http://127.0.0.1:8090/ || fail "no page after the upgrade"

step "removal stops trassa and keeps the rules"
timeout 120 opkg remove trassa >/dev/null || fail "opkg remove: exit $?"
sleep 1
[ ! -e /opt/sbin/trassa ] && [ ! -e /opt/etc/init.d/S99trassa ] || fail "files left after removal"
grep -q "the owner's edit" /opt/etc/trassa/rules.conf || fail "removal took the rules"
[ -z "$(procs)" ] || fail "processes left after removal: $(procs)"

step "install over a copy from tools/deploy.sh"
tar -xzOf /t/v0.0.1/trassa_0.0.1_x64-3.2.ipk ./data.tar.gz | tar -xzf - -C /
opkg status trassa | grep -q '^Status:.* installed' && fail "a copy from deploy.sh is not a package"
install 0.0.2 || fail "install over a copy from deploy.sh: exit $?"
opkg status trassa | grep -q '^Version: 0.0.2' || fail "trassa 0.0.2 is not the installed package"
timeout 120 opkg remove trassa >/dev/null

echo "Entware flows passed"
