#!/usr/bin/env bash
# Build trassa and deliver it to the router. With argument start, also restart the daemon; with stop, only stop it.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
SSH=(ssh -i backup/ssh/router_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=backup/ssh/known_hosts
	-o BatchMode=yes -o ConnectTimeout=10 root@192.168.1.1)

say() { echo ">>> $*"; }

# put <local file> <path on the router> <mode>: write to a temporary file, then swap it in.
put() {
	"${SSH[@]}" "cat > '$2.new' && chmod $3 '$2.new' && mv '$2.new' '$2'" <"$1"
}

case "${1:-}" in
"" | start | stop) ;;
*)
	echo "Usage: tools/deploy.sh [start|stop]" >&2
	exit 1
	;;
esac

if [ "${1:-}" = stop ]; then
	"${SSH[@]}" 'sh /opt/etc/init.d/S99trassa stop'
	exit 0
fi

say "tests and build"
make test >/dev/null
make build >/dev/null
build/trassa check rules/rules.conf

say "delivering to the router"
"${SSH[@]}" 'mkdir -p /opt/etc/trassa/lists /opt/etc/ndm/netfilter.d /opt/etc/ndm/iflayerchanged.d'
# Rules on the router are edited from the web page: the router's file is the master, the project gets a copy.
# The local file is uploaded only if the router has none yet. The check runs before anything is written
# to the router: an uncommitted local edit must never be silently overwritten.
if "${SSH[@]}" 'test -f /opt/etc/trassa/rules.conf'; then
	"${SSH[@]}" 'cat /opt/etc/trassa/rules.conf' >rules/rules.conf.new
	if cmp -s rules/rules.conf rules/rules.conf.new; then
		rm rules/rules.conf.new
	elif ! git diff --quiet -- rules/rules.conf; then
		mv rules/rules.conf.new rules/rules.conf.router
		echo "ERROR: the rules on the router differ from the uncommitted edit in rules/rules.conf." >&2
		echo "The router's copy is in rules/rules.conf.router. The master file is on the router: move your edit" >&2
		echo "to the page http://192.168.1.1:8090, restore rules/rules.conf (git checkout) and run again." >&2
		echo "Nothing was changed on the router." >&2
		exit 1
	else
		mv rules/rules.conf.new rules/rules.conf
		say "the rules on the router have changed: rules/rules.conf now has the router's copy, consider committing it"
	fi
	rules_present=1
else
	rules_present=0
fi
put build/trassa-arm64 /opt/sbin/trassa 755
if [ "$rules_present" = 0 ]; then
	put rules/rules.conf /opt/etc/trassa/rules.conf 644
fi
# The page address is set once; after that the file is left alone.
"${SSH[@]}" "test -f /opt/etc/trassa/web.args || echo '-listen 192.168.1.1:8090' >/opt/etc/trassa/web.args"
for f in rules/lists/*; do
	if [ -f "$f" ]; then
		put "$f" "/opt/etc/trassa/lists/$(basename "$f")" 644
	fi
done
# Executable: Entware's rc.unslung starts trassa when the router boots.
# tools/router.sh trassa-off removes the execute bit again.
put deploy/S99trassa /opt/etc/init.d/S99trassa 755
put deploy/50-trassa-netfilter.sh /opt/etc/ndm/netfilter.d/50-trassa.sh 755
put deploy/50-trassa-iflayer.sh /opt/etc/ndm/iflayerchanged.d/50-trassa.sh 755

say "checking the rules on the router"
"${SSH[@]}" '/opt/sbin/trassa check /opt/etc/trassa/rules.conf'

if [ "${1:-}" = start ]; then
	say "restarting the daemon"
	"${SSH[@]}" 'sh /opt/etc/init.d/S99trassa restart'
	sleep 2
	"${SSH[@]}" 'sh /opt/etc/init.d/S99trassa status'
fi
