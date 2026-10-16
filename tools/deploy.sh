#!/usr/bin/env bash
# Build trassa and deliver it to the router. With argument start, also restart the daemon; with stop, only stop it.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
# The router and how to reach it over SSH (the defaults suit the original setup):
#   TRASSA_ROUTER       the router's address on the home network, 192.168.1.1
#   TRASSA_SSH_KEY      the private key for root on the router, backup/ssh/router_ed25519 if present;
#                       otherwise ssh uses its own defaults (agent, ~/.ssh)
#   TRASSA_KNOWN_HOSTS  the known_hosts file for the router, backup/ssh/known_hosts if present
#   TRASSA_SSH_PORT     the port of Entware's SSH server, 22; with the firmware's own SSH server
#                       enabled, Entware's usually listens on 222
ROUTER_HOST=${TRASSA_ROUTER:-192.168.1.1}
SSH_KEY=${TRASSA_SSH_KEY:-backup/ssh/router_ed25519}
KNOWN_HOSTS=${TRASSA_KNOWN_HOSTS:-backup/ssh/known_hosts}
SSH_PORT=${TRASSA_SSH_PORT:-22}
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 -p "$SSH_PORT")
if [ -r "$SSH_KEY" ]; then SSH+=(-i "$SSH_KEY" -o IdentitiesOnly=yes); fi
if [ -r "$KNOWN_HOSTS" ]; then SSH+=(-o UserKnownHostsFile="$KNOWN_HOSTS"); fi
SSH+=("root@$ROUTER_HOST")

say() { echo ">>> $*"; }

# goenv prints the Go build settings for the router's processor, judged by Entware's architecture.
goenv() {
	local arch
	arch=$("${SSH[@]}" 'PATH=/opt/bin:/opt/sbin:$PATH opkg print-architecture' |
		awk '$1 == "arch" && $2 != "all" && $2 != "noarch" { print $2; exit }')
	case "$arch" in
	aarch64*) echo "GOARCH=arm64" ;;
	mipsel*) echo "GOARCH=mipsle GOMIPS=softfloat" ;;
	mips*) echo "GOARCH=mips GOMIPS=softfloat" ;;
	*)
		echo "Entware architecture '${arch:-unknown}': trassa is built for aarch64, mipsel and mips" >&2
		return 1
		;;
	esac
}

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
goarch=$(goenv)
say "the router's processor: $goarch"
# shellcheck disable=SC2086 # $goarch is a list of variable assignments
env GOOS=linux $goarch CGO_ENABLED=0 go build -trimpath \
	-ldflags "-s -w -X main.version=$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')" \
	-o build/trassa-router ./cmd/trassa

say "delivering to the router"
"${SSH[@]}" 'mkdir -p /opt/etc/trassa/lists /opt/etc/ndm/netfilter.d /opt/etc/ndm/iflayerchanged.d'
# The rules on the router are the owner's own and are edited on the web page. The repository holds
# only the default for a new installation: it is uploaded when the router has no rules yet.
# A copy of the router's rules goes to backup/, which is not in git.
if "${SSH[@]}" 'test -f /opt/etc/trassa/rules.conf'; then
	mkdir -p backup/rules
	"${SSH[@]}" 'cat /opt/etc/trassa/rules.conf' >backup/rules/rules.conf.new
	chmod 600 backup/rules/rules.conf.new
	mv backup/rules/rules.conf.new backup/rules/rules.conf
	say "a copy of the router's rules: backup/rules/rules.conf"
	rules_present=1
else
	rules_present=0
fi
# The new program must run on the router before it replaces the old one: a build for another
# processor stops here, and the router keeps the program it had. Without arguments trassa prints
# its usage. The exit code proves nothing: the shell runs a file the kernel refuses as a script,
# and a syntax error has the same code.
"${SSH[@]}" 'cat > /opt/sbin/trassa.new && chmod 755 /opt/sbin/trassa.new' <build/trassa-router
if ! "${SSH[@]}" '/opt/sbin/trassa.new 2>&1 | grep -q "trassa check <rules file>"'; then
	"${SSH[@]}" 'rm -f /opt/sbin/trassa.new'
	echo "the new program does not run on the router; the old one stays" >&2
	exit 1
fi
"${SSH[@]}" 'mv /opt/sbin/trassa.new /opt/sbin/trassa'
if [ "$rules_present" = 0 ]; then
	put rules/rules.conf /opt/etc/trassa/rules.conf 644
fi
# The page address is set once; after that the file is left alone.
"${SSH[@]}" "test -f /opt/etc/trassa/web.args || echo '-listen $ROUTER_HOST:8090' >/opt/etc/trassa/web.args"
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
