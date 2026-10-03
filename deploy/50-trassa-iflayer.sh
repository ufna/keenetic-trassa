#!/bin/sh
# An interface changed state: ask trassa to recheck the tunnels right away.
trassa_p=$(cat /tmp/trassa.pid 2>/dev/null) || exit 0
# Signal only our own daemon: the PID may have been reused by an unrelated process.
[ -n "$trassa_p" ] && tr '\0' ' ' <"/proc/$trassa_p/cmdline" 2>/dev/null | grep -q "^/opt/sbin/trassa run " &&
	kill -USR2 "$trassa_p" 2>/dev/null
exit 0
