#!/bin/sh
# The firmware rewrote the mangle table: ask trassa to restore its DNS interception rule.
# shellcheck disable=SC2154 # the firmware passes the rewritten table in $table
[ "$table" = "mangle" ] || exit 0
trassa_p=$(cat /tmp/trassa.pid 2>/dev/null) || exit 0
# Signal only our own daemon: the PID may have been reused by an unrelated process.
[ -n "$trassa_p" ] && tr '\0' ' ' <"/proc/$trassa_p/cmdline" 2>/dev/null | grep -q "^/opt/sbin/trassa run " &&
	kill -USR1 "$trassa_p" 2>/dev/null
exit 0
