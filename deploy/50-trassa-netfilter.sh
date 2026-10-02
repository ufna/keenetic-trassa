#!/bin/sh
# Прошивка переписала таблицу mangle — просим trassa вернуть правило перехвата DNS.
[ "$table" = "mangle" ] || exit 0
trassa_p=$(cat /tmp/trassa.pid 2>/dev/null) || exit 0
# Сигнал — только нашему демону: номер процесса мог достаться постороннему.
[ -n "$trassa_p" ] && tr '\0' ' ' <"/proc/$trassa_p/cmdline" 2>/dev/null | grep -q "^/opt/sbin/trassa run " &&
	kill -USR1 "$trassa_p" 2>/dev/null
exit 0
