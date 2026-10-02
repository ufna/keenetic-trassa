#!/bin/sh
# У интерфейса изменилось состояние — просим trassa сразу перепроверить туннели.
trassa_p=$(cat /tmp/trassa.pid 2>/dev/null) || exit 0
# Сигнал — только нашему демону: номер процесса мог достаться постороннему.
[ -n "$trassa_p" ] && tr '\0' ' ' <"/proc/$trassa_p/cmdline" 2>/dev/null | grep -q "^/opt/sbin/trassa run " &&
	kill -USR2 "$trassa_p" 2>/dev/null
exit 0
