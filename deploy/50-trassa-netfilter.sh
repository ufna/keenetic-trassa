#!/bin/sh
# Прошивка переписала таблицу mangle — просим trassa вернуть правило перехвата DNS.
[ "$table" = "mangle" ] && [ -f /tmp/trassa.pid ] && kill -USR1 "$(cat /tmp/trassa.pid)" 2>/dev/null
exit 0
