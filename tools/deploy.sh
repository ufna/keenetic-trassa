#!/usr/bin/env bash
# Сборка trassa и доставка на роутер. С аргументом start — перезапуск демона, stop — остановка.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
SSH=(ssh -i backup/ssh/router_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=backup/ssh/known_hosts
	-o BatchMode=yes -o ConnectTimeout=10 root@192.168.1.1)

say() { echo ">>> $*"; }

# put <локальный файл> <путь на роутере> <права>: запись во временный файл и подмена.
put() {
	"${SSH[@]}" "cat > '$2.new' && chmod $3 '$2.new' && mv '$2.new' '$2'" <"$1"
}

case "${1:-}" in
"" | start | stop) ;;
*)
	echo "Использование: tools/deploy.sh [start|stop]" >&2
	exit 1
	;;
esac

if [ "${1:-}" = stop ]; then
	"${SSH[@]}" 'sh /opt/etc/init.d/S99trassa stop'
	exit 0
fi

say "тесты и сборка"
make test >/dev/null
make build >/dev/null
build/trassa check rules/rules.conf

say "доставка на роутер"
"${SSH[@]}" 'mkdir -p /opt/etc/trassa/lists /opt/etc/ndm/netfilter.d /opt/etc/ndm/iflayerchanged.d'
put build/trassa-arm64 /opt/sbin/trassa 755
# Правила на роутере правятся со страницы: файл на роутере главный, в проект забирается копия.
# Свой файл кладётся, только если на роутере его ещё нет.
if "${SSH[@]}" 'test -f /opt/etc/trassa/rules.conf'; then
	"${SSH[@]}" 'cat /opt/etc/trassa/rules.conf' >rules/rules.conf.new
	if cmp -s rules/rules.conf rules/rules.conf.new; then
		rm rules/rules.conf.new
	else
		mv rules/rules.conf.new rules/rules.conf
		say "правила на роутере изменены — копия в rules/rules.conf обновлена, её стоит закоммитить"
	fi
else
	put rules/rules.conf /opt/etc/trassa/rules.conf 644
fi
# Адрес страницы задаётся один раз; дальше файл не трогается.
"${SSH[@]}" "test -f /opt/etc/trassa/web.args || echo '-listen 192.168.1.1:8090' >/opt/etc/trassa/web.args"
for f in rules/lists/*; do
	if [ -f "$f" ]; then
		put "$f" "/opt/etc/trassa/lists/$(basename "$f")" 644
	fi
done
# Без права исполнения: после перезагрузки роутера trassa сам не запускается.
put deploy/S99trassa /opt/etc/init.d/S99trassa 644
put deploy/50-trassa-netfilter.sh /opt/etc/ndm/netfilter.d/50-trassa.sh 755
put deploy/50-trassa-iflayer.sh /opt/etc/ndm/iflayerchanged.d/50-trassa.sh 755

say "проверка правил на роутере"
"${SSH[@]}" '/opt/sbin/trassa check /opt/etc/trassa/rules.conf'

if [ "${1:-}" = start ]; then
	say "перезапуск демона"
	"${SSH[@]}" 'sh /opt/etc/init.d/S99trassa restart'
	sleep 2
	"${SSH[@]}" 'sh /opt/etc/init.d/S99trassa status'
fi
