#!/usr/bin/env bash
# Проверка, резервная копия и откат роутера Netcraze Giga.
# Работает по локальной сети, интернет не нужен. Подробности — в файле ОТКАТ.md.
set -euo pipefail

ROUTER=${ROUTER:-http://192.168.1.1}
LOGIN=${ROUTER_LOGIN:-admin}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BACKUP=${BACKUP:-$ROOT/backup/2026-10-01}
PASSFILE=$ROOT/backup/.router-pass
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT

die() { echo "ОШИБКА: $*" >&2; exit 1; }
say() { echo ">>> $*"; }

for t in curl jq md5sum sha256sum; do
  command -v "$t" >/dev/null || die "не найдена программа $t"
done

usage() {
  cat <<EOF
Использование: tools/router.sh <команда>

Только чтение:
  check              сравнить состояние роутера с резервной копией
  wait               ждать, пока роутер загрузится и появится интернет
  backup             снять новую резервную копию в backup/<сегодня>
  cli '<команда>'    выполнить команду роутера (осторожно: может менять настройки)
  selftest-upload    проверить загрузку файлов: записать и удалить пробный файл

Изменение прошивки (нужен интернет, спрашивает подтверждение):
  components install|remove <имя>...   изменить набор компонентов и перезагрузить

Откат (каждая команда спрашивает подтверждение):
  trassa-off         остановить trassa и снять его правила (без перезагрузки)
  opkg-off           отключить Entware и перезагрузить: сторонние программы перестают запускаться
  restore-config     вернуть настройки из резервной копии и перезагрузить
  restore-firmware   вернуть прошивку из резервной копии и перезагрузить
  restore-all        прошивка, затем настройки, затем проверка

Резервная копия: $BACKUP
Пароль: переменная ROUTER_PASS, файл backup/.router-pass или ввод с клавиатуры.
EOF
}

password() {
  if [ -n "${ROUTER_PASS:-}" ]; then printf '%s' "$ROUTER_PASS"
  elif [ -r "$PASSFILE" ]; then tr -d '\r\n' < "$PASSFILE"
  else
    local p
    read -r -s -p "Пароль администратора роутера ($LOGIN): " p </dev/tty; echo >&2
    printf '%s' "$p"
  fi
}

reachable() { curl -sS -m 5 -o /dev/null "$ROUTER/auth" 2>/dev/null; }

login() {
  local head realm challenge pass md5 sha code
  head=$(curl -sS -m 10 -c "$JAR" -o /dev/null -D - "$ROUTER/auth") \
    || die "роутер $ROUTER не отвечает. См. ОТКАТ.md, раздел «Роутер не отвечает»."
  realm=$(printf '%s' "$head" | grep -i '^X-NDM-Realm:' | cut -d' ' -f2- | tr -d '\r')
  challenge=$(printf '%s' "$head" | grep -i '^X-NDM-Challenge:' | cut -d' ' -f2- | tr -d '\r')
  [ -n "$challenge" ] || die "роутер не выдал запрос на вход — это точно $ROUTER?"
  pass=$(password)
  md5=$(printf '%s' "$LOGIN:$realm:$pass" | md5sum | cut -d' ' -f1)
  sha=$(printf '%s' "$challenge$md5" | sha256sum | cut -d' ' -f1)
  code=$(curl -sS -m 10 -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -d "{\"login\":\"$LOGIN\",\"password\":\"$sha\"}" "$ROUTER/auth")
  [ "$code" = 200 ] || die "вход не удался (код $code): неверный пароль?"
}

rci_get()  { curl -sS -m 30 -b "$JAR" "$ROUTER/rci/$1"; }
rci_post() { curl -sS -m 60 -b "$JAR" -H 'Content-Type: application/json' -d "$2" "$ROUTER/rci/$1"; }

# Ошибки роутер возвращает с кодом 200, внутри ответа: {"status":[{"status":"error",...}]}
rci_errors() { jq -r '[.. | objects | select(.status? == "error") | .message] | join("; ")' 2>/dev/null; }

cli() {
  local out err
  out=$(rci_post "" "$(jq -n --arg c "$1" '{parse:$c}')")
  err=$(printf '%s' "$out" | rci_errors)
  [ -z "$err" ] || die "команда «$1» отклонена роутером: $err"
  printf '%s\n' "$out"
}

confirm() {
  [ "${YES:-}" = 1 ] && return 0
  local a
  read -r -p "$1 Введите ДА для продолжения: " a </dev/tty
  [ "$a" = "ДА" ] || die "отменено"
}

# upload <локальный файл> <путь на роутере>, например flash:startup-config
upload() {
  local src=$1 dst=$2 size out port err
  [ -r "$src" ] || die "нет файла $src"
  size=$(stat -c %s "$src")
  out=$(rci_post put "$(jq -n --arg f "$dst" --argjson s "$size" '{filename:$f,size:$s}')")
  port=$(printf '%s' "$out" | jq -r '.port.port // empty')
  [ -n "$port" ] || die "роутер не принял загрузку $dst: $(printf '%s' "$out" | rci_errors)"
  say "загрузка $(basename "$src") → $dst ($size байт)"
  curl -sS -m 600 -b "$JAR" -o /dev/null -F "port=$port" -F "Filedata=@$src" "$ROUTER/fui" \
    || die "передача файла оборвалась"
  for _ in $(seq 1 300); do
    out=$(rci_get put)
    err=$(printf '%s' "$out" | rci_errors)
    [ -z "$err" ] || die "роутер отклонил файл $dst: $err"
    printf '%s' "$out" | jq -e '.continued == true' >/dev/null 2>&1 || break
    sleep 1
  done
  say "файл принят"
}

wait_down() {
  say "жду, пока роутер уйдёт в перезагрузку"
  for _ in $(seq 1 60); do reachable || return 0; sleep 2; done
  say "роутер так и не пропал из сети — возможно, перезагрузка уже прошла"
}

wait_up() {
  say "жду роутер (до 10 минут)"
  for _ in $(seq 1 300); do
    if reachable; then say "роутер отвечает"; return 0; fi
    sleep 2
  done
  die "роутер не появился за 10 минут. См. ОТКАТ.md, раздел «Роутер не отвечает»."
}

wait_internet() {
  say "жду интернет (до 5 минут)"
  for _ in $(seq 1 60); do
    login 2>/dev/null && [ "$(rci_get show/internet/status | jq -r '.internet')" = true ] \
      && { say "интернет есть"; return 0; }
    sleep 5
  done
  say "интернет не появился за 5 минут — запустите: tools/router.sh check"
  return 1
}

reboot() {
  rci_post "" '{"system":{"reboot":{}}}' >/dev/null || true
  wait_down
  wait_up
}

row() { echo "$1: $2${3:+ ($3)}"; }

cmd_check() {
  login
  local bad=0 ver now was st
  ver=$(rci_get show/version)

  now=$(printf '%s' "$ver" | jq -r '.release'); was=$(jq -r '.release' "$BACKUP/version.json")
  if [ "$now" = "$was" ]; then row "Версия прошивки" "как было" "$now"; else row "Версия прошивки" "ИЗМЕНЕНО" "$was → $now"; bad=1; fi

  now=$(printf '%s' "$ver" | jq -r '.ndw.components' | tr ',' '\n' | sort)
  was=$(sort "$BACKUP/components-from-version.txt")
  if [ "$now" = "$was" ]; then row "Набор компонентов" "как было" "$(printf '%s\n' "$now" | wc -l) шт."
  else
    row "Набор компонентов" "ИЗМЕНЕНО" "добавлено: $(comm -13 <(printf '%s\n' "$was") <(printf '%s\n' "$now") | tr '\n' ' ') убрано: $(comm -23 <(printf '%s\n' "$was") <(printf '%s\n' "$now") | tr '\n' ' ')"
    bad=1
  fi

  now=$(curl -sS -m 30 -b "$JAR" "$ROUTER/ci/startup-config.txt" | grep -v '^! \$\$\$' | sha256sum | cut -d' ' -f1)
  was=$(grep -v '^! \$\$\$' "$BACKUP/startup-config.txt" | sha256sum | cut -d' ' -f1)
  if [ "$now" = "$was" ]; then row "Настройки" "как было" ""; else row "Настройки" "ИЗМЕНЕНО" "отличаются от резервной копии"; bad=1; fi

  st=$(rci_get show/internet/status | jq -r '.internet')
  if [ "$st" = true ]; then row "Интернет (по данным роутера)" "есть" ""; else row "Интернет (по данным роутера)" "НЕТ" ""; bad=1; fi

  while read -r name was; do
    now=$(rci_get "show/interface/$name" | jq -r '.connected // "no"')
    if [ "$now" = "$was" ]; then row "Туннель $name" "как было" "$now"; else row "Туннель $name" "ИЗМЕНЕНО" "$was → $now"; bad=1; fi
  done < <(jq -r 'to_entries[] | select(.value.type=="Wireguard") | "\(.key) \(.value.connected // "no")"' "$BACKUP/interface.json")

  if getent hosts www.google.com >/dev/null 2>&1; then row "DNS с этого компьютера" "работает" ""; else row "DNS с этого компьютера" "НЕТ" ""; bad=1; fi

  st=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' https://www.youtube.com/generate_204 2>/dev/null || true)
  if [ "$st" = 204 ]; then row "YouTube (через туннель)" "работает" ""; else row "YouTube (через туннель)" "НЕТ" "код ${st:-нет ответа}"; bad=1; fi

  echo
  if [ "$bad" = 0 ]; then say "всё как в резервной копии"; else say "есть отличия от резервной копии (см. выше)"; fi
  return "$bad"
}

cmd_backup() {
  login
  local dir=$ROOT/backup/$(date +%F)
  [ -e "$dir" ] && dir=$dir-$(date +%H%M%S)
  mkdir -p "$dir"; chmod 700 "$ROOT/backup" "$dir"
  rci_get show/version > "$dir/version.json"
  jq -r '.ndw.components' "$dir/version.json" | tr ',' '\n' | sort > "$dir/components-from-version.txt"
  rci_get show/interface > "$dir/interface.json"
  curl -sS -m 30 -b "$JAR" -o "$dir/startup-config.txt" "$ROUTER/ci/startup-config.txt"
  say "скачиваю образ прошивки"
  curl -sS -m 600 -b "$JAR" -o "$dir/firmware.bin" "$ROUTER/ci/firmware"
  chmod 600 "$dir"/*
  say "резервная копия: $dir"
  ls -la "$dir"
}

cmd_opkg_off() {
  confirm "Entware будет отключён, роутер перезагрузится (интернета не будет несколько минут). Сторонние программы на роутере перестанут запускаться."
  login
  cli 'no opkg disk' >/dev/null
  cli 'system configuration save' >/dev/null
  say "Entware отключён, настройки сохранены. Файлы на накопителе роутера не удалены."
  reboot
  wait_internet || true
}

# Запрос с продолжением: роутер отвечает {"continued":true}, пока операция идёт.
rci_continued() {
  local path=$1 body=$2 out
  out=$(rci_post "$path" "$body")
  for _ in $(seq 1 60); do
    printf '%s' "$out" | jq -e '.. | objects | select(.continued? == true)' >/dev/null 2>&1 || break
    sleep 2
    out=$(rci_post "$path" "$body")
  done
  printf '%s\n' "$out"
}

# components install|remove <имя>... — меняет набор компонентов прошивки.
# Роутер сам скачивает пересобранную прошивку (нужен интернет), записывает её и перезагружается.
cmd_components() {
  local action=${1:-}; shift || true
  [ "$action" = install ] || [ "$action" = remove ] || die "нужно: components install|remove <имя>..."
  [ $# -gt 0 ] || die "не указаны компоненты"
  confirm "Набор компонентов прошивки изменится ($action: $*), роутер перезагрузится (интернета не будет несколько минут). Не выключайте питание."
  login
  local body out err last=""
  body=$(printf '%s\n' "$@" | jq -R '{component: .}' | jq -s -c .)
  rci_continued "" '{"components":{"list":{}}}' >/dev/null
  out=$(rci_post "components/$action" "$body")
  err=$(printf '%s' "$out" | rci_errors)
  [ -z "$err" ] || die "роутер отклонил изменение состава: $err"
  say "состав изменён: $action $*"
  out=$(rci_post components/commit '{"reason":"manual"}')
  err=$(printf '%s' "$out" | rci_errors)
  [ -z "$err" ] || die "роутер не начал обновление: $err"
  say "обновление запущено; роутер скачивает и записывает прошивку"
  for _ in $(seq 1 600); do
    out=$(curl -sS -m 5 -b "$JAR" "$ROUTER/rci/components/commit" 2>/dev/null) || break
    out=$(printf '%s' "$out" | jq -c . 2>/dev/null) || break
    if [ "$out" != "$last" ]; then echo "    $out"; last=$out; fi
    err=$(printf '%s' "$out" | rci_errors)
    [ -z "$err" ] || die "обновление остановилось: $err"
    sleep 1
  done
  wait_down
  wait_up
  wait_internet || true
  cmd_check || true
}

# Проверка самой загрузки файлов: пишет маленький файл на накопитель роутера и удаляет его.
cmd_selftest_upload() {
  local tmp name=router-sh-selftest.txt
  login
  tmp=$(mktemp); echo "router.sh selftest $(date)" > "$tmp"
  upload "$tmp" "storage:/$name"; rm -f "$tmp"
  if cli 'ls storage:/' | grep -q "$name"; then say "файл виден на роутере"; else die "файл не появился на роутере"; fi
  cli "erase storage:/$name" >/dev/null
  if cli 'ls storage:/' | grep -q "$name"; then die "файл не удалился"; else say "файл удалён, загрузка работает"; fi
}

cmd_restore_config() {
  confirm "Настройки роутера будут заменены резервной копией, роутер перезагрузится (интернета не будет несколько минут)."
  login
  upload "$BACKUP/startup-config.txt" flash:startup-config
  reboot
  wait_internet || true
}

cmd_restore_firmware() {
  confirm "Прошивка будет заменена образом из резервной копии, роутер перезагрузится (интернета не будет несколько минут). Не выключайте питание."
  login
  upload "$BACKUP/firmware.bin" flash:firmware
  reboot
  wait_internet || true
}

cmd_restore_all() {
  confirm "Будут возвращены прошивка и настройки из резервной копии. Две перезагрузки, около 10 минут без интернета. Не выключайте питание."
  YES=1
  cmd_restore_firmware
  cmd_restore_config
  cmd_check || true
}

# Остановить trassa и снять его правила. Работает по SSH, интернет не нужен.
# Правила снимаются ещё и напрямую, без участия самого trassa: откат не должен зависеть
# от исправности программы, которую откатывают.
cmd_trassa_off() {
  local key=$ROOT/backup/ssh/router_ed25519
  [ -r "$key" ] || die "нет ключа $key"
  ssh -i "$key" -o IdentitiesOnly=yes -o UserKnownHostsFile="$ROOT/backup/ssh/known_hosts" \
    -o BatchMode=yes -o ConnectTimeout=10 root@192.168.1.1 '
      sh /opt/etc/init.d/S99trassa stop
      chmod 644 /opt/etc/init.d/S99trassa
      for p in $(pidof trassa 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
      for t in iptables ip6tables; do
        while $t -w -t mangle -D POSTROUTING -j TRASSA_DNS 2>/dev/null; do :; done
        $t -w -t mangle -F TRASSA_DNS 2>/dev/null
        $t -w -t mangle -X TRASSA_DNS 2>/dev/null
      done
      iptables -w -t mangle -S PREROUTING | grep -- " -j TRASSA$" | sed "s/^-A/-D/" | while read -r r; do iptables -w -t mangle $r; done
      iptables -w -t mangle -F TRASSA 2>/dev/null
      iptables -w -t mangle -X TRASSA 2>/dev/null
      ip rule list | grep "fwmark 0x5452" | while read -r pref rest; do
        ip rule del pref "${pref%:}"
        ip route flush table "${rest##*lookup }" 2>/dev/null
      done
      for s in $(ipset list -n | grep "^trassa_"); do ipset destroy "$s"; done
      rm -f /tmp/trassa.state
      echo "правил trassa в таблицах: $( (iptables-save; ip6tables-save) 2>/dev/null | grep -c TRASSA); правил маршрутизации: $(ip rule list | grep -c "fwmark 0x5452"); списков адресов: $(ipset list -n | grep -c "^trassa_")"
      echo "процессов trassa: $(pidof trassa 2>/dev/null | wc -w)"' \
    || die "не удалось выполнить команду на роутере. Запасной путь: tools/router.sh opkg-off"
  say "trassa остановлен; после перезагрузки роутера сам не запустится"
}

case "${1:-}" in
  check)            cmd_check ;;
  wait)             wait_up; wait_internet ;;
  backup)           cmd_backup ;;
  cli)              [ -n "${2:-}" ] || die "укажите команду"; login; cli "$2" ;;
  selftest-upload)  cmd_selftest_upload ;;
  components)       shift; cmd_components "$@" ;;
  trassa-off)       cmd_trassa_off ;;
  opkg-off)         cmd_opkg_off ;;
  restore-config)   cmd_restore_config ;;
  restore-firmware) cmd_restore_firmware ;;
  restore-all)      cmd_restore_all ;;
  *)                usage; exit 1 ;;
esac
