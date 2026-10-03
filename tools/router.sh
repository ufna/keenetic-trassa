#!/usr/bin/env bash
# Check, backup and rollback of a Keenetic/Netcraze router (tested only on a Netcraze Giga NC-1012).
# Works over the local network, no internet needed.
set -euo pipefail

ROUTER=${ROUTER:-http://192.168.1.1}
LOGIN=${ROUTER_LOGIN:-admin}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# The backup restore-* returns to: the first backup taken becomes the baseline.
BACKUP=${BACKUP:-$ROOT/backup/baseline}
PASSFILE=$ROOT/backup/.router-pass
SSH_KEY=${TRASSA_SSH_KEY:-$ROOT/backup/ssh/router_ed25519}
KNOWN_HOSTS=${TRASSA_KNOWN_HOSTS:-$ROOT/backup/ssh/known_hosts}
SSH_PORT=${TRASSA_SSH_PORT:-22} # Entware's SSH server; often 222 when the firmware's own one is on
# The owner's own rollback notes, if kept (docs/ is not in git); otherwise the README.
GUIDE=${ROLLBACK_GUIDE:-docs/ОТКАТ.md}
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT

die() { echo "ERROR: $*" >&2; exit 1; }
guide() { if [ -f "$ROOT/$GUIDE" ]; then echo "See $GUIDE."; else echo "See README.md, \"If something goes wrong\"."; fi; }
say() { echo ">>> $*"; }

for t in curl jq md5sum sha256sum; do
  command -v "$t" >/dev/null || die "program not found: $t"
done

usage() {
  cat <<EOF
Usage: tools/router.sh <command>

Read-only:
  check              compare the router state with the backup
  wait               wait until the router has booted and the internet is up
  backup             take a new backup into backup/<today>
  cli '<command>'    run a router command (careful: it can change settings)
  selftest-upload    test file upload: write and delete a test file

Firmware change (needs internet, asks for confirmation):
  components install|remove <name>...   change the component set and reboot

Rollback (every command asks for confirmation):
  trassa-off         stop trassa and remove its rules (no reboot)
  opkg-off           disable Entware and reboot: third-party programs stop starting
  restore-config     restore the settings from the backup and reboot
  restore-firmware   restore the firmware from the backup and reboot
  restore-all        firmware, then settings, then check

Router: $ROUTER (the ROUTER variable)
Baseline backup: $BACKUP (the BACKUP variable)
Password: the ROUTER_PASS variable, the file backup/.router-pass, or typed at the keyboard.
SSH for trassa-off: TRASSA_SSH_KEY, TRASSA_KNOWN_HOSTS and TRASSA_SSH_PORT (22), else ssh defaults.
EOF
}

password() {
  if [ -n "${ROUTER_PASS:-}" ]; then printf '%s' "$ROUTER_PASS"
  elif [ -r "$PASSFILE" ]; then tr -d '\r\n' < "$PASSFILE"
  else
    local p
    read -r -s -p "Router admin password ($LOGIN): " p </dev/tty; echo >&2
    printf '%s' "$p"
  fi
}

reachable() { curl -sS -m 5 -o /dev/null "$ROUTER/auth" 2>/dev/null; }

login() {
  local head realm challenge pass md5 sha code
  head=$(curl -sS -m 10 -c "$JAR" -o /dev/null -D - "$ROUTER/auth") \
    || die "router $ROUTER is not responding. $(guide)"
  realm=$(printf '%s' "$head" | grep -i '^X-NDM-Realm:' | cut -d' ' -f2- | tr -d '\r')
  challenge=$(printf '%s' "$head" | grep -i '^X-NDM-Challenge:' | cut -d' ' -f2- | tr -d '\r')
  [ -n "$challenge" ] || die "the router sent no login challenge: is $ROUTER really the router?"
  pass=$(password)
  md5=$(printf '%s' "$LOGIN:$realm:$pass" | md5sum | cut -d' ' -f1)
  sha=$(printf '%s' "$challenge$md5" | sha256sum | cut -d' ' -f1)
  code=$(curl -sS -m 10 -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -d "{\"login\":\"$LOGIN\",\"password\":\"$sha\"}" "$ROUTER/auth")
  [ "$code" = 200 ] || die "login failed (code $code): wrong password?"
}

rci_get()  { curl -sS -m 30 -b "$JAR" "$ROUTER/rci/$1"; }
rci_post() { curl -sS -m 60 -b "$JAR" -H 'Content-Type: application/json' -d "$2" "$ROUTER/rci/$1"; }

# The router returns errors with HTTP code 200, inside the response: {"status":[{"status":"error",...}]}
rci_errors() { jq -r '[.. | objects | select(.status? == "error") | .message] | join("; ")' 2>/dev/null; }

cli() {
  local out err
  out=$(rci_post "" "$(jq -n --arg c "$1" '{parse:$c}')")
  err=$(printf '%s' "$out" | rci_errors)
  [ -z "$err" ] || die "the router rejected the command «$1»: $err"
  printf '%s\n' "$out"
}

confirm() {
  [ "${YES:-}" = 1 ] && return 0
  local a
  read -r -p "$1 Type yes to continue: " a </dev/tty
  [ "$a" = "yes" ] || die "cancelled"
}

# upload <local file> <path on the router>, e.g. flash:startup-config
upload() {
  local src=$1 dst=$2 size out port err
  [ -r "$src" ] || die "file not found: $src"
  size=$(stat -c %s "$src")
  out=$(rci_post put "$(jq -n --arg f "$dst" --argjson s "$size" '{filename:$f,size:$s}')")
  port=$(printf '%s' "$out" | jq -r '.port.port // empty')
  [ -n "$port" ] || die "the router did not accept the upload of $dst: $(printf '%s' "$out" | rci_errors)"
  say "uploading $(basename "$src") → $dst ($size bytes)"
  curl -sS -m 600 -b "$JAR" -o /dev/null -F "port=$port" -F "Filedata=@$src" "$ROUTER/fui" \
    || die "the file transfer was interrupted"
  for _ in $(seq 1 300); do
    out=$(rci_get put)
    err=$(printf '%s' "$out" | rci_errors)
    [ -z "$err" ] || die "the router rejected the file $dst: $err"
    printf '%s' "$out" | jq -e '.continued == true' >/dev/null 2>&1 || break
    sleep 1
  done
  say "file accepted"
}

wait_down() {
  say "waiting for the router to go down for the reboot"
  for _ in $(seq 1 60); do reachable || return 0; sleep 2; done
  say "the router never dropped off the network; the reboot may have already happened"
}

wait_up() {
  say "waiting for the router (up to 10 minutes)"
  for _ in $(seq 1 300); do
    if reachable; then say "the router is responding"; return 0; fi
    sleep 2
  done
  die "the router did not come back within 10 minutes. $(guide)"
}

wait_internet() {
  say "waiting for the internet (up to 5 minutes)"
  for _ in $(seq 1 60); do
    login 2>/dev/null && [ "$(rci_get show/internet/status | jq -r '.internet')" = true ] \
      && { say "the internet is up"; return 0; }
    sleep 5
  done
  say "the internet did not come up within 5 minutes; run: tools/router.sh check"
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
  if [ "$now" = "$was" ]; then row "Firmware version" "unchanged" "$now"; else row "Firmware version" "CHANGED" "$was → $now"; bad=1; fi

  now=$(printf '%s' "$ver" | jq -r '.ndw.components' | tr ',' '\n' | sort)
  was=$(sort "$BACKUP/components-from-version.txt")
  if [ "$now" = "$was" ]; then row "Component set" "unchanged" "$(printf '%s\n' "$now" | wc -l) items"
  else
    row "Component set" "CHANGED" "added: $(comm -13 <(printf '%s\n' "$was") <(printf '%s\n' "$now") | tr '\n' ' ') removed: $(comm -23 <(printf '%s\n' "$was") <(printf '%s\n' "$now") | tr '\n' ' ')"
    bad=1
  fi

  now=$(curl -sS -m 30 -b "$JAR" "$ROUTER/ci/startup-config.txt" | grep -v '^! \$\$\$' | sha256sum | cut -d' ' -f1)
  was=$(grep -v '^! \$\$\$' "$BACKUP/startup-config.txt" | sha256sum | cut -d' ' -f1)
  if [ "$now" = "$was" ]; then row "Settings" "unchanged" ""; else row "Settings" "CHANGED" "differ from the backup"; bad=1; fi

  st=$(rci_get show/internet/status | jq -r '.internet')
  if [ "$st" = true ]; then row "Internet (as reported by the router)" "yes" ""; else row "Internet (as reported by the router)" "NO" ""; bad=1; fi

  while read -r name was; do
    now=$(rci_get "show/interface/$name" | jq -r '.connected // "no"')
    if [ "$now" = "$was" ]; then row "Tunnel $name" "unchanged" "$now"; else row "Tunnel $name" "CHANGED" "$was → $now"; bad=1; fi
  done < <(jq -r 'to_entries[] | select(.value.type=="Wireguard") | "\(.key) \(.value.connected // "no")"' "$BACKUP/interface.json")

  if getent hosts www.google.com >/dev/null 2>&1; then row "DNS from this computer" "works" ""; else row "DNS from this computer" "NO" ""; bad=1; fi

  st=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' https://www.youtube.com/generate_204 2>/dev/null || true)
  if [ "$st" = 204 ]; then row "YouTube (via the tunnel)" "works" ""; else row "YouTube (via the tunnel)" "NO" "code ${st:-no response}"; bad=1; fi

  echo
  if [ "$bad" = 0 ]; then say "everything matches the backup"; else say "there are differences from the backup (see above)"; fi
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
  say "downloading the firmware image"
  curl -sS -m 600 -b "$JAR" -o "$dir/firmware.bin" "$ROUTER/ci/firmware"
  chmod 600 "$dir"/*
  if [ ! -e "$ROOT/backup/baseline" ]; then
    ln -s "$(basename "$dir")" "$ROOT/backup/baseline"
    say "this backup is the baseline from now on: backup/baseline"
  fi
  say "backup: $dir"
  ls -la "$dir"
}

cmd_opkg_off() {
  confirm "Entware will be disabled and the router will reboot (no internet for a few minutes). Third-party programs on the router will no longer start."
  login
  cli 'no opkg disk' >/dev/null
  cli 'system configuration save' >/dev/null
  say "Entware disabled, settings saved. Files on the router's storage were not deleted."
  reboot
  wait_internet || true
}

# Request with continuation: the router answers {"continued":true} while the operation is in progress.
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

# components install|remove <name>... changes the firmware component set.
# The router downloads the rebuilt firmware by itself (needs internet), writes it and reboots.
cmd_components() {
  local action=${1:-}; shift || true
  [ "$action" = install ] || [ "$action" = remove ] || die "expected: components install|remove <name>..."
  [ $# -gt 0 ] || die "no components given"
  confirm "The firmware component set will change ($action: $*) and the router will reboot (no internet for a few minutes). Do not turn off the power."
  login
  local body out err last=""
  body=$(printf '%s\n' "$@" | jq -R '{component: .}' | jq -s -c .)
  rci_continued "" '{"components":{"list":{}}}' >/dev/null
  out=$(rci_post "components/$action" "$body")
  err=$(printf '%s' "$out" | rci_errors)
  [ -z "$err" ] || die "the router rejected the component change: $err"
  say "component set changed: $action $*"
  out=$(rci_post components/commit '{"reason":"manual"}')
  err=$(printf '%s' "$out" | rci_errors)
  [ -z "$err" ] || die "the router did not start the update: $err"
  say "update started; the router is downloading and writing the firmware"
  for _ in $(seq 1 600); do
    out=$(curl -sS -m 5 -b "$JAR" "$ROUTER/rci/components/commit" 2>/dev/null) || break
    out=$(printf '%s' "$out" | jq -c . 2>/dev/null) || break
    if [ "$out" != "$last" ]; then echo "    $out"; last=$out; fi
    err=$(printf '%s' "$out" | rci_errors)
    [ -z "$err" ] || die "the update stopped: $err"
    sleep 1
  done
  wait_down
  wait_up
  wait_internet || true
  cmd_check || true
}

# Test of the file upload itself: writes a small file to the router's storage and deletes it.
cmd_selftest_upload() {
  local tmp name=router-sh-selftest.txt
  login
  tmp=$(mktemp); echo "router.sh selftest $(date)" > "$tmp"
  upload "$tmp" "storage:/$name"; rm -f "$tmp"
  if cli 'ls storage:/' | grep -q "$name"; then say "the file is visible on the router"; else die "the file did not appear on the router"; fi
  cli "erase storage:/$name" >/dev/null
  if cli 'ls storage:/' | grep -q "$name"; then die "the file was not deleted"; else say "file deleted, upload works"; fi
}

cmd_restore_config() {
  confirm "The router settings will be replaced with the backup and the router will reboot (no internet for a few minutes)."
  login
  upload "$BACKUP/startup-config.txt" flash:startup-config
  reboot
  wait_internet || true
}

cmd_restore_firmware() {
  confirm "The firmware will be replaced with the image from the backup and the router will reboot (no internet for a few minutes). Do not turn off the power."
  login
  upload "$BACKUP/firmware.bin" flash:firmware
  reboot
  wait_internet || true
}

cmd_restore_all() {
  confirm "The firmware and the settings will be restored from the backup. Two reboots, about 10 minutes without internet. Do not turn off the power."
  YES=1
  cmd_restore_firmware
  cmd_restore_config
  cmd_check || true
}

# Stop trassa and remove its rules. Works over SSH, no internet needed.
# The rules are also removed directly, without trassa itself: the rollback must not depend
# on the program being rolled back working correctly.
cmd_trassa_off() {
  local host=${ROUTER#*://}; host=${host%%[:/]*}
  local ssh=(ssh -o BatchMode=yes -o ConnectTimeout=10 -p "$SSH_PORT")
  if [ -r "$SSH_KEY" ]; then ssh+=(-i "$SSH_KEY" -o IdentitiesOnly=yes); fi
  if [ -r "$KNOWN_HOSTS" ]; then ssh+=(-o UserKnownHostsFile="$KNOWN_HOSTS"); fi
  "${ssh[@]}" "root@$host" '
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
      for c in $(iptables-save -t mangle 2>/dev/null | sed -n "s/^:\(TRASSA_V[0-9]*\) .*/\1/p"); do
        iptables -w -t mangle -F "$c"; iptables -w -t mangle -X "$c"
      done
      iptables -w -t mangle -X TRASSA 2>/dev/null
      ip rule list | grep "fwmark 0x5452" | while read -r pref rest; do
        ip rule del pref "${pref%:}"
        t=${rest##*lookup }; t=${t%% *}
        case "$t" in 54[1-9] | 5[5-9][0-9]) ip route flush table "$t" 2>/dev/null ;; esac
      done
      for s in $(ipset list -n | grep "^trassa_"); do ipset destroy "$s"; done
      rm -f /tmp/trassa.state /tmp/trassa-web.pid
      rm -rf /opt/var/lib/trassa
      echo "trassa rules in tables: $( (iptables-save; ip6tables-save) 2>/dev/null | grep -c TRASSA); routing rules: $(ip rule list | grep -c "fwmark 0x5452"); address sets: $(ipset list -n | grep -c "^trassa_")"
      echo "trassa processes: $(pidof trassa 2>/dev/null | wc -w)"' \
    || die "failed to run the command on the router. Fallback: tools/router.sh opkg-off"
  say "trassa stopped; it will not start by itself after a router reboot"
}

case "${1:-}" in
  check)            cmd_check ;;
  wait)             wait_up; wait_internet ;;
  backup)           cmd_backup ;;
  cli)              [ -n "${2:-}" ] || die "no command given"; login; cli "$2" ;;
  selftest-upload)  cmd_selftest_upload ;;
  components)       shift; cmd_components "$@" ;;
  trassa-off)       cmd_trassa_off ;;
  opkg-off)         cmd_opkg_off ;;
  restore-config)   cmd_restore_config ;;
  restore-firmware) cmd_restore_firmware ;;
  restore-all)      cmd_restore_all ;;
  *)                usage; exit 1 ;;
esac
