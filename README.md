# trassa

Flexible routing for Keenetic routers: send traffic to a VPN tunnel or straight to the ISP by
domain name, mask, negation and address, edit the rules on a web page served by the router
itself.

```
youtube.com googlevideo.com -> vpn        # these domains and their subdomains through the tunnel
!*.ru -> vpn                              # everything except .ru
149.154.160.0/20 -> vpn strict            # never leaks: blocked while the tunnel is down
default direct                            # everything else as before
```

trassa is a single static Go binary (standard library only, no third-party code) that runs on
the router under Entware. It was developed on a Netcraze Giga NC-1012 (a Keenetic Giga KN-1012
rebrand) with firmware 5.2; other Keenetic models with the same firmware family should work but
have not been tested.

## How it works

```
DNS answer to a client ──► kernel queue ──► trassa: name → first matching rule → exit
                                              │
                                              ├─► address sets in the kernel (ipset)
                                              └─► the answer is released unchanged

packet from a client ──► mark by address set ──► routing table of the exit ──► tunnel or ISP
```

- trassa watches the DNS answers the router's DNS proxy sends to the home network. It never
  changes them and never asks DNS anything itself.
- When an answer matches a rule, its addresses go into the address set of the rule's exit.
  From then on the kernel routes new connections to those addresses without trassa.
- An exit is a list of WireGuard tunnels configured in the firmware; the first live one is
  used. When it goes down, the next one takes over.
- Traffic that matches no rule (with `default direct`) gets no mark at all: the router routes
  it exactly as without trassa.

## Requirements

- A Keenetic (or Netcraze) router with the firmware components **OPKG package manager**
  (`opkg`), **Netfilter kernel modules** (`opkg-kmod-netfilter`) and their **add-ons**
  (`opkg-kmod-netfilter-addons`). Installing components reboots the router.
- **Entware** installed on the router's internal storage or a USB drive, with the packages
  `iptables` and `ipset` (`opkg install iptables ipset`), and SSH access as `root` (Entware's
  `dropbear`; key login recommended).
- At least one **WireGuard** connection set up in the firmware (only WireGuard interfaces can be
  exits).
- Clients use the router as their DNS server (the default). A device with its own encrypted DNS
  (DoH/DoT) is only covered by the address rules.
- To build: **Go 1.22** or newer on your computer; `node` is optional (it runs the web page
  tests).

## Build

```sh
make test     # vet, tests, build check
make build    # build/trassa (this computer) and build/trassa-arm64 (the router)
```

`build/trassa-arm64` is for 64-bit ARM routers (`uname -m` on the router prints `aarch64`).
For a MIPS router build with `GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0 go build
./cmd/trassa` (not tested).

## Install

`tools/deploy.sh` builds trassa, copies it to the router over SSH and installs the init script
and the firmware hooks:

```sh
TRASSA_ROUTER=192.168.1.1 TRASSA_SSH_KEY=~/.ssh/id_ed25519 tools/deploy.sh start
```

| Variable | Default | Meaning |
|---|---|---|
| `TRASSA_ROUTER` | `192.168.1.1` | the router's address on the home network |
| `TRASSA_SSH_KEY` | `backup/ssh/router_ed25519`, if present | private key for `root` on the router; otherwise ssh uses its defaults |
| `TRASSA_KNOWN_HOSTS` | `backup/ssh/known_hosts`, if present | known_hosts file for the router |

On the first install the default rules from `rules/rules.conf` are copied to the router; they
change nothing until you add rules. After that the rules on the router are the master copy:
`deploy.sh` never overwrites them and saves a copy to `backup/rules/rules.conf` (not in git).

trassa starts at boot (Entware runs `/opt/etc/init.d/S99trassa`). A supervisor restarts the
daemon if it exits and a watchdog restarts it if it stops answering.

### Observe first, then route

Out of the box the daemon runs in **observe mode**: it reads DNS and writes what it would do
to the log, but changes no routes. Check that the decisions look right, then switch to
**routing mode**:

```sh
ssh root@192.168.1.1
trassa status                         # what trassa sees: DNS answers, rules, devices
trassa why www.youtube.com            # which rule matched and where the traffic goes
echo -route > /opt/etc/trassa/args    # routing mode for the whole home network
sh /opt/etc/init.d/S99trassa restart
```

`-route -source 192.168.1.50` routes only the traffic of one device, which is a good first step.

If the firmware's own domain routing is configured (DNS-based routes for a domain list), it
marks packets before trassa does and wins. Disable those routes in the firmware for trassa to
take over.

## Rules

The rules live in `/opt/etc/trassa/rules.conf` on the router. The first matching rule wins;
`#` starts a comment. `rules/rules.conf` in this repository is the commented default with
examples.

```
exit vpn = Wireguard0, Wireguard1     # an exit: tunnels in order of preference
exit work = office-tunnel             # a tunnel may be named by its description in the firmware

default direct                        # where everything that matches no rule goes

telegram.org t.me -> vpn              # a domain and all its subdomains
=example.com -> vpn                   # only this exact name
*.example.com -> vpn                  # only the subdomains
~^cdn[0-9]+\.example\.net$ -> vpn     # a regular expression (case-insensitive)
91.108.4.0/22 203.0.113.7 -> vpn      # subnets and addresses
example.org -> vpn strict             # strict: blocked while all tunnels of the exit are down
@lists/streaming.txt -> vpn           # conditions from a file in /opt/etc/trassa, one per line
!*.ru -> vpn                          # negation: everything except .ru (a broad rule: keep it last)

test t.me = vpn                       # expectations, checked every time the file is checked
test yandex.ru = direct
```

- `direct` is the ISP, i.e. the router's normal routing. It is always available.
- Without `strict`, traffic of a rule whose tunnels are all down goes direct.
- Internationalized names may be written as they are (`сайт.рф`); they are compared in punycode.
- A file with errors is never applied: the previous rules stay. Warnings (for example, a rule
  that can never match because an earlier one covers it) need an explicit confirmation.

Check a file on your computer with `build/trassa check rules.conf` and ask about a name with
`build/trassa why -f rules.conf www.youtube.com`.

## Web page

`http://<router>:8090` (the address is in `/opt/etc/trassa/web.args`). Sign in with the
router's administrator login and password: the page checks them with the firmware itself, and
the password never leaves the browser (only a response to a one-time challenge does).

On the page: the rules editor with errors and warnings by line, "why" for any name, address or
link, the state of the exits and tunnels, the latest DNS answers and the version history with
one-click restore (the last 20 versions are kept). The page listens on the home network only.

The switch in the header turns trassa off and on. Off, the daemon stops and removes its routes,
and the router routes all traffic as without trassa; trassa stays off after a reboot until it is
switched on again. The page itself keeps working, and the rules can still be edited.

## Commands

```
trassa check <rules file>                     check a rules file
trassa why -f <rules file> <name or address>  decision by a rules file, without the daemon
trassa why <name, address or link>            decision and DNS details from the running daemon
trassa status                                 daemon state
trassa reload                                 reload the rules without stopping
trassa rollback [-y] [-dir directory]         undo the last rules change (run again to redo it)
trassa disable [-dir directory]               turn trassa off: stop the daemon, keep it off after a reboot
trassa enable [-dir directory]                turn trassa on again
trassa run [-rules file] [-only address]      run the daemon in observe mode
trassa run -route [-source address]           run the daemon in routing mode
trassa web [-listen address] [-dir directory] web page for editing the rules
trassa cleanup                                remove the DNS tap and routing rules
```

## Files on the router

| Path | What |
|---|---|
| `/opt/sbin/trassa` | the program |
| `/opt/etc/trassa/rules.conf` | the rules |
| `/opt/etc/trassa/history/` | the last 20 versions of the rules |
| `/opt/etc/trassa/args`, `web.args` | daemon and web page options |
| `/opt/etc/trassa/disabled` | present while trassa is turned off (the page's switch, `trassa disable`) |
| `/opt/var/lib/trassa/state` | addresses learnt from DNS, kept across restarts (written every 30 minutes and on stop) |
| `/opt/etc/init.d/S99trassa` | start at boot, supervision, stop |
| `/opt/etc/ndm/netfilter.d/50-trassa.sh`, `/opt/etc/ndm/iflayerchanged.d/50-trassa.sh` | firmware hooks: rebuild after the firmware rewrites its tables, recheck tunnels when an interface changes |
| `/tmp/trassa.log` | the log, in RAM, trimmed above 1 MB |

In the kernel trassa uses the `mangle` chains `TRASSA` and `TRASSA_DNS`, the queue 5353,
address sets `trassa_*`, marks `0x5452xxxx`, routing rules with priorities 199–299 and routing
tables 541–599. Nothing else in the firmware's tables is changed.

## If something goes wrong

- If the daemon stops or crashes, DNS keeps working (the kernel passes DNS answers by itself)
  and traffic goes as without trassa; `strict` rules block their traffic until the daemon is
  back. The supervisor restarts it within seconds.
- The quickest way back to the router's own routing is the switch on the page or
  `trassa disable` on the router: the daemon removes everything it built and stays off.
- `tools/router.sh trassa-off` stops trassa, disables the start at boot and removes everything
  it built, without relying on trassa itself. The same by hand on the router:

  ```sh
  sh /opt/etc/init.d/S99trassa stop
  chmod 644 /opt/etc/init.d/S99trassa
  for p in $(pidof trassa); do kill -9 $p; done
  for t in iptables ip6tables; do
    while $t -w -t mangle -D POSTROUTING -j TRASSA_DNS 2>/dev/null; do :; done
    $t -w -t mangle -F TRASSA_DNS; $t -w -t mangle -X TRASSA_DNS
  done
  iptables -w -t mangle -S PREROUTING | grep -- " -j TRASSA$" | sed "s/^-A/-D/" | while read -r r; do iptables -w -t mangle $r; done
  iptables -w -t mangle -F TRASSA; iptables -w -t mangle -X TRASSA
  ip rule list | grep "fwmark 0x5452" | while read -r pref rest; do
    ip rule del pref "${pref%:}"
    t=${rest##*lookup }; t=${t%% *}
    case "$t" in 54[1-9] | 5[5-9][0-9]) ip route flush table "$t" ;; esac
  done
  for s in $(ipset list -n | grep "^trassa_"); do ipset destroy "$s"; done
  ```

  Never flush the table `main`: two of trassa's rules point to it.
- If you disabled the firmware's own domain routes for trassa, turn them back on.
- `tools/router.sh` also takes and compares backups of the router's firmware and settings and
  restores them (`backup`, `check`, `restore-config`, `restore-firmware`); run it without
  arguments for help. Backups go to `backup/`, which is not in git.

## Limitations

- IPv4 only: IPv6 traffic is not routed (DNS answers that arrive over IPv6 are still read).
- DNS over UDP through the router: DNS over TCP and encrypted DNS on the devices are not seen.
- Exits are WireGuard tunnels configured in the firmware; trassa does not bring tunnels up or
  down itself.
- Changing the list or the order of exits cuts tunnel connections in progress (the page asks
  for a confirmation); new connections follow the new rules at once.

## Development

```sh
make test
go run ./tools/webpreview         # the web page with sample data at http://127.0.0.1:8091/
```

The code and comments are in English; the Go standard library is the only dependency.
