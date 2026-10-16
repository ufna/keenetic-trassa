## Install

On the router, as `root` (the router needs Entware and the firmware's netfilter components, see [What the router needs](https://github.com/ufna/keenetic-trassa#what-the-router-needs)):

```sh
opkg update && opkg install curl
curl -fsSL https://github.com/ufna/keenetic-trassa/releases/download/v@VERSION@/install.sh | sh
```

The installer takes the package for the router's processor, checks it and installs it with `opkg`, together with `iptables` and `ipset`. An upgrade keeps the rules and settings in `/opt/etc/trassa`. A first install starts in observe mode: see [Observe first, then route](https://github.com/ufna/keenetic-trassa#observe-first-then-route). `releases/latest/download/install.sh` always installs the latest release.

## Files

| File | For |
|---|---|
| `trassa_@VERSION@_aarch64-3.10.ipk` | ARM64 routers (Entware `aarch64-3.10`) |
| `trassa_@VERSION@_mipsel-3.4.ipk` | MIPS little-endian routers, such as MediaTek MT7621 and MT7628 (Entware `mipsel-3.4`) |
| `trassa_@VERSION@_mips-3.4.ipk` | MIPS big-endian routers (Entware `mips-3.4`) |
| `install.sh` | the installer above |
| `SHA256SUMS` | checksums of the files |
