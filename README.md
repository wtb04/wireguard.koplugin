# WireGuard for KOReader

A [KOReader](https://github.com/koreader/koreader) plugin to bring a WireGuard® VPN up and down from the menu.

I am not affiliated with KOReader or with WireGuard. Just a wrapper I made for my own use.

Tested only on a **Kobo Clara Colour**. Other Kobo models will probably work, other devices YMMV.

> **Looking for something easier?** If you just want a VPN on your e-reader and don't specifically need WireGuard, the [Tailscale plugin for KOReader](https://github.com/victoria-riley-barnett/koreader-tailscale) ships with an install script and works out of the box, no cross-compiling required.

## Screenshots

| Menu | Config picker | Status |
|---|---|---|
| ![Menu location](screenshots/settings.png) | ![Config picker](screenshots/config-picker.png) | ![Status screen](screenshots/status.png) |

## Compatibility

| Device | Status | Notes |
|---|---|---|
| Kobo Clara Colour | Tested | My own device |
| Other Kobo models | Expected to work | Reports welcome |
| Kindle | Untested | I have no way to test this. If you got it working, let me know how so I can update this |
| Android | Not the target | |

## 1. Build the binaries

WireGuard binaries don't ship on Kobo devices, and at the time of writing there are no pre-built binaries available from reputable sources, so you have to cross-compile them yourself. Kobo kernels are also too old to include the WireGuard kernel module, which is why `wireguard-go` (the userspace implementation) is required alongside `wg`.

Sources:

- `wg` from [wireguard-tools](https://github.com/WireGuard/wireguard-tools)
- `wireguard-go` from [wireguard-go](https://github.com/WireGuard/wireguard-go)

Find your arch first (see [SSH](#ssh) below):

```sh
ssh -p 2222 root@<e-reader> 'uname -m'
```

On a Clara Colour that's `armv7l`, so the targets below are armv7. Adjust if yours differs.

I built mine with Docker. The `wg` build runs a Debian armv7 container under emulation, which is slower but avoids needing a cross-compiler. `wg` is small so it still only took about 30 seconds:

```sh
# wg
docker run --rm --platform linux/arm/v7 -v "$PWD:/out" -w /src debian:bookworm-slim sh -c '
  apt-get update && apt-get install -y --no-install-recommends \
    git make gcc libc6-dev ca-certificates
  git clone https://github.com/WireGuard/wireguard-tools
  cd wireguard-tools/src
  make LDFLAGS=-static
  cp wg /out/
'

# wireguard-go
docker run --rm -v "$PWD:/out" -w /src golang:latest sh -c '
  git clone https://github.com/WireGuard/wireguard-go
  cd wireguard-go
  GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -o /out/wireguard-go
'
```

## 2. Put the binaries on the device

```sh
scp -P 2222 wg wireguard-go root@<e-reader>:/usr/bin/
ssh -p 2222 root@<e-reader> 'chmod +x /usr/bin/wg /usr/bin/wireguard-go'
```

Confirm `/dev/net/tun` exists:

```sh
ssh -p 2222 root@<e-reader> 'ls -l /dev/net/tun'
# if missing:
ssh -p 2222 root@<e-reader> 'mkdir -p /dev/net && mknod /dev/net/tun c 10 200'
```

## 3. Install the plugin

Download the latest `wireguard.koplugin-vX.Y.Z.zip` from the [releases page](../../releases/latest) and unzip it into your KOReader plugins folder, e.g.:

```
/mnt/onboard/.adds/koreader/plugins/wireguard.koplugin/
```

(Or clone this repo into your plugins folder as `wireguard.koplugin/`)

Put your `.conf` files in the `configs/` folder:

```
.../wireguard.koplugin/configs/
```

The filename (without `.conf`) becomes the interface name.

Restart KOReader. Plugin appears under **Network > WireGuard VPN**.

## Use

The plugin lives under Network > WireGuard VPN. Tap the first item to bring the tunnel up or down, picking a config if there's more than one. Tap Status to see which binaries are present, the current `wg show` output and the configs the plugin found.

### Gestures and profiles

Four actions are registered with KOReader's Dispatcher and show up under Gesture Manager > General (or in any profile):

- WireGuard connect
- WireGuard disconnect
- WireGuard toggle
- WireGuard status

## SSH

If you haven't enabled SSH on your e-reader yet, follow this guide: <https://dmpop.github.io/koreader-compendium/16-ssh/>.

## FAQ and troubleshooting

**Why not the normal WireGuard kernel module?**

Kobo kernels are too old to include it, so there is nothing to enable.

**Why wireguard-go?**

It is the userspace implementation, so it runs without the kernel module. It does need `/dev/net/tun`, which step 2 covers.

**Which devices work?**

See [Compatibility](#compatibility).

**Where do the .conf files go?**

In the plugin's own `configs/` folder:

```
/mnt/onboard/.adds/koreader/plugins/wireguard.koplugin/configs/
```

The filename without `.conf` becomes the interface name.

**Does it work with Calibre?**

Yes, that is what I built it for. Bring the tunnel up and KOReader's Calibre plugin can reach the Calibre instance on your home network without it being exposed to the internet.

**Why not Tailscale?**

If you do not specifically need WireGuard, use the Tailscale plugin linked at the top. I already ran a WireGuard server at home, so adding a second overlay network just for the e-reader was not worth it.

**The tunnel does not come up**

Open Status first. It shows which binaries are present, the current `wg show` output and the configs the plugin found, which usually points straight at the cause. After that, check:

- `/dev/net/tun` exists
- `uname -m` on the device matches the arch you built the binaries for
- the config file ends in `.conf` and sits in the folder above

**Names stop resolving after connecting**

Bringing the tunnel up writes the DNS from your config into `/etc/resolv.conf` and keeps the original at `/tmp/resolv.wg.bak`. Disconnecting puts it back. If a disconnect never ran, because KOReader was killed or the battery went flat, the old DNS is still in that backup:

```sh
cp /tmp/resolv.wg.bak /etc/resolv.conf
```

`/tmp` is cleared on reboot, so do this before restarting the device.

## License

MIT, see [LICENSE](LICENSE).

Made by [Wouter ten Brinke](https://woutertenbrinke.nl).

## Trademarks

"[WireGuard](https://www.wireguard.com/)" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld. This project is not affiliated with, endorsed by or sponsored by the WireGuard project, Jason A. Donenfeld, zx2c4 or Edge Security LLC.
