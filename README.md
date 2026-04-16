# sing-box-xhttp

Fork of [sing-box](https://github.com/SagerNet/sing-box) (universal proxy platform) with three embedded protocol bridges for [VPN4TV Native](https://github.com/VPN4TV/vpn4tv-native).

## What this fork adds

sing-box does not natively support xhttp/splithttp transports, Outline-style SIP002 prefix Shadowsocks, or AmneziaWG obfuscation. This fork embeds three Go libraries alongside sing-box in a single `libbox.aar` binary so the VPN4TV Android client can handle all of them without running multiple processes.

### 1. Xray bridge (`experimental/libbox/xray.go`)

Embeds [xray-core](https://github.com/XTLS/Xray-core) as a Go dependency. Starts an Xray instance with SOCKS5 inbound on `127.0.0.127:<port>` for each xhttp/splithttp outbound; sing-box routes to it via a socks outbound.

### 2. Outline bridge (`experimental/libbox/outline.go`)

Embeds [outline-sdk](https://github.com/Jigsaw-Code/outline-sdk). Handles Shadowsocks with SIP002 `?prefix=` (TLS prefix obfuscation) which neither sing-box nor xray-core support. Same SOCKS5-per-endpoint pattern, port offset +1000.

### 3. wireproxy-awg bridge (`experimental/libbox/wireproxy.go`)

Embeds [wireproxy](https://github.com/pufferffish/wireproxy) + [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go). Runs userspace AmneziaWG devices (with Jc/Jmin/Jmax/H1-H4/S1-S2 obfuscation) as SOCKS5 endpoints, port offset +2000.

### Shared infrastructure

- All three bridges share one `libgojni.so`, one Go runtime, one `VpnService.protect(fd)` callback via `xrayPlatformWrap`
- `wireproxy_protect_linkname.go` — `go:linkname` shim to inject `protect(fd)` into amneziawg-go's unexported `controlFns`
- `sigsys_handler.c` — JNI shim for SIGSYS on Android 9 arm32 (Go 1.23+ `clock_gettime64` workaround)

## Building

Requires Go 1.23+, gomobile, Android NDK 28+, OpenJDK 17.

```bash
# Install gomobile (SagerNet fork)
make lib_install

# Build libbox.aar with arm + arm64
PATH=$PATH:~/go/bin \
  ANDROID_HOME=~/Library/Android/sdk \
  ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/28.2.13676358 \
  go run ./cmd/internal/build_libbox -target android -platform android/arm,android/arm64
```

Output: `libbox.aar` (~56 MB with both ABIs). Copy to `vpn4tv-native/app/libs/`.

**Important**: always include arm64 — Play Store ABI splits deliver arm64-only APKs to modern devices; an arm-only libbox crashes with `UnsatisfiedLinkError` on every arm64 install.

## Upstream

Based on [sing-box](https://github.com/SagerNet/sing-box) v1.14.x by SagerNet. Upstream remote is `upstream` for future merge-backs.

## License

GPLv3 (same as upstream sing-box).

Embedded libraries under their respective licenses:
- Xray-core — MPLv2
- Outline SDK — Apache 2.0
- amneziawg-go — MIT
- wireproxy — ISC
