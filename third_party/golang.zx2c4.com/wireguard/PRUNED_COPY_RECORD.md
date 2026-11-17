# Pruned copy of golang.zx2c4.com/wireguard

Module: `golang.zx2c4.com/wireguard`

## Upstream

Version: `v0.0.0-20261024220952-b3bc704ef0ee`

Module hash: `h1:hByBPN/P/BVzJ591rJfvNhdoL94vmBtRbnVw77QJL20=`

## Kept files

This copy keeps the packages and compiled files used by doubleshell on Linux
and macOS, on AMD64 and ARM64, with and without the race detector.
Assembly, headers, embedded files, licenses, and module metadata are retained.
Upstream tests, tools, examples, and unsupported platform files are omitted.
Kept source files match upstream except the correction recorded below.

Kept packages:

- `golang.zx2c4.com/wireguard/conn`
- `golang.zx2c4.com/wireguard/device`
- `golang.zx2c4.com/wireguard/ipc`
- `golang.zx2c4.com/wireguard/ratelimiter`
- `golang.zx2c4.com/wireguard/replay`
- `golang.zx2c4.com/wireguard/rwcancel`
- `golang.zx2c4.com/wireguard/tai64n`
- `golang.zx2c4.com/wireguard/tun`
- `golang.zx2c4.com/wireguard/tun/netstack`

## Changed files

- `conn/bind_std.go`: restore the pooled IP slice to 16 bytes before copying
  an IPv6 destination. An earlier IPv4 send leaves the slice at four bytes.
  Copying before resizing truncates the IPv6 destination, sending to the
  wrong address. The real mixed-family inventory reload test reproduces
  the failure without this correction.

## Applied fixes

- Correct truncated IPv6 destinations after IPv4 sends in `StdNetBind.Send`.
  The inventory reload test covers IPv4 followed by IPv6 over real UDP.
