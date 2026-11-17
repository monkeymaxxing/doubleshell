# doubleshell development

Read [the design](docs/design.md) before changing behavior.
[Acceptance contracts](docs/acceptance.md) define completion.
Keep the README, design, and behavior consistent.

## Project facts

- Module: `doubleshell`. Go 1.27.0, toolchain Go 1.27.4.
- Platforms: Linux and macOS, on AMD64 and ARM64. Windows uses WSL.
- License: Apache 2.0. Dependencies retain their upstream licenses.
- `commands.go` owns command parsing, keys, and standard input/output.
- `config.go` owns wg-quick parsing, the saved laptop key, and target selection.
- `agent.go` owns startup, Unix sockets, client requests, and idle lifetime.
- `tunnel.go` owns the WireGuard device, peer updates, handshakes, and tunnel TCP.
- `doubleshell_test.go` owns the real loopback WireGuard tests.

## Commands

Set `GOCACHE`, `GOMODCACHE`, and `GOPATH` to writable temporary directories
when the development environment restricts writes outside the checkout.

```sh
gofmt -l *.go
go vet ./...
go test ./...
go test -race ./...
CGO_ENABLED=0 go build -o /tmp/doubleshell .
```

For cross-platform build checks, set `GOOS` to `linux` or `darwin`, `GOARCH`
to `amd64` or `arm64`, and `CGO_ENABLED=0`. No guest or external server is needed
for the Go tests. Do not format files under `third_party/`.

## Dependency copies

The root `go.mod` replaces every used external module with a copy under
`third_party/`. Keep copies restricted to required files for supported builds.
Keep upstream licenses and a `PRUNED_COPY_RECORD.md` in every module.
[The dependency design](docs/design.md#dependencies) owns the update rule.
Never casually run a dependency upgrade or replace the copies with downloads.

## Names that users read

doubleshell is a general-purpose tool. Write for someone with a few servers
and standard WireGuard tools, who has never heard of any project that uses it.

Use explicit names for commands, flags, files, settings, output columns, and errors.
Use `ssh_port` to distinguish SSH from WireGuard's UDP port. Use `env` only
for environment variables and `config` for configuration. Use `dir` only as a
label whose value is a directory path. Use full words in prose.

## Public terminology

| Term | Meaning |
| --- | --- |
| machine | A server reached through a configured WireGuard peer. |
| laptop | The user's computer that runs doubleshell and OpenSSH. |
| agent | The local doubleshell process that owns the shared WireGuard device. |
| peer | A remote WireGuard public key, endpoint, and allowed private addresses. |
| endpoint | A public address and UDP port that receives WireGuard packets. |
| wg-quick file | The standard WireGuard file named with `--wireguard-config`. `PrivateKey` is optional. |
| laptop key | `~/.config/doubleshell/wireguard_private_key`, written by `create-wireguard-key`. |
| configuration snapshot | The validated local key, addresses, and peers read from the wg-quick file and the laptop key. |
| last WireGuard handshake | The most recent completed WireGuard handshake recorded by the current agent. |
