# Acceptance contracts

Required workflows and outcomes:

- OpenSSH starts the agent automatically, then carries bytes in both directions
  through a userspace WireGuard tunnel to the requested TCP port. A normal EOF
  in one direction leaves the opposite direction open until it ends.
  Server output ending closes the client's standard output so idle OpenSSH sees EOF;
  standard input keeps flowing until input ends.
  After server output ends, failed writes of later input to the closed stream end the client quietly.
  Other copy errors reach the caller and close the socket to unblock network traffic.
- Concurrent connections share one device per user and canonical wg-quick file
  path. Every new connection completes a new handshake without breaking older streams.
- File changes add, update, and remove peers on the existing device before the
  next connection. A file that fails to read leaves the running peers and streams unchanged.
- A wg-quick file without `PrivateKey` uses the saved laptop key. Replacing that
  key counts as a change of the laptop's identity.
- `list-machines` lists configured peers, their endpoints, and actual last
  completed WireGuard handshake times. No unverified reachability claim replaces a timestamp.
- A changed laptop key or address replaces an agent immediately when no other
  connections are open. With open connections, an error directs the user to close
  the other SSH connections and connect again.
- An idle agent exits after ten minutes. A later connection starts an agent again.
  The agent process uses the command word `agent`, which is accepted only with
  the internal environment marker.
  The socket directory belongs to the user and has mode `0700`.
- Key creation protects the directory and file and refuses implicit replacement.
- Server key creation prints exactly one JSON key pair, with a clamped private
  key and matching public key, and writes nothing to disk.
- Errors identify the requested address and SSH port. Network failures
  include the WireGuard endpoint. Cause messages give the applicable next step.
- The [README](../README.md)'s quick start takes a person or a coding agent from nothing to
  SSH with public SSH closed, on Debian, Ubuntu, and the RHEL family (proved on
  Ubuntu 26.04 and Rocky Linux 10.2, 2026-11-13).

Exclusions:

- No system VPN, routing changes, service installation, relay network, or UDP bypass.
- No SSH authentication or host-key verification inside doubleshell. OpenSSH owns
  those checks. Use SSH forwarding to reach other services.
- No native Windows executable. Use Linux inside WSL.
- wg-quick hooks, DNS settings, preshared keys, and interface-management options
  are not supported.

Completion means the real loopback WireGuard tests pass, `go vet ./...` passes,
and doubleshell's own Go files have no `gofmt` changes. Linux and macOS builds
must compile for AMD64 and ARM64 without cgo. Release archives are separate work.

See [the design](design.md) and [contributor guidance](../AGENTS.md).
