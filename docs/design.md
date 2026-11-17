# Design

doubleshell carries OpenSSH streams through WireGuard entirely inside one
unprivileged process. The program creates no operating-system network interface.
The WireGuard device connects to a small TCP/IP stack supplied by gVisor through
wireguard-go's `tun/netstack` package.

## One connection

OpenSSH starts `doubleshell --wireguard-config FILE proxy-ssh HOST PORT`. The client finds the agent's
Unix socket, starting the agent when necessary. The client sends the target,
then connects standard input and output to the returned byte stream.

The agent selects the peer whose `AllowedIPs` most specifically contain the address.
The agent completes a new handshake directly with the machine's public UDP endpoint.
The agent opens TCP to the private address and requested port inside the tunnel.
OpenSSH then handles authentication, encryption, and server host-key verification.

## Why WireGuard instead of public SSH

A server reached through doubleshell closes public SSH. sshd still runs, but
the firewall lets SSH in only through WireGuard, so the server's one open
port is WireGuard's UDP port. (The firewall does this rather than sshd's
`ListenAddress`, because sshd can start before `wg0` exists at boot and would
then fail to bind the address.) That is safer than SSH on public TCP port 22:

- **WireGuard stays silent.** It answers no packet that does not come from a
  known peer key. A scanner cannot even tell that the port is open, so there
  is nothing to probe. An open SSH port answers everyone with its banner and
  version, so the whole internet knows it is there.
- **There is nothing to guess.** WireGuard has no passwords and no login
  prompt. A packet either carries a valid key or gets no reply, so the logs
  stay quiet instead of filling with guessing attempts.
- **Much less code faces the internet.** WireGuard is a few thousand lines,
  built to be small enough to audit. sshd is far larger, and sshd faults
  that work before login do happen: regreSSHion (CVE-2024-6387, 2024) let an
  attacker run code on the server without logging in. Behind WireGuard, only
  someone who already holds a registered key can reach sshd at all.
- **No open TCP port.** WireGuard uses UDP. A server that serves no website
  then has no TCP port open to the internet, which also shuts out flaws in
  the kernel's own TCP code. CVE-2026-98432 (October 2026) let an attacker
  crash a Linux server through any open TCP port, and in some setups run code
  as root.
- **Two locks in a row.** A shell needs a valid WireGuard key first, then a
  valid SSH key.

The examples use WireGuard's standard UDP port 51820. UDP 443 gets through
more hotel and office networks, because browsers use it for HTTP/3. The README
shows how to accept both, by having the server's firewall forward UDP 443 to
51820 rather than setting `ListenPort = 443`: on Ubuntu 26.04, wg-quick's
AppArmor profile cannot listen below port 1024 (found on a real server,
2026-11-13), and the forward works on every system. The port choice is about
getting through networks, not about security.

## Configuration data

doubleshell reads one input: a standard wg-quick file named with
`--wireguard-config`. Every WireGuard guide and tool already produces that
format, so a person brings no new file type, and the file also works as a
reference for the servers' own `wg0.conf`.

An earlier version also read an inventory through `doubleshell_settings.yml`,
found by searching parent directories, and printed SSH configuration from it.
That format belonged to one project's inventory, which outside users don't
have, and that project stopped using it. It was removed on 2026-11-13: one
input format means one reader, one agent identity rule, and one set of errors.

`config.go` owns the configuration snapshot: the laptop's private key, its
addresses inside WireGuard, the peers, and a fingerprint of every file the
snapshot was read from. Each peer holds a public key, a UDP endpoint, and
allowed address prefixes. The first allowed address names the peer in
messages and in `list-machines`.

`[Interface]` may leave out `PrivateKey` (decided 2026-11-13). The snapshot
then uses `~/.config/doubleshell/wireguard_private_key`, which
`create-wireguard-key` writes. The laptop's secret then lives in one file
instead of a copy in each wg-quick file, and the wg-quick file holds nothing
secret. The cost is a small departure from the standard: such a file works
only with doubleshell. The key file counts toward the fingerprint, so
replacing the key is noticed like any other change.

The reader accepts `PrivateKey`, `Address`, `PublicKey`, `Endpoint`, and
`AllowedIPs`. Other settings fail visibly rather than silently changing their
meaning. Endpoint DNS names resolve before wireguard-go receives a numeric endpoint.

The agent rereads the file on every request and compares fingerprints.
Content checks detect replacements even when timestamps have not changed.
A changed file updates only changed peers; unchanged peers keep their WireGuard
and TCP state. A file that fails to read leaves the running peers and streams unchanged.

When the laptop key or address changes, the agent checks for other connections.
With another connection open, the agent keeps the existing device and returns:
"this laptop's WireGuard key or address changed; close this laptop's other SSH connections through doubleshell, then connect again".
With no other connections, the agent closes the listener and WireGuard device,
then releases the socket lock. A private restart response, `restart_agent`,
tells the waiting client to start another agent. The old process waits for
pending restart replies before exiting. The client has consumed no SSH input
before the restart, and the replacement agent starts with the new identity at once.

## Agent ownership and lifetime

One device owns a laptop's WireGuard sessions for all peers. Separate devices
using the same key pair can replace each other's sessions and break SSH connections.
A shared agent prevents that conflict for each wg-quick file.

Agents are separated by user and by the wg-quick file's full path after
resolving symlinks. Two files must not use the same laptop key against the
same server at once.

The socket is `<per-user directory>/doubleshell/<path-hash>.sock`, where the
hash is the first 32 hexadecimal characters of SHA-256 over that full path.
The per-user directory is `$TMPDIR` on macOS and `$XDG_RUNTIME_DIR` on Linux.
Only the user can create entries there, so another account cannot take the
socket directory's name first. When the variable is unset, the socket
directory is `/tmp/doubleshell-<uid>`.

macOS limits a Unix socket path to 103 bytes. macOS's `$TMPDIR` is
`/var/folders/<2 characters>/<28 characters>/T/` for every user, whatever the
user name, so the socket path is 98 bytes.

The directory must belong to the user with mode `0700`, or doubleshell creates
it that way. Symlinks are rejected. The socket has mode `0600`.

A companion `<path-hash>.sock.lock` file holds an exclusive kernel lock for
the agent's lifetime. Only the lock holder may remove a stale socket.
Concurrent clients can start child processes, but only one child becomes an agent.
A startup pipe reports readiness or the exact startup error to the waiting client.

The agent has no service definition. The client starts a detached child,
`doubleshell --wireguard-config PATH agent`, with the resolved path and the
private environment marker `DOUBLESHELL_INTERNAL_AGENT=1`. The command parser
accepts `agent` only with that marker, and help omits it.
An accepted client counts as active until its request or stream finishes.
Ten minutes without active clients closes the listener, removes the socket,
and closes the WireGuard device. The lock file remains for reuse.
A new agent stays at least three seconds, the time its starting client keeps
trying to connect after the ready report, even with a shorter idle interval.

## Fresh handshakes

`Peer.ExpireCurrentKeypairs()` expires outgoing session keys while retaining
incoming keys and the peer's TCP streams. `Peer.SendHandshakeInitiation(false)`
starts a new exchange. The agent waits for a newer completed handshake timestamp
before opening the requested TCP connection.

A mutex serializes handshake attempts to each peer. WireGuard rejects initiations
inside a 20 ms flood window and rounds initiation timestamps to roughly 16 ms.
The agent spaces initiations from the previous answer by the upstream flood window.
No protocol constants or session internals are changed.

Other open connections continue using the shared stack. The tests compare
server-side handshake timestamps and exchange bytes on the older streams afterward.
A normal EOF in one direction does not end the opposite direction. When server
output ends, the client closes standard output so OpenSSH sees the connection end
even while OpenSSH sends nothing. Standard input keeps flowing until input ends,
including input sent after server output ends. The client waits for input and
output copies to finish.
After server output ends, failed writes of later input to the closed stream end
the client quietly, because OpenSSH already reports the closed connection.
Other copy failures reach the caller and close the socket to unblock the opposite network copy.

## Messages and reachability

A handshake timeout alone cannot distinguish a stopped server, a rejected
key, or blocked UDP. After a five-second timeout on the target, the agent
probes the other peers concurrently for up to five more seconds. Another
answering peer identifies the failed machine. No answers produce the
network-wide message. The README lists the messages and what each means.

Proxy errors add the requested address and SSH port. Network errors also name
the WireGuard endpoint. `proxy-ssh` accepts only an IP address as `HOST`:
OpenSSH passes the `HostName` from the SSH entry, and a name there would have
no peer to match.

`list-machines` probes every peer. The `last_wireguard_handshake` column shows
the last completed handshake in the running device. A failed probe keeps the
earlier time. A new agent starts with no handshake history.

## Server key creation

`create-server-wireguard-key` exists for first-boot data written on a laptop:
macOS's bundled `openssl` (LibreSSL) cannot generate X25519 keys, and the
laptop may have no WireGuard tools. The command prints the pair as JSON and
writes nothing, so no temporary private key is left on disk. A server set up
by hand uses `wg genkey` instead.

The server and laptop commands share one random private-key generator, which
clamps the key exactly as `wg genkey` does. The laptop command owns saving
the key and the replacement checks.

## Dependencies

The root module pins dependency versions and replaces each module with a pruned
copy under `third_party/<module path>/`. Copies contain the packages and compiled
files needed on Linux and macOS, on AMD64 and ARM64, including race builds.
Licenses, assembly, required headers, embedded files, and module metadata stay.
Upstream tests, examples, tools, and unsupported platform files are excluded.

Each copy's `PRUNED_COPY_RECORD.md` records the version, module checksum, retained
packages, changed files, and applied fixes. Source files remain identical to
upstream unless a reproduced vulnerability or high-value fault requires a fix.
A newer upstream version alone is not a reason to replace a copy.

The wireguard-go copy corrects a reproduced IPv6 destination truncation in
`StdNetBind.Send`: resize a pooled IP slice before copying 16 bytes into the slice.
The loopback reload test sends to IPv4 and IPv6 endpoints through one device.
No other retained dependency file differs from upstream.

The implementation uses Go's standard library for keys, process startup, Unix
sockets, hashing, and byte streams. Userspace WireGuard requires the included external modules. Builds require no C compiler or C libraries.

## Releases

doubleshell uses semantic versioning. The first release is 0.1.0. A patch
release holds fixes and documentation changes and needs nothing from its
users. New features come in a minor release. Before 1.0.0, a minor release
may also rename a command or a setting, and its release notes say what to
change. From 1.0.0, a rename waits for a major release.

`doubleshell version` prints `doubleshell` and the version. A development
build prints `0.1.0-dev`, the default of the `version` variable in
`commands.go`. The release build sets the variable with `-ldflags -X`, and
the release workflow refuses to publish the development version. Each release
holds one archive for Linux and macOS on AMD64 and ARM64, built without
cgo and with `-trimpath`. Two builds of one commit give identical archives,
and each archive carries a build attestation and a line in `SHA256SUMS`.

## Tests

The Go suite creates other wireguard-go devices and TCP echo listeners inside
netstack. Real UDP on loopback carries encrypted WireGuard packets between devices.
The tests need no admin rights, network-device installation, or external server.

The suite checks bidirectional streams, concurrent streams, fresh handshakes,
file reloads, a file without `PrivateKey`, all cause messages, idle exit and
restart, socket directory permissions, laptop key creation and replacement,
and server key pairs without disk writes. Subprocess startup runs through the
actual executable, with a shorter idle interval in test processes.
