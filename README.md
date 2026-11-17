# doubleshell

doubleshell lets you close your servers' SSH port to the internet and still
SSH to them exactly as before.

(This README says "laptop" for the computer you work from. A desktop works
just the same.)

## Why close SSH to the internet?

A server with SSH open on port 22 talks to anyone who connects. Bots scan the
whole internet around the clock, find port 22, and try to log in, so your logs
fill with their attempts. A good SSH key keeps the bots out. But every open
TCP port is a way in for bugs that strike before any login:

- In 2024, regreSSHion let attackers into sshd without logging in.
- In October 2026, CVE-2026-98432, a flaw in Linux's own TCP code, let
  attackers crash a server through any open TCP port, and in some setups take
  it over.

A server with no website, whose only open port is [WireGuard](https://www.wireguard.com/)'s, has no TCP port
open to the internet at all, so neither flaw could reach it.

## Keys: public and private

WireGuard, like SSH, proves who is who with key pairs. A key pair is two
matching keys:

- The **private key** is a secret. It stays on its own machine.
- The **public key** is made from the private key. It is safe to share, like
  your name. It can check that something came from the holder of the matching
  private key, but it can't be used to pretend to be them.

If you log in to servers with an SSH key, you already use this. For example,
the private key might be `~/.ssh/id_ed25519` on your laptop, and the server
lists the matching public key, from `~/.ssh/id_ed25519.pub`, in its
`~/.ssh/authorized_keys` file.

WireGuard keys are separate from SSH keys:

- Your laptop gets one WireGuard key pair, and each server gets its own.
- You give the laptop's public key to each server, so the server knows the
  laptop.
- You give each server's public key to the laptop, so the laptop knows the
  server.
- Each private key stays on its own machine. The one exception is a new
  server's key made on the laptop and sent in the server's first-boot data:
  [A server key in first-boot data](#a-server-key-in-first-boot-data) says
  what that exposes.

## How WireGuard helps

WireGuard is a small, modern tool for encrypted connections between machines.
The part that matters here: before the server answers anything, the laptop
must prove that it holds the private key for one of the public keys the server
was given. A packet without that proof gets no reply at all: no error,
nothing. To a scanner, the port looks like nothing is there. After the proof,
everything between the two machines is encrypted.

So you put SSH behind WireGuard. The server's firewall lets SSH in only
through WireGuard, and WireGuard's port is the only one open to the internet.
A stranger can't even reach sshd. Getting in now takes your laptop's
WireGuard private key first, and then whatever SSH already asks for, such as
your SSH key.

## What doubleshell adds

Using WireGuard usually means running a VPN on your laptop. That takes admin
rights, adds a network device, changes your network settings, and can clash
with other VPNs. doubleshell instead runs WireGuard inside itself, only for
SSH. You install nothing else, you need no admin rights, and the rest of your
laptop's traffic stays as it is.

You keep using SSH the way you do now: `ssh web01`, `scp`, `rsync`, and
editors that work over SSH. doubleshell plugs into [OpenSSH](https://www.openssh.com/) as its
`ProxyCommand`, which is SSH's built-in way to let another program carry the
connection.

### doubleshell and Tailscale

[Tailscale](https://tailscale.com/) and similar mesh networks are another way to keep SSH off the
internet. Every device signs in, and they all join one network. Setup is
quick, and devices connect through almost any network with no open port. The
cost is control:

- Laptops, phones, and servers end up on the same network, so one lost or
  compromised device can reach a lot.
- Who can reach what is often set by clicking in a web console rather than in
  reviewed code, and it drifts as devices come and go.
- An outside service decides which keys your servers trust.

With doubleshell, each laptop's WireGuard file lists exactly the servers it
can reach, and each server's WireGuard file lists exactly the laptops it
accepts. Only SSH travels. Every one of those files can live in your
repository and change only through review.

Servers that talk to each other privately, such as an app server and its
database, don't need a mesh either: plain WireGuard between them does that.
doubleshell works alongside such a network, as the way a laptop gets in for
SSH. The [Monkeymaxxing Stack](https://github.com/monkeymaxxing/monkeymaxxing-stack)
does exactly this: its servers share their own WireGuard network, and each
person's laptop uses doubleshell to SSH to their admin server on it.

[Why WireGuard instead of public SSH](docs/design.md#why-wireguard-instead-of-public-ssh)
goes into more detail.

## Set it up with your coding agent

The easiest way to set up doubleshell is to have your coding agent do it,
such as [Claude Code](https://claude.com/claude-code) or [Codex](https://openai.com/codex/). The agent follows the steps in this README and
checks each one before the next. It asks you when it needs something only you
can give, such as a login to your hosting provider.

Paste this into your agent, with your own servers in place of the example:

```text
Set up doubleshell so I can SSH to my servers with SSH closed to the
internet. Follow the README at https://github.com/monkeymaxxing/doubleshell,
including its "For coding agents" checklist.

My servers: web01 at 203.0.113.11 (list all of yours). I log in to them
as root (or name your user) with my current SSH setup.

Start with one server, and pass each step's check before the next.
Keep my current SSH entry for each server working until SSH through
doubleshell works to it, and don't close public SSH before then. Never
print, copy, or commit a private key. If my hosting provider has a
firewall in front of the servers, tell me exactly what to change there,
because I'll do that part. Don't reboot a server unless I say so.
```

The prompt tells the agent to keep your current SSH access open until SSH
through doubleshell works, so you aren't cut off partway. You'll be asked to
change your hosting provider's firewall, if it has one, because an agent
usually can't reach it. The rest of this README shows every step the agent
takes, if you want to follow along or do it yourself.

## Install

doubleshell runs on macOS and Linux. On Windows, use it inside [WSL](https://learn.microsoft.com/windows/wsl/), with
WSL's `ssh`. Download the release archive for your machine and its checksum
file, check the download, and unpack it:

```sh
version=0.1.0
platform=macos-arm64      # or macos-amd64 (Intel Mac), linux-amd64, linux-arm64
release=https://github.com/monkeymaxxing/doubleshell/releases/download/v$version

curl -fLO "$release/doubleshell-$version-$platform.tar.gz"
curl -fLO "$release/SHA256SUMS"
shasum -a 256 --check --ignore-missing SHA256SUMS    # on Linux: sha256sum --check --ignore-missing SHA256SUMS

tar -xzf "doubleshell-$version-$platform.tar.gz"
mkdir -p ~/.local/bin
cp "doubleshell-$version-$platform/doubleshell" ~/.local/bin/doubleshell
doubleshell version
```

`~/.local/bin` must be on your `PATH`. The last command prints
`doubleshell 0.1.0`.

The checksum finds a damaged download. If you have the
[GitHub CLI](https://cli.github.com/), this command also proves that
doubleshell's own release workflow built the archive:

```sh
gh attestation verify "doubleshell-$version-$platform.tar.gz" --repo monkeymaxxing/doubleshell
```

On a Mac, download with `curl` as shown. macOS refuses to start a program
that a web browser downloaded, because the release builds are not signed
with an Apple developer certificate.

**Upgrade.** Download a newer archive and replace the `doubleshell` program
with the one in it.

**Build from source.** To run your own build, you need Git and Go 1.21 or
newer. Go downloads the exact Go version that `go.mod` names, if you have an
older one:

```sh
git clone https://github.com/monkeymaxxing/doubleshell
cd doubleshell
go build -o doubleshell .
```

Then move `doubleshell` to a folder on your `PATH`, such as `~/.local/bin` or
`/usr/local/bin`. The dependencies are included in `third_party/`, so the
build downloads no dependency code.

The code is also at <https://gitlab.com/monkeymaxxing/doubleshell>, a copy for
when GitHub is down. It has no release archives: clone it and build as shown
above. Issues and pull requests go to GitHub.

## Quick start: one server

The example uses these addresses. Change them to suit your network.

| | Address inside WireGuard | Public address |
| --- | --- | --- |
| Laptop | `10.20.9.1` | none needed |
| Server `web01` | `10.20.1.11` | `203.0.113.11` |

Keep your current SSH access open until step 5 works. Step 6 closes it.

**1. Create the laptop's key.** On the laptop:

```sh
doubleshell create-wireguard-key
```

The command saves the private key in
`~/.config/doubleshell/wireguard_private_key` and prints the public key.

**2. Install WireGuard on the server.**

- Debian and Ubuntu: `apt update && apt install wireguard`
- Rocky Linux, AlmaLinux, Fedora, and RHEL: `dnf install wireguard-tools`

**3. Give the server a WireGuard key and interface.** On the server, as root:

```sh
umask 077
wg genkey > /etc/wireguard/private.key
wg pubkey < /etc/wireguard/private.key
```

The last command prints the server's public key. Write
`/etc/wireguard/wg0.conf`:

```ini
[Interface]
PrivateKey = SERVER_PRIVATE_KEY
Address = 10.20.1.11/24
ListenPort = 51820

[Peer]
PublicKey = LAPTOP_PUBLIC_KEY
AllowedIPs = 10.20.9.1/32
```

Replace `SERVER_PRIVATE_KEY` with the contents of
`/etc/wireguard/private.key` and `LAPTOP_PUBLIC_KEY` with the key from step 1.
Then start WireGuard now and at every boot:

```sh
systemctl enable --now wg-quick@wg0
```

Allow UDP port 51820 in your provider's firewall, if it has one. If the
server's own firewall is already on, as `firewalld` usually is on Rocky,
AlmaLinux, Fedora, and RHEL, open the port there now too:

- `ufw allow 51820/udp`
- `firewall-cmd --permanent --add-port=51820/udp && firewall-cmd --reload`

**4. Tell doubleshell about the server.** On the laptop, write
`~/.config/doubleshell/servers.conf`:

```ini
[Interface]
Address = 10.20.9.1/32

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = 203.0.113.11:51820
AllowedIPs = 10.20.1.11/32
```

Replace `SERVER_PUBLIC_KEY` with the key that `wg pubkey` printed in step 3.
The file uses the standard wg-quick format but leaves out `PrivateKey`:
doubleshell uses the key from step 1 instead, so the file holds no secret.
(wg-quick itself needs `PrivateKey`, so it can't use this file.)

Add this entry to `~/.ssh/config`, above any `Host *` entry, because OpenSSH
uses the first value it finds. If you already have a `Host web01` entry,
change that one instead, and keep a copy of its old lines until step 5 works:

```sshconfig
Host web01
  HostName 10.20.1.11
  User root
  ProxyCommand doubleshell --wireguard-config ~/.config/doubleshell/servers.conf proxy-ssh %h %p
```

**5. Connect.**

```sh
ssh web01
```

SSH asks once to trust the server's host key, because `10.20.1.11` is a new
address for it. The key is the same one the server showed before:
`ssh-keygen -lF 203.0.113.11` prints the fingerprint you trusted then.

A coding agent can't answer that question. It connects once with
`ssh -o StrictHostKeyChecking=accept-new web01 true`, then checks that
`ssh-keygen -lF 10.20.1.11` prints the same fingerprint as
`ssh-keygen -lF 203.0.113.11`.

**6. Close public SSH.** Once step 5 works, allow SSH only through WireGuard:
TCP port 22 open on `wg0` and closed everywhere else. Keep every other port
the server serves allowed, such as 80 and 443 for a website. For example:

- With `ufw` (common on Ubuntu):

  ```sh
  ufw allow 51820/udp
  ufw allow in on wg0 to any port 22 proto tcp
  ufw allow 80/tcp     # only if the server serves a website
  ufw allow 443/tcp    # only if the server serves a website
  ufw --force enable
  ```

  If `ufw status` still lists `OpenSSH` or `22/tcp` from anywhere, remove
  that rule with `ufw delete allow OpenSSH` or `ufw delete allow 22/tcp`.

- With `firewalld` (Rocky, AlmaLinux, Fedora, and RHEL):

  ```sh
  firewall-cmd --permanent --add-port=51820/udp
  firewall-cmd --permanent --zone=trusted --add-interface=wg0
  firewall-cmd --permanent --remove-service=ssh
  firewall-cmd --permanent --remove-service=cockpit   # unless you use Cockpit
  firewall-cmd --reload
  ```

  Some server images come without firewalld. Install and start it first with
  `dnf install firewalld` and `systemctl enable --now firewalld`.

Remove TCP port 22 from your provider's firewall too. Check both ways from the
laptop: `ssh web01` still works, and `ssh -o ConnectTimeout=5 root@203.0.113.11`
now times out or is refused. If you ever lock yourself out, use your provider's web console.

sshd keeps listening on every address. The firewall, not sshd, limits SSH to
WireGuard, because sshd can start before `wg0` exists at boot. sshd set to
listen only on the WireGuard address would then fail to start.

## More servers

Give each server its own WireGuard address and key, as in steps 2, 3, and 6.
Add one `[Peer]` per server to `servers.conf`:

```ini
[Peer]
PublicKey = DB01_PUBLIC_KEY
Endpoint = 203.0.113.12:51820
AllowedIPs = 10.20.1.12/32
```

One SSH entry can cover every server by address, alongside a short name for each:

```sshconfig
Host web01
  HostName 10.20.1.11
Host db01
  HostName 10.20.1.12
Host web01 db01 10.20.1.*
  User root
  ProxyCommand doubleshell --wireguard-config ~/.config/doubleshell/servers.conf proxy-ssh %h %p
```

doubleshell rereads `servers.conf` on every connection, so a new peer works
right away. `doubleshell --wireguard-config ~/.config/doubleshell/servers.conf list-machines`
checks every server and shows when each last answered.

Another laptop needs its own key and address, and a `[Peer]` for it in each
server's `wg0.conf`.

For separate sets of servers, such as work and personal, use one file for each
set. Each file gets its own background process.

### Reaching servers from hotels and offices: UDP 443

**Why.** Many hotel, airport, café, and office networks let through only the
ports that web browsing uses and block everything else, including UDP 51820.
Then doubleshell reports "No server answered on UDP 51820". These networks usually allow UDP 443, because
browsers use it for HTTP/3. If you SSH from such places, also accept
WireGuard on UDP 443. A phone hotspot is the quick fix when you haven't.

**When you can't.** Skip this if the server already serves HTTP/3 on UDP 443,
as Caddy and some other web servers do by default: one port can't serve both.

**How.** Keep WireGuard listening on 51820, and have the server's firewall
forward UDP 443 to it. Both ports then work. Forwarding works the same on
every system. Setting `ListenPort = 443` directly doesn't: on Ubuntu 26.04,
wg-quick's AppArmor profile stops WireGuard from listening on ports below
1024.

1. Allow UDP 443 in your provider's firewall.
2. Forward UDP 443 to 51820 on the server:
   - With `ufw`: add these lines at the very top of `/etc/ufw/before.rules`,
     then run `ufw reload`:

     ```
     *nat
     :PREROUTING ACCEPT [0:0]
     -A PREROUTING -p udp --dport 443 -j REDIRECT --to-ports 51820
     COMMIT
     ```

   - With `firewalld`:

     ```sh
     firewall-cmd --permanent --add-forward-port=port=443:proto=udp:toport=51820
     firewall-cmd --reload
     ```

3. On the laptop, set that server's `Endpoint` to port 443, such as
   `Endpoint = 203.0.113.11:443`.

Check with `doubleshell --wireguard-config ~/.config/doubleshell/servers.conf list-machines`:
the server shows a recent time, with its endpoint on port 443.

## For coding agents

When you set up doubleshell for someone, reach each outcome below and run its
check before moving on. Use the commands that fit the person's system. Never
close public SSH before the check in step 5 passes.

| Step | Outcome | Check |
| --- | --- | --- |
| 1 | The laptop has a doubleshell key. | `~/.config/doubleshell/wireguard_private_key` exists with mode `0600`. |
| 2–3 | Each server runs WireGuard on a UDP port (51820 unless the person needs another), with the laptop's public key as a peer, and starts it at boot. | `wg show wg0` on the server lists the laptop's public key. |
| 3 | That UDP port is open in any firewall already running on the server. Before step 4, ask the person whether their hosting provider has a firewall; if it does, they open the port there. | Step 4's check. |
| 4 | The laptop's wg-quick file has one `[Peer]` per server, and `~/.ssh/config` sends those servers through `doubleshell proxy-ssh`. | `doubleshell --wireguard-config FILE list-machines` shows a recent time for every server. |
| 5 | SSH works through doubleshell. | `ssh HOST true` succeeds. |
| 6 | TCP port 22 is reachable only through `wg0`, and the firewall and WireGuard start at boot. Allow the WireGuard port and SSH on `wg0` before turning the firewall on. Tell the person to remove TCP 22 from the provider's firewall. | `ssh HOST true` still succeeds; SSH to the server's public address times out or is refused; `systemctl is-enabled` reports the firewall service and `wg-quick@wg0` as enabled. |

Keep `~/.config/doubleshell/wireguard_private_key` on the laptop. Never copy
it into chat, logs, or a repository. Each server's private key stays on that
server.

`doubleshell create-server-wireguard-key` prints a private key. Never show
its output. Send it to a file that only the person can read, and read only
the public key back:

```sh
(umask 077 && doubleshell create-server-wireguard-key > server-key.json)
jq -r .public_key server-key.json
```

Build the server's first-boot data from `server-key.json` without printing
the file or the first-boot data. Delete `server-key.json` once the server
exists.

## Commands

`--wireguard-config FILE` comes before the command.

- `doubleshell --wireguard-config FILE proxy-ssh HOST PORT` carries one SSH
  connection. OpenSSH runs it as `ProxyCommand ... proxy-ssh %h %p`. `HOST`
  must be an address inside WireGuard. Standard input and output carry only
  SSH's bytes. Errors go to standard error.
- `doubleshell --wireguard-config FILE list-machines` checks every peer and
  prints its `wireguard_address`, `endpoint`, and `last_wireguard_handshake`
  in UTC. `never` means no handshake since doubleshell's background process
  started. A failed check leaves the earlier time in place.
- `doubleshell create-wireguard-key` saves a new laptop key in
  `~/.config/doubleshell/wireguard_private_key`, with mode `0600` in a
  directory with mode `0700`, and prints the public key. It never replaces an
  existing key unless you add `--replace-existing-key`. After a replacement,
  update the laptop's peer on every server.
- `doubleshell create-server-wireguard-key` prints a new server key pair as
  one JSON object with `private_key` and `public_key`, and saves nothing. Use
  it to put a key in a new server's first-boot data, such as cloud-init, from
  a laptop without WireGuard tools. Pass the private key only to the new
  server; keep only the public key. Read
  [A server key in first-boot data](#a-server-key-in-first-boot-data) first.
- `doubleshell version` prints `doubleshell` and the version number of the
  program, such as `doubleshell 0.1.0`.

### A server key in first-boot data

Your hosting provider keeps a copy of a server's first-boot data, such as
cloud-init, for the server's whole life. On most providers, any program on
the server can read that copy from the metadata address `169.254.169.254`.
No root is needed.

So a private key sent in first-boot data can be read by anything that runs
on the server, such as a website with a security hole. Replace the key after
the first boot. On the server, as root:

```sh
umask 077
wg genkey > /etc/wireguard/private.key
wg pubkey < /etc/wireguard/private.key
```

Replace the `PrivateKey` line in `/etc/wireguard/wg0.conf` with the contents
of `/etc/wireguard/private.key`. Then restart WireGuard:

```sh
systemctl restart wg-quick@wg0
```

Your SSH connection through doubleshell drops at the restart.

On the laptop, put the new public key, which `wg pubkey` printed, in that
server's `[Peer]`. Then connect again. Other servers that have this server as
a peer need the new public key too. If you can't connect, use your provider's
web console.

If you manage the server's outgoing firewall rules, blocking
`169.254.169.254` for every user except root also works.

### The wg-quick file

doubleshell reads these settings and refuses any other, so a file never means
something different from what it says:

- `[Interface]`: `Address` (required), and `PrivateKey` (optional; without
  it, doubleshell uses the key that `create-wireguard-key` saved).
- `[Peer]`: `PublicKey`, `Endpoint`, and `AllowedIPs`, all required.

`Address` and `AllowedIPs` take comma-separated lists, and IPv4 and IPv6 both
work. `Endpoint` takes an IP address or a DNS name, with the UDP port. When
several peers' `AllowedIPs` contain the requested address, the most specific
one wins. A file with `PrivateKey` holds a secret: give it mode `0600`.

## When something fails

Each error names the server's address, SSH port, and WireGuard endpoint, and
says what to do next. The usual ones:

| Message | What it means |
| --- | --- |
| No server answered on UDP 51820. A firewall in front of the servers, or this network, may block that port: check the hosting provider's firewall, or try a phone hotspot. If this laptop was added recently, the change may not be applied to the servers yet. | No server finished a WireGuard handshake within five seconds. During setup, it's usually the provider's firewall. |
| 10.20.1.12 answers, but 10.20.1.11 doesn't: 10.20.1.11 may be down, or its WireGuard stopped. | Your network is fine; that one server is not answering. |
| 10.20.1.14 is not in the AllowedIPs of any [Peer] in FILE; add a [Peer] for that server | The file has no peer for that address. |
| WireGuard answers, but the TCP connection failed | WireGuard works. sshd is not running, listens on another port, or the server's firewall blocks port 22 on `wg0`. |

To see where the packets stop, run `tcpdump -ni eth0 udp port 51820` on the
server while you connect. No packets means a firewall or network in between.
Packets but no handshake in `wg show wg0` means the keys don't match.

A handshake timeout cannot by itself tell a stopped server from a blocked
network or an unknown key. So when the server doesn't answer, doubleshell
checks the other peers for up to five more seconds to tell those cases apart.

## How it works

The first SSH connection starts a small background process, which shows in
`ps` as `doubleshell --wireguard-config FILE agent`. It holds the WireGuard
connection for every SSH connection that uses the same file, and exits after
ten minutes with none. Every new SSH connection makes a fresh WireGuard
handshake, so a success always proves the server is answering now.

Changes to the file apply to the next connection. Open connections keep
working, and a file with a mistake leaves the running setup as it was. If the
laptop's key or address changes while other SSH connections are open,
doubleshell asks you to close them and connect again.

[The design](docs/design.md) has the details and the reasons.

## doubleshell and the Monkeymaxxing tools

doubleshell is a small utility from Monkeymaxxing. It works by itself, with
any servers. The Monkeymaxxing Stack uses doubleshell for SSH access to its
servers.

| Tool | What it does |
|---|---|
| [MMX](https://github.com/monkeymaxxing/mmx) | Sets up your servers, and makes every later change to them |
| [MMWatchdog](https://github.com/monkeymaxxing/mmwatchdog) | Watches your servers, restarts what fails, and alerts you |
| [MMHotline](https://github.com/monkeymaxxing/mmhotline) | Gets each urgent alert to the person on call, and can let your coding agent investigate first |
| [Monkeymaxxing Stack](https://github.com/monkeymaxxing/monkeymaxxing-stack) | Instructions for your coding agent that build and run a whole production system with the three tools above |

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) says how issues and pull requests work, and
how to report a security problem. [AGENTS.md](AGENTS.md) has the development
commands, and [docs/acceptance.md](docs/acceptance.md) says what every change
must keep working.

## License

Apache License 2.0. Included dependencies retain their own licenses.
