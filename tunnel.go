package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const handshakeWait = 5 * time.Second

var errLaptopIdentityChanged = errors.New("this laptop's WireGuard key or address changed; close this laptop's other SSH connections through doubleshell, then connect again")

type tunnel struct {
	device    *device.Device
	network   *netstack.Net
	config    *configuration
	peerLocks map[[32]byte]*sync.Mutex
}

func newTunnel(c *configuration) (*tunnel, error) {
	tun, network, err := netstack.CreateNetTUN(c.Addresses, nil, 1420)
	if err != nil {
		return nil, err
	}
	d := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t := &tunnel{device: d, network: network, peerLocks: make(map[[32]byte]*sync.Mutex)}
	if err := d.IpcSet("private_key=" + keyHex(c.PrivateKey) + "\n"); err != nil {
		d.Close()
		return nil, err
	}
	if err := t.update(c); err != nil {
		d.Close()
		return nil, err
	}
	if err := d.Up(); err != nil {
		d.Close()
		return nil, err
	}
	return t, nil
}

// The agent's mutex protects configuration updates and peer-lock lookup.
// Established streams use netstack directly and do not hold this mutex.
func (t *tunnel) update(c *configuration) error {
	if t.config != nil && (t.config.PrivateKey != c.PrivateKey || !reflect.DeepEqual(t.config.Addresses, c.Addresses)) {
		return errLaptopIdentityChanged
	}
	var update strings.Builder
	current := make(map[[32]byte]machine)
	if t.config != nil {
		for _, m := range t.config.Machines {
			current[m.PublicKey] = m
		}
	}
	for _, m := range c.Machines {
		old, exists := current[m.PublicKey]
		delete(current, m.PublicKey)
		if exists && reflect.DeepEqual(old, m) {
			continue
		}
		endpoint, err := resolveEndpoint(m.Endpoint)
		if err != nil {
			return fmt.Errorf("peer %s (WireGuard endpoint %s): %w", m.address(), m.Endpoint, err)
		}
		fmt.Fprintf(&update, "public_key=%s\nendpoint=%s\nreplace_allowed_ips=true\n", keyHex(m.PublicKey), endpoint)
		for _, p := range m.AllowedIPs {
			fmt.Fprintf(&update, "allowed_ip=%s\n", p)
		}
		if t.peerLocks[m.PublicKey] == nil {
			t.peerLocks[m.PublicKey] = new(sync.Mutex)
		}
	}
	for key := range current {
		fmt.Fprintf(&update, "public_key=%s\nremove=true\n", keyHex(key))
	}
	if update.Len() > 0 {
		if err := t.device.IpcSet(update.String()); err != nil {
			return fmt.Errorf("configure WireGuard peers: %w", err)
		}
	}
	t.config = c
	return nil
}

func (t *tunnel) lastHandshakes() map[[32]byte]time.Time {
	result := make(map[[32]byte]time.Time)
	state, err := t.device.IpcGet()
	if err != nil {
		return result
	}
	var key [32]byte
	var seconds int64
	for _, line := range strings.Split(state, "\n") {
		name, value, _ := strings.Cut(line, "=")
		switch name {
		case "public_key":
			decoded, err := hex.DecodeString(value)
			if err == nil && len(decoded) == 32 {
				copy(key[:], decoded)
			}
		case "last_handshake_time_sec":
			seconds, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			ns, _ := strconv.ParseInt(value, 10, 64)
			if seconds != 0 || ns != 0 {
				result[key] = time.Unix(seconds, ns)
			}
		}
	}
	return result
}

// ExpireCurrentKeypairs expires outbound keys, retaining inbound keys and TCP
// state. SendHandshakeInitiation then proves a fresh exchange even if the next
// TCP packet would otherwise fit an established WireGuard session.
func (t *tunnel) handshake(ctx context.Context, m machine, lock *sync.Mutex) error {
	lock.Lock()
	defer lock.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	peer := t.device.LookupPeer(device.NoisePublicKey(m.PublicKey))
	if peer == nil {
		return fmt.Errorf("WireGuard peer was removed from the wg-quick file")
	}
	before := t.lastHandshakes()[m.PublicKey]
	// WireGuard rejects initiations within its 20 ms flood window. Its timestamp
	// also rounds down to 16 ms. Spacing from the received response satisfies
	// both rules without changing the protocol or the dependency.
	if wait := device.HandshakeInitationRate - time.Since(before); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	peer.ExpireCurrentKeypairs()
	if err := peer.SendHandshakeInitiation(false); err != nil {
		return err
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if t.lastHandshakes()[m.PublicKey].After(before) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type machineStatus struct {
	Address                string    `json:"wireguard_address"`
	Endpoint               string    `json:"endpoint"`
	LastWireGuardHandshake time.Time `json:"last_wireguard_handshake"`
}

type connectionTarget struct {
	machine machine
	address netip.Addr
	port    uint16
	lock    *sync.Mutex
}

func (target connectionTarget) describe(err error) error {
	return fmt.Errorf("%s, SSH port %d, WireGuard endpoint %s: %w", target.address, target.port, target.machine.Endpoint, err)
}

func (t *tunnel) connect(ctx context.Context, target connectionTarget, others []connectionTarget) (net.Conn, error) {
	handshakeContext, cancel := context.WithTimeout(ctx, handshakeWait)
	err := t.handshake(handshakeContext, target.machine, target.lock)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return nil, target.describe(ctx.Err())
		}
		probeContext, cancel := context.WithTimeout(ctx, handshakeWait)
		defer cancel()
		answers := make(chan string, len(others))
		for _, other := range others {
			go func() {
				if t.handshake(probeContext, other.machine, other.lock) == nil {
					answers <- other.machine.address().String()
				} else {
					answers <- ""
				}
			}()
		}
		for range others {
			if name := <-answers; name != "" {
				return nil, target.describe(fmt.Errorf("%s answers, but %s doesn't: %s may be down, or its WireGuard stopped.", name, target.machine.address(), target.machine.address()))
			}
		}
		ports := make(map[string]bool)
		for _, m := range append(others, target) {
			_, port, _ := net.SplitHostPort(m.machine.Endpoint)
			ports[port] = true
		}
		portText := "the configured WireGuard ports"
		if len(ports) == 1 {
			for port := range ports {
				portText = "UDP " + port
			}
		}
		down := "The server may be down"
		if len(others) > 0 {
			down = "The servers may be down"
		}
		return nil, target.describe(fmt.Errorf("No server answered on %s. %s, or a firewall in front of the servers or on this network may block that port. Check that the server is running and check the hosting provider's firewall, or try a phone hotspot. If this laptop was added recently, the change may not be applied to the servers yet.", portText, down))
	}
	tcpContext, cancel := context.WithTimeout(ctx, handshakeWait)
	defer cancel()
	stream, err := t.network.DialContextTCPAddrPort(tcpContext, netip.AddrPortFrom(target.address, target.port))
	if err != nil {
		return nil, target.describe(fmt.Errorf("WireGuard answers, but the TCP connection failed: %w", err))
	}
	return stream, nil
}

func resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid WireGuard endpoint: %w", err)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return endpoint, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), handshakeWait)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", fmt.Errorf("resolve WireGuard endpoint %s: %w", host, err)
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("WireGuard endpoint %s has no IP address", host)
	}
	return net.JoinHostPort(addresses[0].Unmap().String(), port), nil
}
