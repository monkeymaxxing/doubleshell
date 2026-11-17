package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// machine is one [Peer] of the wg-quick file.
type machine struct {
	PublicKey  [32]byte
	Endpoint   string
	AllowedIPs []netip.Prefix
}

// address is the peer's first allowed address, which names the machine in
// messages and in list-machines.
func (m machine) address() netip.Addr { return m.AllowedIPs[0].Addr() }

// configuration is the snapshot an agent runs from. Fingerprint covers every
// file the snapshot was read from, so any change to them is noticed.
type configuration struct {
	PrivateKey  [32]byte
	Addresses   []netip.Addr
	Machines    []machine
	Fingerprint [32]byte
}

func decodeKey(value string) ([32]byte, error) {
	var key [32]byte
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(b) != len(key) {
		return key, fmt.Errorf("WireGuard key must be 32 bytes encoded as base64")
	}
	copy(key[:], b)
	if key == [32]byte{} {
		return key, fmt.Errorf("WireGuard key must not be zero")
	}
	return key, nil
}

func publicKey(private [32]byte) [32]byte {
	key, _ := ecdh.X25519().NewPrivateKey(private[:])
	var public [32]byte
	copy(public[:], key.PublicKey().Bytes())
	return public
}

func keyHex(key [32]byte) string { return hex.EncodeToString(key[:]) }

// keyPath is the laptop key that create-wireguard-key saves. A wg-quick file
// without PrivateKey uses it, so the secret lives in one file.
func keyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "doubleshell", "wireguard_private_key"), nil
}

func readConfiguration(source string) (*configuration, error) {
	data, err := os.ReadFile(source)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	hash := sha256.New()
	hash.Write(data)
	c := &configuration{}
	if err := parseWireGuardConfig(data, source, c); err != nil {
		return nil, err
	}
	if c.PrivateKey == [32]byte{} {
		path, err := keyPath()
		if err != nil {
			return nil, err
		}
		keyData, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s has no PrivateKey, and the laptop key %s could not be read: %w; run doubleshell create-wireguard-key, or add PrivateKey to [Interface]", source, path, err)
		}
		hash.Write(keyData)
		if c.PrivateKey, err = decodeKey(string(keyData)); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if len(c.Addresses) == 0 {
		return nil, fmt.Errorf("%s needs Address in [Interface]: this laptop's address inside WireGuard", source)
	}
	seenKeys := make(map[[32]byte]bool)
	seenPrefixes := make(map[netip.Prefix]netip.Addr)
	for _, m := range c.Machines {
		if seenKeys[m.PublicKey] {
			return nil, fmt.Errorf("%s: peer %s repeats another peer's PublicKey", source, m.address())
		}
		seenKeys[m.PublicKey] = true
		for _, p := range m.AllowedIPs {
			if other, ok := seenPrefixes[p]; ok {
				return nil, fmt.Errorf("%s: AllowedIPs %s appears in peers %s and %s", source, p, other, m.address())
			}
			seenPrefixes[p] = m.address()
		}
	}
	copy(c.Fingerprint[:], hash.Sum(nil))
	return c, nil
}

// parseWireGuardConfig reads the wg-quick settings doubleshell supports.
// Unsupported settings fail rather than being silently ignored.
func parseWireGuardConfig(data []byte, source string, c *configuration) error {
	section := ""
	var peer *machine
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch line {
			case "[Interface]":
				if section != "" {
					return fmt.Errorf("%s must have one [Interface], before every [Peer]", source)
				}
				section = "Interface"
			case "[Peer]":
				if section == "" {
					return fmt.Errorf("%s must start with [Interface]", source)
				}
				section = "Peer"
				c.Machines = append(c.Machines, machine{})
				peer = &c.Machines[len(c.Machines)-1]
			default:
				return fmt.Errorf("unsupported section %q in %s", line, source)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("invalid line in %s: expected NAME = VALUE", source)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		var err error
		switch {
		case section == "Interface" && key == "PrivateKey":
			c.PrivateKey, err = decodeKey(value)
		case section == "Interface" && key == "Address":
			for _, text := range strings.Split(value, ",") {
				prefix, e := netip.ParsePrefix(strings.TrimSpace(text))
				if e != nil {
					return fmt.Errorf("invalid Address %q in %s: %w", text, source, e)
				}
				c.Addresses = append(c.Addresses, prefix.Addr())
			}
		case section == "Peer" && key == "PublicKey":
			peer.PublicKey, err = decodeKey(value)
		case section == "Peer" && key == "Endpoint":
			peer.Endpoint = value
		case section == "Peer" && key == "AllowedIPs":
			for _, text := range strings.Split(value, ",") {
				prefix, e := netip.ParsePrefix(strings.TrimSpace(text))
				if e != nil {
					return fmt.Errorf("invalid AllowedIPs %q in %s: %w", text, source, e)
				}
				peer.AllowedIPs = append(peer.AllowedIPs, prefix.Masked())
			}
		default:
			supported := "PrivateKey and Address"
			if section == "Peer" {
				supported = "PublicKey, Endpoint, and AllowedIPs"
			}
			return fmt.Errorf("unsupported setting %s in [%s] of %s; [%s] supports %s", key, section, source, section, supported)
		}
		if err != nil {
			return fmt.Errorf("%s in %s: %w", key, source, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	for _, m := range c.Machines {
		if m.PublicKey == [32]byte{} || m.Endpoint == "" || len(m.AllowedIPs) == 0 {
			return fmt.Errorf("every [Peer] in %s needs PublicKey, Endpoint, and AllowedIPs", source)
		}
		host, port, err := net.SplitHostPort(m.Endpoint)
		n, e := strconv.Atoi(port)
		if err != nil || e != nil || n < 1 || n > 65535 || host == "" {
			return fmt.Errorf("invalid Endpoint %q in %s: use HOST:PORT, such as 203.0.113.11:51820", m.Endpoint, source)
		}
	}
	return nil
}

// findMachine picks the peer whose AllowedIPs most specifically contain host.
func (c *configuration) findMachine(host, source string) (machine, netip.Addr, error) {
	address, err := netip.ParseAddr(host)
	if err != nil {
		return machine{}, netip.Addr{}, fmt.Errorf("%s is not an IP address; set HostName in the SSH entry to the server's WireGuard address", host)
	}
	var selected *machine
	bits := -1
	for i := range c.Machines {
		for _, p := range c.Machines[i].AllowedIPs {
			if p.Contains(address) && p.Bits() > bits {
				selected, bits = &c.Machines[i], p.Bits()
			}
		}
	}
	if selected == nil {
		return machine{}, netip.Addr{}, fmt.Errorf("%s is not in the AllowedIPs of any [Peer] in %s; add a [Peer] for that server", host, source)
	}
	return *selected, address, nil
}
