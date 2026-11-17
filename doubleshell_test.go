package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestMain(m *testing.M) {
	if os.Getenv(internalAgentEnv) == "1" {
		agentIdleTimeout = 80 * time.Millisecond
		if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func testKey(t *testing.T) [32]byte {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	key[0] &= 248
	key[31] = key[31]&127 | 64
	return key
}

func base64Key(key [32]byte) string { return base64.StdEncoding.EncodeToString(key[:]) }

type testServer struct {
	device    *device.Device
	machine   machine
	clientKey [32]byte
}

func startServer(t *testing.T, clientKey [32]byte, address string, handlers ...func(net.Conn)) *testServer {
	t.Helper()
	private := testKey(t)
	tun, network, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(address)}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	d := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(d.Close)
	err = d.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=10.20.9.1/32\n", keyHex(private), keyHex(publicKey(clientKey))))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Up(); err != nil {
		t.Fatal(err)
	}
	state, _ := d.IpcGet()
	var port string
	for _, line := range strings.Split(state, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port = strings.TrimPrefix(line, "listen_port=")
		}
	}
	if port == "" || port == "0" {
		t.Fatalf("WireGuard did not bind UDP: %s", port)
	}
	listener, err := network.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(address), 22))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			stream, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer stream.Close()
				if len(handlers) > 0 {
					handlers[0](stream)
				} else {
					io.Copy(stream, stream)
				}
			}()
		}
	}()
	return &testServer{device: d, clientKey: clientKey, machine: machine{PublicKey: publicKey(private), Endpoint: "127.0.0.1:" + port, AllowedIPs: []netip.Prefix{netip.MustParsePrefix(address + "/32")}}}
}

func configFor(private [32]byte, machines ...machine) *configuration {
	return &configuration{PrivateKey: private, Addresses: []netip.Addr{netip.MustParseAddr("10.20.9.1")}, Machines: machines}
}

func openTunnel(t *testing.T, c *configuration) *tunnel {
	t.Helper()
	tunnel, err := newTunnel(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tunnel.device.Close)
	return tunnel
}

func connectTunnel(t *testing.T, tunnel *tunnel, m machine) net.Conn {
	t.Helper()
	target := connectionTarget{machine: m, address: m.AllowedIPs[0].Addr(), port: 22, lock: tunnel.peerLocks[m.PublicKey]}
	stream, err := tunnel.connect(context.Background(), target, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stream.Close() })
	return stream
}

func exchange(t *testing.T, stream net.Conn, value string) {
	t.Helper()
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(stream, value); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(value))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != value {
		t.Fatalf("echo %q, want %q", got, value)
	}
	stream.SetDeadline(time.Time{})
}

func TestNewHandshakePreservesConcurrentConnections(t *testing.T) {
	key := testKey(t)
	server := startServer(t, key, "10.20.1.1")
	tunnel := openTunnel(t, configFor(key, server.machine))
	first := connectTunnel(t, tunnel, server.machine)
	exchange(t, first, "first connection: client to server and back\n")
	before := (&tunnelForAnswers{server.device}).lastAnswer(publicKey(key))
	second := connectTunnel(t, tunnel, server.machine)
	exchange(t, second, "second connection\n")
	after := (&tunnelForAnswers{server.device}).lastAnswer(publicKey(key))
	if !after.After(before) {
		t.Fatal("second connection did not complete a new server-side handshake")
	}
	exchange(t, first, "first connection still works after the new handshake\n")
	exchange(t, second, "second connection still works\n")
	// Repeated starts must not be held back by wireguard-go's normal five-second
	// initiation rate limit after ExpireCurrentKeypairs.
	third := connectTunnel(t, tunnel, server.machine)
	exchange(t, third, "third connection\n")
	exchange(t, first, "first connection still works after a third handshake\n")
}

type tunnelForAnswers struct{ device *device.Device }

func (t *tunnelForAnswers) lastAnswer(key [32]byte) time.Time {
	return (&tunnel{device: t.device}).lastHandshakes()[key]
}

func writeQuick(t *testing.T, path string, key [32]byte, machines ...machine) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = 10.20.9.1/24\n", base64Key(key))
	for _, m := range machines {
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\n", base64Key(m.PublicKey), m.Endpoint, m.AllowedIPs[0])
	}
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		t.Fatal(err)
	}
}

func startTestAgent(t *testing.T, source string, idle time.Duration) (*agent, string, <-chan error) {
	t.Helper()
	canonicalSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	source = canonicalSource
	socket, err := socketPath(source)
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{source: source, idle: idle}
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- a.serve(socket, func(err error) { ready <- err }) }()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.listener.Close(); os.Remove(socket + ".lock") })
	return a, socket, done
}

func agentConnection(t *testing.T, socket, host string) net.Conn {
	t.Helper()
	stream, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(stream).Encode(agentRequest{Command: "proxy-ssh", Host: host, Port: 22}); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stream)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var response agentResponse
	if err := json.Unmarshal([]byte(line), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error != "" {
		stream.Close()
		t.Fatal(response.Error)
	}
	// No payload was sent before the response, so the reader cannot consume it.
	if reader.Buffered() != 0 {
		t.Fatal("unexpected tunnel bytes before the client sends data")
	}
	t.Cleanup(func() { stream.Close() })
	return stream
}

func TestCauseMessages(t *testing.T) {
	key := testKey(t)
	up := startServer(t, key, "10.20.1.2")
	dead := machine{PublicKey: publicKey(testKey(t)), Endpoint: "127.0.0.1:443", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.20.1.1/32")}}
	for _, test := range []struct {
		name     string
		machines []machine
		want     string
	}{
		{"no_server_answers", []machine{dead}, "No server answered on UDP 443. The server may be down, or a firewall in front of the servers or on this network may block that port. Check that the server is running and check the hosting provider's firewall, or try a phone hotspot. If this laptop was added recently, the change may not be applied to the servers yet."},
		{"another_server_answers", []machine{dead, up.machine}, "10.20.1.2 answers, but 10.20.1.1 doesn't: 10.20.1.1 may be down, or its WireGuard stopped."},
	} {
		t.Run(test.name, func(t *testing.T) {
			tunnel := openTunnel(t, configFor(key, test.machines...))
			target := connectionTarget{machine: dead, address: dead.address(), port: 22, lock: tunnel.peerLocks[dead.PublicKey]}
			var others []connectionTarget
			if len(test.machines) > 1 {
				others = append(others, connectionTarget{machine: up.machine, lock: tunnel.peerLocks[up.machine.PublicKey]})
			}
			_, err := tunnel.connect(context.Background(), target, others)
			if err == nil || !strings.Contains(err.Error(), test.want) || !strings.Contains(err.Error(), "10.20.1.1, SSH port 22, WireGuard endpoint 127.0.0.1:443: ") {
				t.Fatalf("error = %v", err)
			}
		})
	}
	source := "/home/barbara/wireguard.conf"
	c := configFor(key, up.machine)
	for host, want := range map[string]string{
		"10.20.1.4": "10.20.1.4 is not in the AllowedIPs of any [Peer] in /home/barbara/wireguard.conf; add a [Peer] for that server",
		"web01":     "web01 is not an IP address; set HostName in the SSH entry to the server's WireGuard address",
	} {
		if _, _, err := c.findMachine(host, source); err == nil || err.Error() != want {
			t.Fatalf("%s: error = %v, want %q", host, err, want)
		}
	}
}

func TestReloadAddsPeerAndKeepsConnection(t *testing.T) {
	key := testKey(t)
	first := startServer(t, key, "10.20.1.1")
	second := startServer(t, key, "10.20.1.2")
	// One device sends to an IPv4 and an IPv6 endpoint. This covers the
	// IPv6 destination fix in the wireguard-go copy (docs/design.md#dependencies).
	_, port, _ := net.SplitHostPort(second.machine.Endpoint)
	second.machine.Endpoint = net.JoinHostPort("::1", port)
	source := filepath.Join(t.TempDir(), "wireguard.conf")
	writeQuick(t, source, key, first.machine)
	_, socket, _ := startTestAgent(t, source, time.Minute)
	one := agentConnection(t, socket, "10.20.1.1")
	exchange(t, one, "before the file changes\n")
	writeQuick(t, source, key, first.machine, second.machine)
	two := agentConnection(t, socket, "10.20.1.2")
	exchange(t, two, "new peer\n")
	exchange(t, one, "original peer after the file changed\n")
}

func TestInvalidReloadPreservesCurrentPeers(t *testing.T) {
	key := testKey(t)
	server := startServer(t, key, "10.20.1.1")
	source := filepath.Join(t.TempDir(), "wireguard.conf")
	writeQuick(t, source, key, server.machine)
	good, _ := os.ReadFile(source)
	a, socket, _ := startTestAgent(t, source, time.Minute)
	held := agentConnection(t, socket, "10.20.1.1")
	exchange(t, held, "before the broken edit\n")
	os.WriteFile(source, append(append([]byte{}, good...), "\n[Peer]\nPublicKey = not-a-key\n"...), 0600)
	stream, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	json.NewEncoder(stream).Encode(agentRequest{Command: "list-machines"})
	var response agentResponse
	err = json.NewDecoder(stream).Decode(&response)
	stream.Close()
	if err != nil || !strings.Contains(response.Error, "PublicKey in "+a.source) {
		t.Fatalf("reload error = %q (%v)", response.Error, err)
	}
	a.mu.Lock()
	count := len(a.tunnel.config.Machines)
	a.mu.Unlock()
	if count != 1 {
		t.Fatal("broken edit changed the current peers")
	}
	exchange(t, held, "open connection survived the broken edit\n")
	os.WriteFile(source, good, 0600)
	restored := agentConnection(t, socket, "10.20.1.1")
	exchange(t, restored, "new connection after fixing the file\n")
}

// A wg-quick file without PrivateKey uses the key create-wireguard-key saved,
// and replacing that key counts as a change of the laptop's identity.
func TestFileWithoutPrivateKeyUsesSavedLaptopKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	source := filepath.Join(t.TempDir(), "wireguard.conf")
	peer := machine{PublicKey: publicKey(testKey(t)), Endpoint: "203.0.113.11:443", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.20.1.11/32")}}
	writeQuick(t, source, testKey(t), peer)
	data, _ := os.ReadFile(source)
	var kept []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, "PrivateKey") {
			kept = append(kept, line)
		}
	}
	os.WriteFile(source, []byte(strings.Join(kept, "\n")), 0600)
	path, _ := keyPath()
	if _, err := readConfiguration(source); err == nil || !strings.Contains(err.Error(), "has no PrivateKey, and the laptop key "+path+" could not be read") || !strings.Contains(err.Error(), "run doubleshell create-wireguard-key") {
		t.Fatalf("missing key error = %v", err)
	}
	var printed bytes.Buffer
	if err := run([]string{"create-wireguard-key"}, nil, &printed); err != nil {
		t.Fatal(err)
	}
	first, err := readConfiguration(source)
	if err != nil {
		t.Fatal(err)
	}
	if base64Key(publicKey(first.PrivateKey))+"\n" != printed.String() {
		t.Fatal("the file did not use the saved laptop key")
	}
	if err := run([]string{"create-wireguard-key", "--replace-existing-key"}, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	second, err := readConfiguration(source)
	if err != nil {
		t.Fatal(err)
	}
	if second.PrivateKey == first.PrivateKey || second.Fingerprint == first.Fingerprint {
		t.Fatal("replacing the saved key did not change the snapshot")
	}
}

func TestCommandsNeedTheWireGuardFile(t *testing.T) {
	for _, args := range [][]string{{"proxy-ssh", "10.20.1.1", "22"}, {"list-machines"}} {
		err := run(args, nil, io.Discard)
		want := args[0] + " needs --wireguard-config FILE before the command, naming a wg-quick file"
		if err == nil || err.Error() != want {
			t.Fatalf("error = %v, want %q", err, want)
		}
	}
}

func TestIdleAgentExitsAndNextConnectionStartsAgent(t *testing.T) {
	key := testKey(t)
	server := startServer(t, key, "10.20.1.1")
	source := filepath.Join(t.TempDir(), "wireguard.conf")
	writeQuick(t, source, key, server.machine)
	a, socket, done := startTestAgent(t, source, time.Minute)
	source = a.source
	stream := agentConnection(t, socket, "10.20.1.1")
	exchange(t, stream, "before idle\n")
	a.mu.Lock()
	a.idle = 80 * time.Millisecond
	a.mu.Unlock()
	// A connection must hold the agent alive beyond the idle interval.
	time.Sleep(120 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("agent exited with active stream: %v", err)
	default:
	}
	exchange(t, stream, "still active\n")
	stream.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not exit after becoming idle")
	}
	if _, err := net.Dial("unix", socket); err == nil {
		t.Fatal("idle socket still accepts connections")
	}
	restarted, err := dialAgent(source)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Close()
	after := agentConnection(t, socket, "10.20.1.1")
	exchange(t, after, "automatically restarted agent\n")
	after.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, err := os.Lstat(socket)
		if os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restarted child did not exit when idle")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestNewAgentWaitsForItsStartingClient(t *testing.T) {
	key := testKey(t)
	server := startServer(t, key, "10.20.1.1")
	source := filepath.Join(t.TempDir(), "wireguard.conf")
	writeQuick(t, source, key, server.machine)
	source, err := filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := socketPath(source)
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{source: source, idle: time.Millisecond}
	ready := make(chan error, 1)
	done := make(chan error, 1)
	// The starting client reads the ready report after a delay longer than
	// the idle interval, as a busy machine can make it.
	go func() {
		done <- a.serve(socket, func(err error) { time.Sleep(100 * time.Millisecond); ready <- err })
	}()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(socket + ".lock") })
	stream := agentConnection(t, socket, "10.20.1.1")
	exchange(t, stream, "late starting client\n")
	stream.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not exit after its starting client finished")
	}
}

func TestSocketDirectoryIsPrivateAndIgnoresTheEnvironment(t *testing.T) {
	source := filepath.Join(t.TempDir(), "settings.yml")
	var directories []string
	// A terminal, a coding agent with its own TMPDIR, and a program started
	// with no environment must all find the same agent.
	for _, parent := range []string{"", t.TempDir(), t.TempDir()} {
		t.Setenv("TMPDIR", parent)
		t.Setenv("XDG_RUNTIME_DIR", parent)
		socket, err := socketPath(source)
		if err != nil {
			t.Fatal(err)
		}
		directories = append(directories, filepath.Dir(socket))
	}
	if directories[0] != directories[1] || directories[0] != directories[2] {
		t.Fatalf("socket directory follows the environment: %v", directories)
	}
	if runtime.GOOS == "darwin" && strings.HasPrefix(directories[0], "/tmp/") {
		t.Fatalf("socket directory %s is in the shared /tmp", directories[0])
	}
	info, err := os.Lstat(directories[0])
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 || !info.IsDir() {
		t.Fatalf("unsafe socket directory: %v", info.Mode())
	}
}

func TestCreateWireGuardKeyRefusesReplacement(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var output bytes.Buffer
	if err := run([]string{"create-wireguard-key"}, nil, &output); err != nil {
		t.Fatal(err)
	}
	path, _ := keyPath()
	before, _ := os.ReadFile(path)
	key, err := decodeKey(string(before))
	if err != nil {
		t.Fatal(err)
	}
	if output.String() != base64Key(publicKey(key))+"\n" {
		t.Fatal("command did not print the public key")
	}
	for path, want := range map[string]os.FileMode{path: 0600, filepath.Dir(path): 0700} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode %o", path, info.Mode().Perm())
		}
	}
	if err := run([]string{"create-wireguard-key"}, nil, &output); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("replacement error: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("key changed without explicit replacement")
	}
	if err := run([]string{"create-wireguard-key", "--replace-existing-key"}, nil, &output); err != nil {
		t.Fatal(err)
	}
	replaced, _ := os.ReadFile(path)
	if bytes.Equal(before, replaced) {
		t.Fatal("explicit replacement did not replace key")
	}
}

func TestProxyCommandAndListMachines(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "doubleshell")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build executable: %v: %s", err, output)
	}
	invoke := func(args []string, input io.Reader, output io.Writer) error {
		command := exec.Command(binary, args...)
		command.Stdin, command.Stdout = input, output
		var stderr bytes.Buffer
		command.Stderr = &stderr
		if err := command.Run(); err != nil {
			return fmt.Errorf("%v: %s", err, stderr.String())
		}
		return nil
	}
	key := testKey(t)
	server := startServer(t, key, "10.20.1.1")
	source := filepath.Join(t.TempDir(), "wireguard.conf")
	writeQuick(t, source, key, server.machine)
	_, socket, _ := startTestAgent(t, source, time.Minute)
	held := agentConnection(t, socket, "10.20.1.1")
	exchange(t, held, "held connection\n")
	var output bytes.Buffer
	payload := "SSH bytes including a half-close\x00\x01\xff\n"
	if err := invoke([]string{"--wireguard-config", source, "proxy-ssh", "10.20.1.1", "22"}, strings.NewReader(payload), &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != payload {
		t.Fatalf("proxy output %q, want %q", output.String(), payload)
	}
	output.Reset()
	if err := invoke([]string{"--wireguard-config", source, "list-machines"}, nil, &output); err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(output.String())
	if len(fields) != 6 || fields[0] != "wireguard_address" || fields[1] != "endpoint" || fields[2] != "last_wireguard_handshake" || fields[3] != "10.20.1.1" || fields[4] != server.machine.Endpoint {
		t.Fatalf("machine list: %q", output.String())
	}
	answered, err := time.Parse(time.RFC3339Nano, fields[5])
	if err != nil || time.Since(answered) > 5*time.Second {
		t.Fatalf("machine list has no recent answer: %q", output.String())
	}
	exchange(t, held, "list-machines preserved the open stream\n")
	output.Reset()
	err = invoke([]string{"--wireguard-config", source, "proxy-ssh", "10.20.1.4", "22"}, strings.NewReader(""), &output)
	if err == nil || !strings.Contains(err.Error(), "10.20.1.4, SSH port 22: 10.20.1.4 is not in the AllowedIPs of any [Peer] in ") {
		t.Fatalf("unknown-machine error: %v", err)
	}
	if output.Len() != 0 {
		t.Fatal("proxy error contaminated the SSH byte stream")
	}
}

func TestAgentProcessCommandLine(t *testing.T) {
	t.Setenv(internalAgentEnv, "")
	if err := run([]string{"agent"}, nil, io.Discard); err == nil || !strings.Contains(err.Error(), `unknown command "agent"`) {
		t.Fatalf("agent without internal marker: %v", err)
	}
	source := filepath.Join(t.TempDir(), "wireguard.conf")
	writeQuick(t, source, testKey(t))
	stream, err := dialAgent(source)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close() // Keep the child active while ps reads its command line.
	output, err := exec.Command("ps", "-axww", "-o", "args=").Output()
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(output), "\n") {
		if strings.Contains(line, source) {
			t.Logf("agent process: %s", strings.TrimSpace(line))
			if !strings.HasSuffix(strings.TrimSpace(line), " agent") || strings.Contains(line, " list-machines") {
				t.Fatalf("want agent command word without list-machines: %s", line)
			}
			return
		}
	}
	t.Fatal("agent process not found in ps output")
}

func TestMultipleClientsStartOneAgent(t *testing.T) {
	key := testKey(t)
	server := startServer(t, key, "10.20.1.1")
	source := filepath.Join(t.TempDir(), "wireguard.conf")
	writeQuick(t, source, key, server.machine)
	source, err := filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := socketPath(source)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan struct {
		stream *net.UnixConn
		err    error
	}, 4)
	for range 4 {
		go func() {
			<-start
			stream, err := dialAgent(source)
			results <- struct {
				stream *net.UnixConn
				err    error
			}{stream, err}
		}()
	}
	close(start)
	var streams []*net.UnixConn
	for range 4 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		streams = append(streams, result.stream)
		t.Cleanup(func() { result.stream.Close() })
	}
	for i, stream := range streams {
		json.NewEncoder(stream).Encode(agentRequest{Command: "proxy-ssh", Host: "10.20.1.1", Port: 22})
		reader := bufio.NewReader(stream)
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		var response agentResponse
		if err := json.Unmarshal([]byte(line), &response); err != nil {
			t.Fatal(err)
		}
		if response.Error != "" {
			t.Fatal(response.Error)
		}
		exchange(t, stream, fmt.Sprintf("client %d\n", i))
	}
	// If competing starts used different devices, later handshakes would break
	// earlier streams because the server associates each key with one session.
	for i, stream := range streams {
		exchange(t, stream, fmt.Sprintf("client %d still shares the agent\n", i))
		stream.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Lstat(socket); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("test child did not exit after its shortened idle interval")
		}
		time.Sleep(20 * time.Millisecond)
	}
	os.Remove(socket + ".lock")
}

func TestQuickAllowedIPsChooseMostSpecificPeer(t *testing.T) {
	key := testKey(t)
	broad := machine{PublicKey: publicKey(testKey(t)), Endpoint: "127.0.0.1:443", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.20.1.0/24")}}
	specific := machine{PublicKey: publicKey(testKey(t)), Endpoint: "127.0.0.1:444", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.20.1.0/32")}}
	source := filepath.Join(t.TempDir(), "wireguard.conf")
	writeQuick(t, source, key, broad, specific)
	config, err := readConfiguration(source)
	if err != nil {
		t.Fatal(err)
	}
	got, address, err := config.findMachine("10.20.1.0", source)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicKey != specific.PublicKey || address.String() != "10.20.1.0" {
		t.Fatal("peer selection did not use the most specific AllowedIPs prefix")
	}
	got, address, err = config.findMachine("10.20.1.27", source)
	if err != nil || got.PublicKey != broad.PublicKey || address.String() != "10.20.1.27" {
		t.Fatal("peer selection did not preserve the target inside an AllowedIPs subnet")
	}
}

func TestProxyClosesOutputWhileInputIsIdle(t *testing.T) {
	key := testKey(t)
	const payload = "server output before closing\n"
	server := startServer(t, key, "10.20.1.1", func(stream net.Conn) {
		io.WriteString(stream, payload)
	})
	source := filepath.Join(t.TempDir(), "wireguard.conf")
	writeQuick(t, source, key, server.machine)
	startTestAgent(t, source, time.Minute)
	input, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close(); inputWriter.Close() })
	outputReader, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { outputReader.Close(); output.Close() })
	done := make(chan error, 1)
	go func() {
		done <- run([]string{"--wireguard-config", source, "proxy-ssh", "10.20.1.1", "22"}, input, output)
	}()
	if err := outputReader.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(outputReader)
	if err != nil {
		t.Fatalf("proxy output did not reach EOF while input stayed open: %v (received %q)", err, data)
	}
	if string(data) != payload {
		t.Fatalf("proxy output %q, want %q", data, payload)
	}
	inputWriter.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not finish after input ended")
	}
}

func TestProxyQuietlyEndsWhenLaterInputReachesClosedStream(t *testing.T) {
	key := testKey(t)
	const payload = "server output before closing\n"
	server := startServer(t, key, "10.20.1.1", func(stream net.Conn) {
		io.WriteString(stream, payload)
	})
	source := filepath.Join(t.TempDir(), "wireguard.conf")
	writeQuick(t, source, key, server.machine)
	startTestAgent(t, source, time.Minute)
	input, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close(); inputWriter.Close() })
	outputReader, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { outputReader.Close(); output.Close() })
	done := make(chan error, 1)
	go func() {
		done <- run([]string{"--wireguard-config", source, "proxy-ssh", "10.20.1.1", "22"}, input, output)
	}()
	deadline := time.Now().Add(5 * time.Second)
	if err := outputReader.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(outputReader)
	if err != nil || string(data) != payload {
		t.Fatalf("proxy output = %q, error = %v", data, err)
	}
	if err := inputWriter.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	// A full server close first ends output. Later input makes the agent's
	// network copy fail, closing the Unix stream while input is still open.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			return
		case <-ticker.C:
			if time.Now().After(deadline) {
				t.Fatal("proxy did not finish after later input reached the closed stream")
			}
			if _, err := io.WriteString(inputWriter, "ssh's last bytes\n"); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestProxyWaitsForInputAfterServerOutputEnds(t *testing.T) {
	key := testKey(t)
	outputEnded := make(chan struct{})
	received := make(chan string, 1)
	server := startServer(t, key, "10.20.1.1", func(stream net.Conn) {
		stream.SetDeadline(time.Now().Add(5 * time.Second))
		closeWrite(stream)
		close(outputEnded)
		data, err := io.ReadAll(stream)
		if err != nil {
			received <- "read failed: " + err.Error()
			return
		}
		received <- string(data)
	})
	source := filepath.Join(t.TempDir(), "wireguard.conf")
	writeQuick(t, source, key, server.machine)
	startTestAgent(t, source, time.Minute)
	input, writer := io.Pipe()
	t.Cleanup(func() { input.Close(); writer.Close() })
	done := make(chan error, 1)
	go func() {
		done <- run([]string{"--wireguard-config", source, "proxy-ssh", "10.20.1.1", "22"}, input, io.Discard)
	}()
	select {
	case <-outputEnded:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not end output")
	}
	select {
	case err := <-done:
		t.Fatalf("proxy returned before input ended: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	payload := "input delivered after server output ends\x00\xff"
	if _, err := io.WriteString(writer, payload); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	select {
	case got := <-received:
		if got != payload {
			t.Fatalf("server received %q, want %q", got, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive remaining input")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not finish after both directions ended")
	}
}

type failingCopyReader struct{ err error }

func (r failingCopyReader) Read([]byte) (int, error) { return 0, r.err }

type failingCopyWriter struct{ err error }

func (w failingCopyWriter) Write([]byte) (int, error) { return 0, w.err }

func TestProxyReportsCopyErrors(t *testing.T) {
	for _, direction := range []string{"input", "output"} {
		t.Run(direction, func(t *testing.T) {
			key := testKey(t)
			server := startServer(t, key, "10.20.1.1")
			source := filepath.Join(t.TempDir(), "wireguard.conf")
			writeQuick(t, source, key, server.machine)
			startTestAgent(t, source, time.Minute)
			failure := errors.New("test " + direction + " copy failure")
			var input io.Reader = strings.NewReader("hello")
			var output io.Writer = io.Discard
			if direction == "input" {
				input = failingCopyReader{failure}
			} else {
				output = failingCopyWriter{failure}
			}
			done := make(chan error, 1)
			go func() {
				done <- run([]string{"--wireguard-config", source, "proxy-ssh", "10.20.1.1", "22"}, input, output)
			}()
			select {
			case err := <-done:
				if !errors.Is(err, failure) {
					t.Fatalf("copy error = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("copy failure did not unblock the other direction")
			}
		})
	}
}

func TestQuickUnsupportedSettingNamesSectionAndFile(t *testing.T) {
	for _, test := range []struct{ section, setting, supported string }{
		{"Interface", "DNS", "PrivateKey and Address"},
		{"Peer", "PersistentKeepalive", "PublicKey, Endpoint, and AllowedIPs"},
	} {
		t.Run(test.section, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "wireguard.conf")
			data := "[Interface]\n"
			if test.section == "Peer" {
				data += "[Peer]\n"
			}
			data += test.setting + " = 1\n"
			os.WriteFile(source, []byte(data), 0600)
			_, err := readConfiguration(source)
			want := fmt.Sprintf("unsupported setting %s in [%s] of %s; [%s] supports %s", test.setting, test.section, source, test.section, test.supported)
			if err == nil || err.Error() != want {
				t.Fatalf("error = %v, want %q", err, want)
			}
		})
	}
}

func TestLaptopIdentityChangeRestartsAgentWithoutWaiting(t *testing.T) {
	for _, change := range []string{"key", "address"} {
		for _, openConnection := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_other_connection_%t", change, openConnection), func(t *testing.T) {
				oldKey := testKey(t)
				server := startServer(t, oldKey, "10.20.1.1")
				source := filepath.Join(t.TempDir(), "wireguard.conf")
				writeQuick(t, source, oldKey, server.machine)
				a, socket, done := startTestAgent(t, source, time.Minute)
				var held net.Conn
				if openConnection {
					held = agentConnection(t, socket, "10.20.1.1")
					exchange(t, held, "old identity before change\n")
				}
				newKey := oldKey
				address := "10.20.9.1"
				if change == "key" {
					newKey = testKey(t)
				} else {
					address = "10.20.9.2"
				}
				writeQuick(t, source, newKey, server.machine)
				if change == "address" {
					data, _ := os.ReadFile(source)
					data = bytes.ReplaceAll(data, []byte("10.20.9.1/24"), []byte(address+"/24"))
					os.WriteFile(source, data, 0600)
				}
				invoke := func() (string, error) {
					var output bytes.Buffer
					err := run([]string{"--wireguard-config", source, "proxy-ssh", "10.20.1.1", "22"}, strings.NewReader("new identity\n"), &output)
					return output.String(), err
				}
				if openConnection {
					_, err := invoke()
					want := "this laptop's WireGuard key or address changed; close this laptop's other SSH connections through doubleshell, then connect again"
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("identity-change error = %v", err)
					}
					exchange(t, held, "old identity still works after rejected change\n")
					select {
					case err := <-done:
						t.Fatalf("agent stopped with an open stream: %v", err)
					default:
					}
					held.Close()
					// Wait for the existing request's actual teardown, rather than sleeping
					// an assumed amount before testing the now-idle identity transition.
					deadline := time.Now().Add(5 * time.Second)
					for {
						a.mu.Lock()
						active := a.active
						a.mu.Unlock()
						if active == 0 {
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("closed connection did not finish")
						}
						time.Sleep(time.Millisecond)
					}
				}
				update := "public_key=" + keyHex(publicKey(oldKey)) + "\nremove=true\npublic_key=" + keyHex(publicKey(newKey)) + "\nallowed_ip=" + address + "/32\n"
				if err := server.device.IpcSet(update); err != nil {
					t.Fatal(err)
				}
				result := make(chan struct {
					output string
					err    error
				}, 1)
				go func() {
					output, err := invoke()
					result <- struct {
						output string
						err    error
					}{output, err}
				}()
				select {
				case got := <-result:
					if got.err != nil || got.output != "new identity\n" {
						t.Fatalf("new identity connection: %q, %v", got.output, got.err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("identity change waited instead of restarting immediately")
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("old agent did not exit for the new identity")
				}
				if (&tunnel{device: server.device}).lastHandshakes()[publicKey(newKey)].IsZero() {
					t.Fatal("server did not complete a handshake using the new identity")
				}
				// Spawned test agents have a shortened idle interval. Observe socket
				// disappearance without making more connections that would extend it.
				deadline := time.Now().Add(3 * time.Second)
				for {
					if _, err := os.Lstat(socket); os.IsNotExist(err) {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("replacement test agent did not exit when idle")
					}
					time.Sleep(20 * time.Millisecond)
				}
			})
		}
	}
}

func TestRunningAgentProcessReportsIdentityRestart(t *testing.T) {
	oldKey, newKey := testKey(t), testKey(t)
	server := startServer(t, oldKey, "10.20.1.1")
	source := filepath.Join(t.TempDir(), "wireguard.conf")
	writeQuick(t, source, oldKey, server.machine)
	source, err := filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := dialAgent(source)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	writeQuick(t, source, newKey, server.machine)
	if err := server.device.IpcSet("public_key=" + keyHex(publicKey(oldKey)) + "\nremove=true\npublic_key=" + keyHex(publicKey(newKey)) + "\nallowed_ip=10.20.9.1/32\n"); err != nil {
		t.Fatal(err)
	}
	pending.SetDeadline(time.Now().Add(5 * time.Second))
	json.NewEncoder(pending).Encode(agentRequest{Command: "proxy-ssh", Host: "10.20.1.1", Port: 22})
	var response agentResponse
	if err := json.NewDecoder(pending).Decode(&response); err != nil {
		t.Fatalf("agent process exited before reporting restart: %v", err)
	}
	if !response.RestartAgent || response.Error != "" {
		t.Fatalf("restart response: %+v", response)
	}
	pending.Close()
	var output bytes.Buffer
	if err := run([]string{"--wireguard-config", source, "proxy-ssh", "10.20.1.1", "22"}, strings.NewReader("new agent process\n"), &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "new agent process\n" {
		t.Fatalf("replacement process output %q", output.String())
	}
	socket, err := socketPath(source)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Lstat(socket); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replacement process did not become idle")
		}
		time.Sleep(20 * time.Millisecond)
	}
	os.Remove(socket + ".lock")
}

func TestCreateServerWireGuardKeyPrintsPairWithoutSaving(t *testing.T) {
	home, working := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(working)
	for _, directory := range []string{home, working} {
		if err := os.WriteFile(filepath.Join(directory, "existing_file"), []byte("unchanged"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var previous [32]byte
	for range 2 {
		var output bytes.Buffer
		if err := run([]string{"create-server-wireguard-key"}, nil, &output); err != nil {
			t.Fatal(err)
		}
		var pair map[string]string
		decoder := json.NewDecoder(&output)
		if err := decoder.Decode(&pair); err != nil {
			t.Fatal("command did not print a JSON key pair")
		}
		if len(pair) != 2 || pair["private_key"] == "" || pair["public_key"] == "" {
			t.Fatal("key pair must contain only private_key and public_key")
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			t.Fatal("key command printed more than one JSON object")
		}
		private, err := decodeKey(pair["private_key"])
		if err != nil {
			t.Fatal("invalid private key encoding")
		}
		public, err := decodeKey(pair["public_key"])
		if err != nil {
			t.Fatal("invalid public key encoding")
		}
		if private[0]&7 != 0 || private[31]&128 != 0 || private[31]&64 == 0 {
			t.Fatal("private key is not clamped as wg genkey requires")
		}
		independent, err := ecdh.X25519().NewPrivateKey(private[:])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(independent.PublicKey().Bytes(), public[:]) {
			t.Fatal("public key does not match the private key")
		}
		if private == previous {
			t.Fatal("command reused a private key")
		}
		previous = private
	}
	for _, directory := range []string{home, working} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Name() != "existing_file" {
			t.Fatal("server key command saved a file or created a directory")
		}
		content, err := os.ReadFile(filepath.Join(directory, "existing_file"))
		if err != nil || string(content) != "unchanged" {
			t.Fatal("server key command changed an existing file")
		}
	}
	var output bytes.Buffer
	err := run([]string{"create-server-wireguard-key", "unexpected"}, nil, &output)
	if err == nil || err.Error() != "usage: doubleshell create-server-wireguard-key" || output.Len() != 0 {
		t.Fatalf("unexpected command argument: %v", err)
	}
}

func TestVersionCommandPrintsVersion(t *testing.T) {
	var printed bytes.Buffer
	if err := run([]string{"version"}, nil, &printed); err != nil {
		t.Fatal(err)
	}
	if want := "doubleshell " + version + "\n"; printed.String() != want {
		t.Fatalf("version printed %q, want %q", printed.String(), want)
	}
	if err := run([]string{"version", "extra"}, nil, io.Discard); err == nil {
		t.Fatal("version accepted an extra argument")
	}
}
