package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const idleTimeout = 10 * time.Minute

// startupConnectWindow is how long a client that started an agent keeps
// trying to connect after the agent reports ready. The new agent stays at
// least this long, so a short idle interval cannot close it before that
// client arrives.
const startupConnectWindow = 3 * time.Second

const internalAgentEnv = "DOUBLESHELL_INTERNAL_AGENT"

type agentRequest struct {
	Command string `json:"command"`
	Host    string `json:"host"`
	Port    uint16 `json:"ssh_port"`
}

func (r agentRequest) describe(err error) error {
	if r.Command == "list-machines" {
		return fmt.Errorf("list-machines: %w", err)
	}
	return fmt.Errorf("%s, SSH port %d: %w", r.Host, r.Port, err)
}

type agentResponse struct {
	Error        string          `json:"error,omitempty"`
	Machines     []machineStatus `json:"machines,omitempty"`
	RestartAgent bool            `json:"restart_agent,omitempty"`
}

type agent struct {
	source   string
	mu       sync.Mutex
	tunnel   *tunnel
	listener *net.UnixListener
	active   int
	idle     time.Duration
	stopping bool
	stopped  chan struct{}
}

// socketDirectory is the same for every program the person runs, whatever
// its environment, so a terminal and a coding agent share one agent; and it
// is private to the account, so another account cannot create it first.
// macOS gives each account a private temporary directory, which getconf
// reports even when TMPDIR is unset or changed. On Linux, systemd keeps
// /run/user/UID for the account while it is logged in; XDG_RUNTIME_DIR names
// it only in some programs. The shared /tmp is the last fallback.
func socketDirectory() string {
	switch runtime.GOOS {
	case "darwin":
		if output, err := exec.Command("/usr/bin/getconf", "DARWIN_USER_TEMP_DIR").Output(); err == nil {
			if parent := strings.TrimSpace(string(output)); parent != "" {
				return filepath.Join(parent, "doubleshell")
			}
		}
	case "linux":
		parent := filepath.Join("/run/user", strconv.Itoa(os.Getuid()))
		if info, err := os.Stat(parent); err == nil && info.IsDir() {
			return filepath.Join(parent, "doubleshell")
		}
	}
	return filepath.Join("/tmp", "doubleshell-"+strconv.Itoa(os.Getuid()))
}

func socketPath(source string) (string, error) {
	directory := socketDirectory()
	if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm() != 0700 || !ok || stat.Uid != uint32(os.Getuid()) {
		return "", fmt.Errorf("agent socket directory %s must be owned by this user with mode 0700 and must not be a symlink", directory)
	}
	hash := sha256.Sum256([]byte(source))
	return filepath.Join(directory, hex.EncodeToString(hash[:16])+".sock"), nil
}

func (a *agent) refresh() error {
	c, err := readConfiguration(a.source)
	if err != nil {
		return err
	}
	if a.tunnel == nil {
		a.tunnel, err = newTunnel(c)
	} else if c.Fingerprint != a.tunnel.config.Fingerprint {
		err = a.tunnel.update(c)
	}
	return err
}

// serve owns the exclusive lock until the socket has closed. Competing starts
// cannot unlink a live agent's socket, including during an idle shutdown.
func (a *agent) serve(socket string, ready func(error)) error {
	var handlers sync.WaitGroup
	// A process must not exit until pending clients receive the restart response.
	// Resource cleanup runs first, then releases handlers waiting on stopped.
	defer handlers.Wait()
	a.stopped = make(chan struct{})
	defer close(a.stopped)
	lock, err := os.OpenFile(socket+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		ready(err)
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			ready(nil)
			return nil
		}
		ready(err)
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	// Only an agent holding the exclusive lock may remove a stale socket.
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		ready(err)
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		ready(err)
		return err
	}
	a.listener = listener
	defer listener.Close()
	if err := os.Chmod(socket, 0600); err != nil {
		ready(err)
		return err
	}
	if err := a.refresh(); err != nil {
		ready(err)
		return err
	}
	defer a.tunnel.device.Close()
	a.listener.SetDeadline(time.Now().Add(max(a.idle, startupConnectWindow)))
	ready(nil)
	for {
		stream, err := listener.AcceptUnix()
		if err != nil {
			a.mu.Lock()
			idle, stopping := a.active == 0, a.stopping
			a.mu.Unlock()
			if stopping {
				return nil
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() && !idle {
				continue
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				return nil
			}
			return err
		}
		a.mu.Lock()
		a.active++
		listener.SetDeadline(time.Time{})
		a.mu.Unlock()
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer func() {
				stream.Close()
				a.mu.Lock()
				a.active--
				if a.active == 0 {
					listener.SetDeadline(time.Now().Add(a.idle))
				}
				a.mu.Unlock()
			}()
			a.handle(stream)
		}()
	}
}

func (a *agent) handle(stream *net.UnixConn) {
	reader := bufio.NewReader(stream)
	stream.SetReadDeadline(time.Now().Add(handshakeWait))
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	stream.SetReadDeadline(time.Time{})
	var request agentRequest
	if err := json.Unmarshal([]byte(line), &request); err != nil {
		json.NewEncoder(stream).Encode(agentResponse{Error: "invalid agent request"})
		return
	}
	fail := func(err error) { json.NewEncoder(stream).Encode(agentResponse{Error: err.Error()}) }
	a.mu.Lock()
	restart := func() {
		a.mu.Unlock()
		<-a.stopped
		json.NewEncoder(stream).Encode(agentResponse{RestartAgent: true})
	}
	if a.stopping {
		restart()
		return
	}
	err = a.refresh()
	if errors.Is(err, errLaptopIdentityChanged) && a.active == 1 {
		a.stopping = true
		a.listener.Close()
		restart()
		return
	}
	if err != nil {
		a.mu.Unlock()
		fail(request.describe(err))
		return
	}
	t := a.tunnel
	var target connectionTarget
	var others []connectionTarget
	if request.Command == "proxy-ssh" {
		m, address, err := t.config.findMachine(request.Host, a.source)
		if err != nil {
			a.mu.Unlock()
			fail(request.describe(err))
			return
		}
		target = connectionTarget{machine: m, address: address, port: request.Port, lock: t.peerLocks[m.PublicKey]}
	}
	for _, m := range t.config.Machines {
		if request.Command == "proxy-ssh" && m.PublicKey == target.machine.PublicKey {
			continue
		}
		others = append(others, connectionTarget{machine: m, address: m.address(), lock: t.peerLocks[m.PublicKey]})
	}
	a.mu.Unlock()
	switch request.Command {
	case "proxy-ssh":
		remote, err := t.connect(context.Background(), target, others)
		if err != nil {
			fail(err)
			return
		}
		defer remote.Close()
		if err := json.NewEncoder(stream).Encode(agentResponse{}); err != nil {
			return
		}
		relay(stream, reader, remote)
	case "list-machines":
		var group sync.WaitGroup
		for _, target := range others {
			group.Go(func() {
				ctx, cancel := context.WithTimeout(context.Background(), handshakeWait)
				defer cancel()
				t.handshake(ctx, target.machine, target.lock)
			})
		}
		group.Wait()
		handshakes := t.lastHandshakes()
		var statuses []machineStatus
		for _, target := range others {
			statuses = append(statuses, machineStatus{Address: target.address.String(), Endpoint: target.machine.Endpoint, LastWireGuardHandshake: handshakes[target.machine.PublicKey]})
		}
		json.NewEncoder(stream).Encode(agentResponse{Machines: statuses})
	default:
		fail(fmt.Errorf("unknown agent command %q", request.Command))
	}
}

func closeWrite(stream net.Conn) {
	if half, ok := stream.(interface{ CloseWrite() error }); ok {
		half.CloseWrite()
	}
}

func relay(client net.Conn, input io.Reader, remote net.Conn) {
	done := make(chan struct{})
	go func() {
		_, err := io.Copy(remote, input)
		closeWrite(remote)
		if err != nil {
			remote.Close()
		}
		close(done)
	}()
	_, err := io.Copy(client, remote)
	closeWrite(client)
	if err != nil {
		remote.Close()
		client.Close()
	}
	<-done
}

func dialAgent(source string) (*net.UnixConn, error) {
	socket, err := socketPath(source)
	if err != nil {
		return nil, err
	}
	dial := func() (*net.UnixConn, error) {
		return net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	}
	if stream, err := dial(); err == nil {
		return stream, nil
	}
	// Check the file here so its errors reach the person directly.
	if _, err := readConfiguration(source); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	child := exec.Command(executable, "--wireguard-config", source, "agent")
	child.Env = append(os.Environ(), internalAgentEnv+"=1")
	child.Dir = filepath.Dir(source)
	// The agent reports startup success or its exact error on this pipe.
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	child.ExtraFiles = []*os.File{writer}
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := child.Start(); err != nil {
		writer.Close()
		return nil, err
	}
	writer.Close()
	go child.Wait()
	reader.SetReadDeadline(time.Now().Add(15 * time.Second))
	var response agentResponse
	if err := json.NewDecoder(reader).Decode(&response); err != nil {
		return nil, fmt.Errorf("start doubleshell agent: %w", err)
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}
	deadline := time.Now().Add(startupConnectWindow)
	for {
		stream, err := dial()
		if err == nil {
			return stream, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("connect to doubleshell agent %s: %w", socket, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
