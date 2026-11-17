package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

var agentIdleTimeout = idleTimeout

// version is the release version. The release build sets it with
// -ldflags "-X main.version=VERSION".
var version = "0.1.0-dev"

const usage = `usage:
  doubleshell --wireguard-config FILE proxy-ssh HOST PORT
  doubleshell --wireguard-config FILE list-machines
  doubleshell create-wireguard-key [--replace-existing-key]
  doubleshell create-server-wireguard-key
  doubleshell version`

const help = usage + `

--wireguard-config FILE names a wg-quick file. Without PrivateKey in
[Interface], the file uses the key that create-wireguard-key saved.`

func run(args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("doubleshell", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("wireguard-config", "", "read this wg-quick file")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(output, help)
			return nil
		}
		return fmt.Errorf("%w\n%s", err, usage)
	}
	args = flags.Args()
	if len(args) == 0 {
		return errors.New(usage)
	}
	request := agentRequest{Command: args[0]}
	switch args[0] {
	case "create-wireguard-key":
		replace := len(args) == 2 && args[1] == "--replace-existing-key"
		if len(args) != 1 && !replace {
			return fmt.Errorf("usage: doubleshell create-wireguard-key [--replace-existing-key]")
		}
		return createKey(output, replace)
	case "version":
		if len(args) != 1 {
			return fmt.Errorf("usage: doubleshell version")
		}
		fmt.Fprintf(output, "doubleshell %s\n", version)
		return nil
	case "create-server-wireguard-key":
		if len(args) != 1 {
			return fmt.Errorf("usage: doubleshell create-server-wireguard-key")
		}
		return printServerKey(output)
	case "proxy-ssh":
		if len(args) != 3 {
			return fmt.Errorf("usage: doubleshell --wireguard-config FILE proxy-ssh HOST PORT")
		}
		port, err := strconv.ParseUint(args[2], 10, 16)
		if err != nil || port == 0 {
			return fmt.Errorf("%s, SSH port %s: SSH port must be from 1 to 65535", args[1], args[2])
		}
		request.Host, request.Port = args[1], uint16(port)
	case "list-machines":
		if len(args) != 1 {
			return fmt.Errorf("usage: doubleshell --wireguard-config FILE list-machines")
		}
	case "agent":
		// The client starts the agent with the canonical file path; see dialAgent.
		if os.Getenv(internalAgentEnv) == "1" {
			return runAgent(*configPath)
		}
		fallthrough
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
	if *configPath == "" {
		return fmt.Errorf("%s needs --wireguard-config FILE before the command, naming a wg-quick file", args[0])
	}
	source, err := filepath.Abs(*configPath)
	if err == nil {
		// The resolved path identifies the agent, so every name for one file shares it.
		source, err = filepath.EvalSymlinks(source)
	}
	if err != nil {
		return request.describe(fmt.Errorf("read %s: %w", *configPath, err))
	}
	return runClient(source, request, input, output)
}

// runAgent is the detached agent process. It reports startup on file
// descriptor 3, which the starting client reads.
func runAgent(source string) error {
	startup := os.NewFile(3, "agent-startup")
	defer startup.Close()
	ready := func(err error) {
		response := agentResponse{}
		if err != nil {
			response.Error = err.Error()
		}
		json.NewEncoder(startup).Encode(response)
		startup.Close()
	}
	socket, err := socketPath(source)
	if err != nil {
		ready(err)
		return err
	}
	return (&agent{source: source, idle: agentIdleTimeout}).serve(socket, ready)
}

// runClient sends one request to the agent and then prints the machine list
// or carries the SSH stream.
func runClient(source string, request agentRequest, input io.Reader, output io.Writer) error {
	for {
		stream, err := dialAgent(source)
		if err != nil {
			return request.describe(err)
		}
		defer stream.Close()
		if err := json.NewEncoder(stream).Encode(request); err != nil {
			return request.describe(err)
		}
		reader := bufio.NewReader(stream)
		line, err := reader.ReadString('\n')
		if err != nil {
			return request.describe(fmt.Errorf("read doubleshell agent response: %w", err))
		}
		var response agentResponse
		if err := json.Unmarshal([]byte(line), &response); err != nil {
			return request.describe(err)
		}
		if response.RestartAgent {
			stream.Close()
			continue // No SSH input has been consumed; the old device is fully closed.
		}
		if response.Error != "" {
			return errors.New(response.Error)
		}
		if request.Command == "list-machines" {
			return printMachines(output, response.Machines)
		}
		if err := carrySSH(stream, reader, input, output); err != nil {
			return request.describe(err)
		}
		return nil
	}
}

func printMachines(output io.Writer, machines []machineStatus) error {
	fmt.Fprintln(output, "wireguard_address\tendpoint\tlast_wireguard_handshake")
	for _, m := range machines {
		handshake := "never"
		if !m.LastWireGuardHandshake.IsZero() {
			handshake = m.LastWireGuardHandshake.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
		}
		if _, err := fmt.Fprintf(output, "%s\t%s\t%s\n", m.Address, m.Endpoint, handshake); err != nil {
			return err
		}
	}
	return nil
}

// carrySSH copies standard input to the agent and the agent's bytes to
// standard output, until both directions end.
func carrySSH(stream *net.UnixConn, fromAgent io.Reader, input io.Reader, output io.Writer) error {
	copies := make(chan error, 2)
	outputEnded := make(chan struct{})
	go func() {
		_, err := io.Copy(stream, input)
		if err == nil {
			err = stream.CloseWrite()
		}
		var operation *net.OpError
		if errors.As(err, &operation) && operation.Op == "write" &&
			(errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, net.ErrClosed)) {
			select {
			case <-outputEnded:
				err = nil // OpenSSH already saw the server's output end.
			default:
			}
		}
		copies <- err
	}()
	go func() {
		_, err := io.Copy(output, fromAgent)
		if err == nil {
			close(outputEnded)
			// Closing standard output lets an idle OpenSSH see the end.
			if closer, ok := output.(io.Closer); ok {
				err = closer.Close()
			}
		}
		copies <- err
	}()
	for range 2 {
		if err := <-copies; err != nil {
			stream.Close() // Unblock the remaining network copy on failure.
			return err
		}
	}
	return nil
}

func printServerKey(output io.Writer) error {
	private, err := newWireGuardPrivateKey()
	if err != nil {
		return err
	}
	public := publicKey(private)
	return json.NewEncoder(output).Encode(struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
	}{base64.StdEncoding.EncodeToString(private[:]), base64.StdEncoding.EncodeToString(public[:])})
}

func createKey(output io.Writer, replace bool) error {
	path, err := keyPath()
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("WireGuard key directory %s must not be a symlink", directory)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return err
	}
	if replace {
		// Refuse symlinks before replacement. Write a fresh inode and rename so a
		// failed write cannot destroy the working private key.
		if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("%s must be a regular private key file", path)
		}
	}
	private, err := newWireGuardPrivateKey()
	if err != nil {
		return err
	}
	var file *os.File
	if replace {
		file, err = os.CreateTemp(directory, ".wireguard_private_key-*")
	} else {
		file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	}
	if os.IsExist(err) {
		return fmt.Errorf("%s already exists; use doubleshell create-wireguard-key --replace-existing-key only when replacing this laptop's key", path)
	}
	if err != nil {
		return err
	}
	if replace {
		defer os.Remove(file.Name())
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	_, err = fmt.Fprintln(file, base64.StdEncoding.EncodeToString(private[:]))
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if replace {
		if err := os.Rename(file.Name(), path); err != nil {
			return err
		}
	}
	public := publicKey(private)
	_, err = fmt.Fprintln(output, base64.StdEncoding.EncodeToString(public[:]))
	return err
}

func newWireGuardPrivateKey() ([32]byte, error) {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return [32]byte{}, err
	}
	// WireGuard's genkey clamps the scalar before encoding the private key.
	private[0] &= 248
	private[31] = private[31]&127 | 64
	return private, nil
}
