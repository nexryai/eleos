//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var envSeq int

type env struct {
	t   *testing.T
	bin string
	id  int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration tests must run as root (e.g. inside the privileged CI container)")
	}
	envSeq++
	return &env{t: t, bin: binaryPath(t), id: envSeq}
}

func binaryPath(t *testing.T) string {
	t.Helper()
	p := os.Getenv("ELCTL_BIN")
	if p == "" {
		p = filepath.Join("..", "elctl")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("failed to resolve elctl path: %v", err)
	}
	if st, err := os.Stat(abs); err != nil || st.IsDir() {
		t.Fatalf("elctl binary not found at %s; build it first (go build -o elctl main.go) or set ELCTL_BIN", abs)
	}
	return abs
}

// nsName and ifName generate short, unique names for namespaces/interfaces.
func (e *env) nsName(label string) string {
	return fmt.Sprintf("rs-%s-%d", label, e.id)
}

func (e *env) ifName(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, e.id)
}

func (e *env) run(name string, args ...string) (string, error) {
	e.t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func (e *env) must(name string, args ...string) string {
	e.t.Helper()
	out, err := e.run(name, args...)
	if err != nil {
		e.t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

// newNS creates a network namespace and registers its removal.
func (e *env) newNS(label string) string {
	e.t.Helper()
	name := e.nsName(label)
	_, _ = e.run("ip", "netns", "del", name)
	e.must("ip", "netns", "add", name)
	e.t.Cleanup(func() { _, _ = e.run("ip", "netns", "del", name) })
	return name
}

// veth connects two namespaces with a veth pair.
func (e *env) veth(nsA, ifA, nsB, ifB string) {
	e.t.Helper()
	_, _ = e.run("ip", "link", "del", ifA)
	_, _ = e.run("ip", "link", "del", ifB)
	e.must("ip", "link", "add", ifA, "type", "veth", "peer", "name", ifB)
	e.must("ip", "link", "set", ifA, "netns", nsA)
	e.must("ip", "link", "set", ifB, "netns", nsB)
	for _, ns := range []string{nsA, nsB} {
		e.must("ip", "-n", ns, "link", "set", "lo", "up")
	}
	e.must("ip", "-n", nsA, "link", "set", ifA, "up")
	e.must("ip", "-n", nsB, "link", "set", ifB, "up")
}

func (e *env) addr(ns, iface, cidr string) {
	e.t.Helper()
	e.must("ip", "-n", ns, "addr", "add", cidr, "dev", iface)
}

func (e *env) route(ns string, args ...string) {
	e.t.Helper()
	e.must("ip", append([]string{"-n", ns, "route", "add"}, args...)...)
}

func (e *env) writeConfig(content string) string {
	e.t.Helper()
	path := filepath.Join(e.t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		e.t.Fatalf("failed to write config: %v", err)
	}
	return path
}

// elctl runs the binary inside ns.
func (e *env) elctl(ns, configPath string, operation string) string {
	e.t.Helper()
	args := []string{"netns", "exec", ns, e.bin}
	if configPath != "" {
		args = append(args, "-f", configPath)
	}
	args = append(args, operation)
	return e.must("ip", args...)
}

func (e *env) ruleset(ns string) string {
	e.t.Helper()
	return e.must("ip", "netns", "exec", ns, "nft", "list", "table", "inet", "eleos")
}

func (e *env) tableExists(ns string) bool {
	e.t.Helper()
	_, err := e.run("ip", "netns", "exec", ns, "nft", "list", "table", "inet", "eleos")
	return err == nil
}

func (e *env) mustContain(ns string, substrings ...string) {
	e.t.Helper()
	ruleset := e.ruleset(ns)
	for _, sub := range substrings {
		if !strings.Contains(ruleset, sub) {
			e.t.Errorf("ruleset does not contain %q\n--- ruleset ---\n%s", sub, ruleset)
		}
	}
}

// helperArgs builds the arguments to run the test binary itself as a network
// helper inside the given namespace.
func (e *env) helperArgs(ns string, args ...string) []string {
	e.t.Helper()
	exe, err := os.Executable()
	if err != nil {
		e.t.Fatalf("failed to locate test binary: %v", err)
	}
	base := []string{"netns", "exec", ns, exe, "-test.run=TestHelperProcess", "--"}
	return append(base, args...)
}

func helperEnv() []string {
	return append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
}

// serve starts a helper listener in ns and waits until it is ready.
func (e *env) serve(ns, action, addr string) {
	e.t.Helper()
	cmd := exec.Command("ip", e.helperArgs(ns, action, addr)...)
	cmd.Env = helperEnv()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		e.t.Fatalf("failed to create pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		e.t.Fatalf("failed to start %s helper: %v", action, err)
	}
	e.t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "READY" {
				ready <- nil
				return
			}
		}
		ready <- fmt.Errorf("helper exited before becoming ready: %v", scanner.Err())
	}()

	select {
	case err := <-ready:
		if err != nil {
			e.t.Fatalf("%s(%s) failed: %v", action, addr, err)
		}
	case <-time.After(5 * time.Second):
		e.t.Fatalf("%s(%s) did not become ready in time", action, addr)
	}
}

// dial runs a helper client in ns and reports whether it connected.
func (e *env) dial(ns, action, addr string) error {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ip", e.helperArgs(ns, action, addr)...)
	cmd.Env = helperEnv()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (e *env) expectReachable(ns, action, addr string) {
	e.t.Helper()
	if err := e.dial(ns, action, addr); err != nil {
		e.t.Errorf("%s %s from %s: expected reachable, got: %v", action, addr, ns, err)
	}
}

func (e *env) expectBlocked(ns, action, addr string) {
	e.t.Helper()
	if err := e.dial(ns, action, addr); err == nil {
		e.t.Errorf("%s %s from %s: expected blocked, but it was reachable", action, addr, ns)
	}
}

func (e *env) ping(ns, addr string) error {
	e.t.Helper()
	_, err := e.run("ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "1", addr)
	return err
}

// TestInputPortSourceInterfaceAndDeny verifies source CIDR restrictions,
// interface restrictions and alwaysDenyIP on the input path.
func TestInputPortSourceInterfaceAndDeny(t *testing.T) {
	e := newEnv(t)
	srv := e.newNS("srv")
	cli := e.newNS("cli")
	bad := e.newNS("bad")

	ifS := e.ifName("vs")
	ifC := e.ifName("vc")
	ifW := e.ifName("ws")
	ifB := e.ifName("wc")
	e.veth(srv, ifS, cli, ifC)
	e.addr(srv, ifS, "10.0.0.1/24")
	e.addr(cli, ifC, "10.0.0.2/24")
	e.veth(srv, ifW, bad, ifB)
	e.addr(srv, ifW, "10.9.0.1/24")
	e.addr(bad, ifB, "10.9.0.2/24")
	// bad reaches 10.0.0.1 through the server so the firewall sees its traffic.
	e.route(bad, "10.0.0.0/24", "via", "10.9.0.1")

	cfg := e.writeConfig(fmt.Sprintf(`
default:
  allowAllIn: false
  allowAllOut: true
  allowAllFwd: false
  allowPing: true
  enableIPv6: false
  enableLogging: false

security:
  alwaysDenyIP: ["10.9.0.2"]

ports:
  - port: 8080
    proto: "tcp"
    allowIP: "10.0.0.0/24"
  - port: 8081
    proto: "tcp"
    allowInterface: "%s"
`, ifS))

	e.serve(srv, "tcp-echo", "0.0.0.0:8080")
	e.serve(srv, "tcp-echo", "0.0.0.0:8081")

	e.elctl(srv, cfg, "enable")
	e.mustContain(srv, "tcp dport 8080", "10.0.0.0/24", `iifname "`+ifS+`" tcp dport 8081`, "ip saddr 10.9.0.2 drop", "policy drop")

	e.expectReachable(cli, "tcp-dial", "10.0.0.1:8080")
	e.expectReachable(cli, "tcp-dial", "10.0.0.1:8081")

	// 10.9.0.2 is outside the allowed CIDR and also explicitly denied.
	e.expectBlocked(bad, "tcp-dial", "10.0.0.1:8080")
	// Arrives on the wrong interface, so the interface-restricted rule must not match.
	e.expectBlocked(bad, "tcp-dial", "10.9.0.1:8081")
}

// TestInputUDPAndPing verifies UDP port rules and the ping allow/deny rules.
func TestInputUDPAndPing(t *testing.T) {
	e := newEnv(t)
	srv := e.newNS("srv")
	cli := e.newNS("cli")
	ifS := e.ifName("vs")
	ifC := e.ifName("vc")
	e.veth(srv, ifS, cli, ifC)
	e.addr(srv, ifS, "10.0.0.1/24")
	e.addr(cli, ifC, "10.0.0.2/24")

	cfg := e.writeConfig(`
default:
  allowAllIn: false
  allowAllOut: true
  allowAllFwd: false
  allowPing: true
  enableIPv6: false
  enableLogging: false

ports:
  - port: 9090
    proto: "udp"
`)

	e.serve(srv, "udp-echo", "0.0.0.0:9090")
	e.serve(srv, "udp-echo", "0.0.0.0:9091")

	e.elctl(srv, cfg, "enable")
	e.mustContain(srv, "udp dport 9090", "icmp type echo-request")

	e.expectReachable(cli, "udp-dial", "10.0.0.1:9090")
	e.expectBlocked(cli, "udp-dial", "10.0.0.1:9091")
	if err := e.ping(cli, "10.0.0.1"); err != nil {
		t.Errorf("ping to the firewall host should be allowed: %v", err)
	}
}

// TestInputIPSetExpansion verifies that "$NAME" references are expanded from
// the configured ipsets.
func TestInputIPSetExpansion(t *testing.T) {
	e := newEnv(t)
	srv := e.newNS("srv")
	cli := e.newNS("cli")
	other := e.newNS("oth")
	ifS := e.ifName("vs")
	ifC := e.ifName("vc")
	ifW := e.ifName("ws")
	ifO := e.ifName("wc")
	e.veth(srv, ifS, cli, ifC)
	e.addr(srv, ifS, "10.0.0.1/24")
	e.addr(cli, ifC, "10.0.0.2/24")
	e.veth(srv, ifW, other, ifO)
	e.addr(srv, ifW, "10.0.1.1/24")
	e.addr(other, ifO, "10.0.1.2/24")

	cfg := e.writeConfig(`
default:
  allowAllIn: false
  allowAllOut: true
  allowAllFwd: false
  allowPing: true
  enableIPv6: false
  enableLogging: false

ipset:
  - name: "TRUSTED"
    ip: ["10.0.0.2"]

ports:
  - port: 8082
    proto: "tcp"
    allowIP: "$TRUSTED"
`)

	e.serve(srv, "tcp-echo", "0.0.0.0:8082")
	e.elctl(srv, cfg, "enable")
	e.mustContain(srv, "tcp dport 8082", "ip saddr 10.0.0.2")

	e.expectReachable(cli, "tcp-dial", "10.0.0.1:8082")
	e.expectBlocked(other, "tcp-dial", "10.0.1.1:8082")
}

// TestInputIPv6 verifies IPv6 address matching and neighbor discovery rules.
func TestInputIPv6(t *testing.T) {
	e := newEnv(t)
	srv := e.newNS("srv")
	cli := e.newNS("cli")
	ifS := e.ifName("vs")
	ifC := e.ifName("vc")
	e.veth(srv, ifS, cli, ifC)
	// nodad keeps the test deterministic; neighbor discovery is still
	// exercised on the first connection attempt.
	e.must("ip", "-n", srv, "addr", "add", "fd00::1/64", "dev", ifS, "nodad")
	e.must("ip", "-n", cli, "addr", "add", "fd00::2/64", "dev", ifC, "nodad")

	cfg := e.writeConfig(`
default:
  allowAllIn: false
  allowAllOut: true
  allowAllFwd: false
  allowPing: true
  enableIPv6: true
  enableLogging: false

ports:
  - port: 8083
    proto: "tcp"
    allowIP: "fd00::/64"
`)

	e.serve(srv, "tcp-echo", "[::]:8083")
	e.serve(srv, "tcp-echo", "[::]:8084")

	// IPv6 neighbor discovery needs a moment over a fresh veth pair.
	time.Sleep(500 * time.Millisecond)

	e.elctl(srv, cfg, "enable")
	e.mustContain(srv, "ip6 saddr fd00::/64", "tcp dport 8083", "nd-neighbor-solicit")

	e.expectReachable(cli, "tcp-dial", "[fd00::1]:8083")
	e.expectBlocked(cli, "tcp-dial", "[fd00::1]:8084")
	if err := e.ping(cli, "fd00::1"); err != nil {
		t.Errorf("IPv6 ping should be allowed: %v", err)
	}
}

// TestOutputAllowedPorts verifies that only explicitly allowed outbound ports
// leave the firewall host when allowAllOut is false.
func TestOutputAllowedPorts(t *testing.T) {
	e := newEnv(t)
	srv := e.newNS("srv")
	cli := e.newNS("cli")
	ifS := e.ifName("vs")
	ifC := e.ifName("vc")
	e.veth(srv, ifS, cli, ifC)
	e.addr(srv, ifS, "10.0.0.1/24")
	e.addr(cli, ifC, "10.0.0.2/24")

	cfg := e.writeConfig(`
default:
  allowAllIn: false
  allowAllOut: false
  allowAllFwd: false
  allowPing: true
  enableIPv6: false
  enableLogging: false

outbound:
  allowed:
    - dport: 7000
      proto: "tcp"
`)

	e.serve(cli, "tcp-echo", "0.0.0.0:7000")
	e.serve(cli, "tcp-echo", "0.0.0.0:7001")

	e.elctl(srv, cfg, "enable")
	e.mustContain(srv, "tcp dport 7000", "policy drop")

	e.expectReachable(srv, "tcp-dial", "10.0.0.2:7000")
	e.expectBlocked(srv, "tcp-dial", "10.0.0.2:7001")
}

// TestRouterNATAndPortForward verifies forwarding, masquerading and DNAT.
func TestRouterNATAndPortForward(t *testing.T) {
	e := newEnv(t)
	rtr := e.newNS("rtr")
	lan := e.newNS("lan")
	wan := e.newNS("wan")
	ifLanR := e.ifName("lr")
	ifLanH := e.ifName("lh")
	ifWanR := e.ifName("wr")
	ifWanH := e.ifName("wh")
	e.veth(rtr, ifLanR, lan, ifLanH)
	e.addr(rtr, ifLanR, "10.0.0.1/24")
	e.addr(lan, ifLanH, "10.0.0.2/24")
	e.veth(rtr, ifWanR, wan, ifWanH)
	e.addr(rtr, ifWanR, "192.0.2.1/24")
	e.addr(wan, ifWanH, "192.0.2.2/24")
	e.route(lan, "default", "via", "10.0.0.1")

	e.must("ip", "netns", "exec", rtr, "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")

	cfg := e.writeConfig(fmt.Sprintf(`
default:
  allowAllIn: false
  allowAllOut: false
  allowAllFwd: false
  allowPing: true
  enableIPv6: false
  enableLogging: false

router:
  configAsRouter: true
  wanInterface: "%s"
  privateNetworks: ["10.0.0.0/24"]
  lanInterfaces: ["%s"]

nat:
  - interface: "%s"
    allowIP: "192.0.2.0/24"
    dstIP: "192.0.2.1"
    dstPort: "8085"
    proto: "tcp"
    natTo: "10.0.0.2:8085"
`, ifWanR, ifLanR, ifWanR))

	// 10.0.0.2:8085 is the DNAT target, 10.0.0.2:8086 the masquerade target.
	e.serve(lan, "tcp-echo", "0.0.0.0:8085")
	e.serve(wan, "tcp-echo", "0.0.0.0:8086")

	e.elctl(rtr, cfg, "enable")
	e.mustContain(rtr,
		"masquerade",
		"dnat",
		"10.0.0.2:8085",
		"snat",
		`iifname "`+ifLanR+`" accept`,
		"chain forward",
		"chain prerouting",
		"chain postrouting",
	)

	// Port forwarding: WAN client reaches the LAN host through DNAT.
	e.expectReachable(wan, "tcp-dial", "192.0.2.1:8085")
	// Masquerading: LAN host reaches the WAN host with the router's address.
	e.expectReachable(lan, "tcp-dial", "192.0.2.2:8086")

	// Re-applying must be idempotent and keep working.
	e.elctl(rtr, cfg, "enable")
	e.elctl(rtr, cfg, "apply")
	e.expectReachable(wan, "tcp-dial", "192.0.2.1:8085")
	e.expectReachable(lan, "tcp-dial", "192.0.2.2:8086")
}

// TestDisableRestoresConnectivity verifies that disable removes the table and
// that the default-drop policy is no longer in effect.
func TestDisableRestoresConnectivity(t *testing.T) {
	e := newEnv(t)
	srv := e.newNS("srv")
	cli := e.newNS("cli")
	ifS := e.ifName("vs")
	ifC := e.ifName("vc")
	e.veth(srv, ifS, cli, ifC)
	e.addr(srv, ifS, "10.0.0.1/24")
	e.addr(cli, ifC, "10.0.0.2/24")

	cfg := e.writeConfig(`
default:
  allowAllIn: false
  allowAllOut: true
  allowAllFwd: false
  allowPing: false
  enableIPv6: false
  enableLogging: false
`)

	e.elctl(srv, cfg, "enable")
	if !e.tableExists(srv) {
		t.Fatal("table should exist after enable")
	}
	if err := e.ping(cli, "10.0.0.1"); err == nil {
		t.Error("ping should be blocked when allowPing is false")
	}

	e.elctl(srv, "", "disable")
	if e.tableExists(srv) {
		t.Error("table should be removed after disable")
	}
	if err := e.ping(cli, "10.0.0.1"); err != nil {
		t.Errorf("ping should work after disable: %v", err)
	}
}

// TestHelperProcess is not a real test: it is re-executed inside a network
// namespace to act as a network listener/client for the tests above.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	args := os.Args
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || sep+2 >= len(args) {
		fmt.Fprintln(os.Stderr, "helper: missing action/address")
		os.Exit(2)
	}
	action, addr := args[sep+1], args[sep+2]

	switch action {
	case "tcp-echo":
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "helper:", err)
			os.Exit(1)
		}
		fmt.Println("READY")
		for {
			conn, err := ln.Accept()
			if err != nil {
				os.Exit(1)
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("ok\n"))
			}(conn)
		}
	case "tcp-dial":
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			fmt.Fprintln(os.Stderr, "helper:", err)
			os.Exit(1)
		}
		_ = conn.Close()
		os.Exit(0)
	case "udp-echo":
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "helper:", err)
			os.Exit(1)
		}
		fmt.Println("READY")
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				os.Exit(1)
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	case "udp-dial":
		conn, err := net.Dial("udp", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "helper:", err)
			os.Exit(1)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("ping")); err != nil {
			fmt.Fprintln(os.Stderr, "helper:", err)
			os.Exit(1)
		}
		buf := make([]byte, 100)
		if _, err := conn.Read(buf); err != nil {
			fmt.Fprintln(os.Stderr, "helper:", err)
			os.Exit(1)
		}
		os.Exit(0)
	default:
		fmt.Fprintln(os.Stderr, "helper: unknown action", action)
		os.Exit(2)
	}
}
