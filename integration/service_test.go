//go:build integration && linux

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests install real services on a disposable VM. An explicit opt-in
// keeps the container-based packet tests and ordinary developer runs separate.
func serviceEnv(t *testing.T, kind string) *env {
	t.Helper()
	if os.Getenv("ELEOS_SERVICE_TEST") != kind {
		t.Skip("set ELEOS_SERVICE_TEST=" + kind + " on a disposable Ubuntu VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("service tests require root")
	}
	e := &env{t: t}
	e.must("systemctl", "list-units", "--no-pager")
	// Refuse to replace any existing host firewall table or installation.
	tables := e.must("nft", "list", "tables")
	if strings.Contains(tables, "table inet eleos\n") {
		t.Fatal("an eleos table already exists; use a clean disposable VM")
	}
	if _, err := e.run("systemctl", "cat", "eleos.service"); err == nil {
		t.Fatal("eleos.service already exists; use a clean disposable VM")
	}
	if _, err := e.run("systemctl", "cat", "snap.eleos.daemon.service"); err == nil {
		t.Fatal("eleos Snap service already exists; use a clean disposable VM")
	}
	return e
}

func putFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func repoFile(t *testing.T, name string) []byte {
	t.Helper()
	// Compiled tests run from the repository root in CI; go test runs from
	// integration/. Support both without depending on the checkout's location.
	for _, root := range []string{".", ".."} {
		if data, err := os.ReadFile(filepath.Join(root, name)); err == nil {
			return data
		}
	}
	t.Fatalf("repository file %s not found", name)
	return nil
}

// Accept policies preserve the VM's CI connection. The distinctive port rules
// let us verify replacement without flushing or changing unrelated tables.
func serviceConfig(port int) []byte {
	return []byte(fmt.Sprintf(`default:
  allowAllIn: true
  allowAllOut: true
  allowAllFwd: true
  enableIPv6: true
ports:
  - port: %d
    proto: tcp
`, port))
}

func (e *env) hostRules(port int, absent ...int) {
	e.t.Helper()
	rules := e.must("nft", "-nn", "list", "table", "inet", "eleos")
	if !strings.Contains(rules, fmt.Sprintf("tcp dport %d accept", port)) {
		e.t.Fatalf("expected port %d in rules:\n%s", port, rules)
	}
	for _, p := range absent {
		if strings.Contains(rules, fmt.Sprintf("tcp dport %d ", p)) {
			e.t.Fatalf("stale port %d in rules:\n%s", p, rules)
		}
	}
}

func (e *env) noHostTable() {
	e.t.Helper()
	// A successful list also distinguishes absence from a netlink/tool error.
	if tables := e.must("nft", "list", "tables"); strings.Contains(tables, "table inet eleos\n") {
		e.t.Fatalf("eleos table still exists:\n%s", tables)
	}
}

func (e *env) unitProperty(unit, property, want string) {
	e.t.Helper()
	got := strings.TrimSpace(e.must("systemctl", "show", unit, "--property="+property, "--value"))
	if got != want {
		e.t.Fatalf("%s %s = %q, want %q", unit, property, got, want)
	}
}

func (e *env) oneshotActive(unit string) {
	e.t.Helper()
	for _, p := range []struct{ key, value string }{
		{"Type", "oneshot"}, {"RemainAfterExit", "yes"},
		{"ActiveState", "active"}, {"SubState", "exited"}, {"MainPID", "0"},
	} {
		e.unitProperty(unit, p.key, p.value)
	}
	// MainPID=0 alone would miss a detached child. Check every cgroup below
	// the unit too; systemd may remove an empty cgroup after the command exits.
	cgroup := strings.TrimSpace(e.must("systemctl", "show", unit, "--property=ControlGroup", "--value"))
	if cgroup == "" {
		return
	}
	err := filepath.WalkDir(filepath.Join("/sys/fs/cgroup", cgroup), func(path string, d os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.Name() == "cgroup.procs" {
			data, err := os.ReadFile(path)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			if strings.TrimSpace(string(data)) != "" {
				return fmt.Errorf("resident processes in %s: %s", path, data)
			}
		}
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

type serviceCommands struct {
	start, reload, restart, stop []string
}

func (e *env) exerciseService(unit, config string, commands serviceCommands) {
	e.t.Helper()
	putFile(e.t, config, serviceConfig(41001), 0644)
	e.must(commands.start[0], commands.start[1:]...)
	e.unitProperty(unit, "UnitFileState", "enabled")
	e.oneshotActive(unit)
	e.hostRules(41001)

	putFile(e.t, config, serviceConfig(41002), 0644)
	e.hostRules(41001, 41002)
	e.must(commands.reload[0], commands.reload[1:]...)
	e.oneshotActive(unit)
	e.hostRules(41002, 41001)

	// Build-time validation must fail before the existing rules are replaced.
	putFile(e.t, config, []byte("ports:\n  - port: 41004\n    proto: invalid-protocol\n"), 0644)
	if out, err := e.run(commands.reload[0], commands.reload[1:]...); err == nil {
		e.t.Fatalf("invalid configuration unexpectedly reloaded: %s", out)
	}
	e.hostRules(41002, 41001, 41004)
	putFile(e.t, config, serviceConfig(41003), 0644)
	e.must(commands.reload[0], commands.reload[1:]...)
	e.hostRules(41003, 41002)
	e.must(commands.restart[0], commands.restart[1:]...)
	e.oneshotActive(unit)
	e.hostRules(41003, 41001, 41002)

	e.must(commands.stop[0], commands.stop[1:]...)
	e.unitProperty(unit, "ActiveState", "inactive")
	e.unitProperty(unit, "UnitFileState", "disabled")
	e.noHostTable()
}

func (e *env) diagnostics(unit string) {
	if !e.t.Failed() {
		return
	}
	for _, args := range [][]string{
		{"systemctl", "status", unit, "--no-pager", "--full"},
		{"journalctl", "-u", unit, "--no-pager", "-n", "100"},
		{"nft", "-nn", "list", "ruleset"},
	} {
		out, err := e.run(args[0], args[1:]...)
		e.t.Logf("%v: %v\n%s", args, err, out)
	}
}

func TestSystemdService(t *testing.T) {
	e := serviceEnv(t, "systemd")
	const unit = "eleos.service"
	paths := []string{"/usr/bin/elctl", "/etc/eleos.yml", "/etc/systemd/system/eleos.service"}
	for _, path := range paths {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("refusing to overwrite %s: %v", path, err)
		}
	}
	bin, err := os.ReadFile(binaryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.diagnostics(unit)
		_, _ = e.run("systemctl", "disable", "--now", unit)
		_, _ = e.run("nft", "delete", "table", "inet", "eleos")
		for _, path := range paths {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Errorf("cleanup %s: %v", path, err)
			}
		}
		e.must("systemctl", "daemon-reload")
	})
	putFile(t, paths[0], bin, 0755)
	putFile(t, paths[2], repoFile(t, "systemd/eleos.service"), 0644)
	e.must("systemctl", "daemon-reload")
	e.must("systemd-analyze", "verify", paths[2])
	e.exerciseService(unit, paths[1], serviceCommands{
		start:   []string{"systemctl", "enable", "--now", unit},
		reload:  []string{"systemctl", "reload", unit},
		restart: []string{"systemctl", "restart", unit},
		stop:    []string{"systemctl", "disable", "--now", unit},
	})
}

func TestSnapService(t *testing.T) {
	e := serviceEnv(t, "snap")
	const unit = "snap.eleos.daemon.service"
	const config = "/var/snap/eleos/current/eleos.yml"
	artifact := os.Getenv("ELEOS_SNAP_FILE")
	if artifact == "" {
		t.Fatal("ELEOS_SNAP_FILE must name the built .snap")
	}
	artifact, err := filepath.Abs(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := e.run("snap", "list", "eleos"); err == nil {
		t.Fatal("eleos snap already installed; use a clean disposable VM")
	}
	t.Cleanup(func() {
		e.diagnostics(unit)
		_, _ = e.run("snap", "remove", "--purge", "eleos")
		_, _ = e.run("nft", "delete", "table", "inet", "eleos")
	})
	e.must("snap", "wait", "system", "seed.loaded")
	if confinement := strings.TrimSpace(e.must("snap", "debug", "confinement")); confinement != "strict" {
		t.Fatalf("strict confinement unavailable: %s", confinement)
	}
	e.must("snap", "install", "--dangerous", artifact)
	seed, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if string(seed) != string(repoFile(t, "config.default.yml")) {
		t.Fatal("install hook did not seed the default configuration")
	}
	e.unitProperty(unit, "UnitFileState", "disabled")
	e.unitProperty(unit, "ActiveState", "inactive")
	e.noHostTable()
	putFile(t, config, serviceConfig(41001), 0644)
	if out, err := e.run("snap", "run", "eleos.elctl", "apply"); err == nil {
		t.Fatalf("firewall-control unexpectedly available before connection: %s", out)
	}
	e.noHostTable()
	e.must("snap", "connect", "eleos:firewall-control")
	e.exerciseService(unit, config, serviceCommands{
		start:   []string{"snap", "start", "--enable", "eleos.daemon"},
		reload:  []string{"snap", "restart", "--reload", "eleos.daemon"},
		restart: []string{"snap", "restart", "eleos.daemon"},
		stop:    []string{"snap", "stop", "--disable", "eleos.daemon"},
	})
	// Exercise the CLI wrapper separately from the service's lifecycle.
	e.must("snap", "run", "eleos.elctl", "apply")
	e.hostRules(41003)
	e.must("snap", "run", "eleos.elctl", "disable")
	e.must("snap", "run", "eleos.elctl", "disable")
	e.noHostTable()
	// Removing an active service must execute its stop command as well.
	e.must("snap", "start", "--enable", "eleos.daemon")
	e.oneshotActive(unit)
	e.must("snap", "remove", "--purge", "eleos")
	e.noHostTable()

	// Reinstall without enabling the service, so only the remove hook can
	// clean up rules applied through the CLI.
	e.must("snap", "install", "--dangerous", artifact)
	e.unitProperty(unit, "UnitFileState", "disabled")
	e.must("snap", "connect", "eleos:firewall-control")
	putFile(t, config, serviceConfig(41003), 0644)
	e.must("snap", "run", "eleos.elctl", "apply")
	e.hostRules(41003)
	e.must("snap", "remove", "--purge", "eleos")
	e.noHostTable() // remove hook must also clean up manually applied rules
}
