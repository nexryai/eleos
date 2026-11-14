package snap_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func writeFile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Run the real hooks/wrapper with a fake binary; never touch host firewall rules.
func setup(t *testing.T) (root, data, args string) {
	t.Helper()
	root = t.TempDir()
	data = filepath.Join(root, "data with spaces")
	for _, dir := range []string{data, filepath.Join(root, "bin")} {
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	args = filepath.Join(root, "args")
	writeFile(t, filepath.Join(root, "bin/elctl"), `#!/bin/sh
printf '%s\n' "$@" > "$TEST_ARGS"
exit "${TEST_EXIT:-0}"
`, 0755)
	writeFile(t, filepath.Join(root, "bin/elctl-cli"), readFile(t, "local/elctl-cli"), 0755)
	t.Setenv("SNAP", root)
	t.Setenv("SNAP_DATA", data)
	t.Setenv("ELEOS_CONFIG", "")
	t.Setenv("TEST_ARGS", args)
	t.Setenv("TEST_EXIT", "0")
	return
}

func run(t *testing.T, script string, args ...string) ([]byte, error) {
	t.Helper()
	return exec.Command("/bin/sh", append([]string{script}, args...)...).CombinedOutput()
}

func TestInstallSeedsConfigWithoutOverwriting(t *testing.T) {
	root, data, _ := setup(t)
	writeFile(t, filepath.Join(root, "default-config.yml"), "default: true\n", 0644)
	for _, want := range []string{"default: true\n", "custom: true\n"} {
		if out, err := run(t, "hooks/install"); err != nil {
			t.Fatalf("install: %v: %s", err, out)
		}
		if got := readFile(t, filepath.Join(data, "eleos.yml")); got != want {
			t.Fatalf("config = %q, want %q", got, want)
		}
		writeFile(t, filepath.Join(data, "eleos.yml"), "custom: true\n", 0600)
	}
}

func TestCLIForwardsArgumentsAndExitStatus(t *testing.T) {
	_, data, args := setup(t)
	for _, override := range []string{"", "/custom path/eleos.yml"} {
		t.Setenv("ELEOS_CONFIG", override)
		config := override
		if config == "" {
			config = filepath.Join(data, "eleos.yml")
		}
		out, err := run(t, "local/elctl-cli", "-debug", "apply", "argument with spaces")
		if err != nil {
			t.Fatalf("CLI: %v: %s", err, out)
		}
		want := "-f\n" + config + "\n-debug\napply\nargument with spaces\n"
		if got := readFile(t, args); got != want {
			t.Fatalf("args = %q, want %q", got, want)
		}
	}
	t.Setenv("TEST_EXIT", "37")
	_, err := run(t, "local/elctl-cli", "apply")
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 37 {
		t.Fatalf("CLI should propagate exit 37, got %v", err)
	}
}

func TestServiceLifecycle(t *testing.T) {
	root, data, args := setup(t)
	var manifest struct {
		Apps map[string]struct {
			Command       string
			Daemon        string
			InstallMode   string `yaml:"install-mode"`
			StopCommand   string `yaml:"stop-command"`
			ReloadCommand string `yaml:"reload-command"`
			Plugs         []string
		}
	}
	if err := yaml.Unmarshal([]byte(readFile(t, "snapcraft.yaml")), &manifest); err != nil {
		t.Fatal(err)
	}
	service := manifest.Apps["daemon"]
	if service.Daemon != "oneshot" || service.InstallMode != "disable" {
		t.Fatalf("service must be oneshot and initially disabled: %+v", service)
	}
	if !reflect.DeepEqual(service.Plugs, []string{"firewall-control"}) {
		t.Fatalf("service must have firewall-control: %v", service.Plugs)
	}
	for _, step := range []struct{ command, operation string }{
		{service.Command, "enable"},
		{service.ReloadCommand, "apply"},
		{service.StopCommand, "disable"},
	} {
		if step.command == "" {
			t.Fatalf("missing service command for %s", step.operation)
		}
		command := strings.Fields(step.command)
		out, err := run(t, filepath.Join(root, command[0]), command[1:]...)
		if err != nil {
			t.Fatalf("%s: %v: %s", step.operation, err, out)
		}
		want := "-f\n" + filepath.Join(data, "eleos.yml") + "\n" + step.operation + "\n"
		if got := readFile(t, args); got != want {
			t.Fatalf("%s args = %q, want %q", step.operation, got, want)
		}
	}
	// A failed start/reload must be visible, rather than retried in a loop.
	t.Setenv("TEST_EXIT", "1")
	command := strings.Fields(service.Command)
	if _, err := run(t, filepath.Join(root, command[0]), command[1:]...); err == nil {
		t.Fatal("service hid apply failure")
	}
}

func TestRemoveCleansUpManualRulesBestEffort(t *testing.T) {
	_, _, args := setup(t)
	for _, status := range []string{"0", "1"} {
		t.Setenv("TEST_EXIT", status)
		if out, err := run(t, "hooks/remove"); err != nil || len(out) != 0 {
			t.Fatalf("remove must be quiet and best effort: %v: %s", err, out)
		}
		if got := readFile(t, args); got != "disable\n" {
			t.Fatalf("remove args = %q", got)
		}
	}
}
