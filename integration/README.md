# Integration tests

`.github/workflows/integration.yml` runs three independent jobs. All runtime
assertions and service installation/cleanup live in the Go `integration`
package; no test shell scripts are required.

- **nftables:** the existing privileged container tests use network namespaces
  to verify allowed/blocked traffic, IPv6, NAT and rule removal.
- **systemd:** an Ubuntu 24.04 VM installs the built binary and the repository's
  unmodified service unit. It verifies enable/start, reload, rejected invalid
  configuration, recovery, restart, disable/stop and table removal with the
  unit's security restrictions intact.
- **Snap:** an Ubuntu 24.04 VM builds and installs the actual strictly confined
  Snap using `snapcore/action-build`. It verifies configuration seeding, an
  initially disabled service, denied access before connecting `firewall-control`,
  and the same service lifecycle. It also tests the CLI wrapper, idempotent
  disable, active-service removal, and remove-hook cleanup of manually applied
  rules while the service is disabled.

Both service jobs check that the service stays `active (exited)` with no main
process or remaining processes in its cgroup. Reload must replace the previous
port rule, and failed reload must preserve it. Failed tests print service state,
the journal and nftables rules before cleanup.

## Running locally

Use a **disposable Ubuntu VM**, not your workstation. Service tests require root
and write `/usr/bin/elctl`, `/etc/eleos.yml`, systemd units, Snap data and the
host's `inet eleos` table. They refuse to overwrite existing installations or
an existing Eleos table, and remove their installations when finished. Test
configurations use accept policies to preserve the VM's CI connection; packet
filtering behavior is covered by the separate namespace tests.

Install `nftables` for service tests, and `snapd` for Snap tests. Run these commands
from the repository root with the Go version in `go.mod`:

```sh
CGO_ENABLED=0 go build -o elctl .
CGO_ENABLED=0 go test -tags integration -c -o /tmp/eleos-integration.test ./integration
sudo env ELEOS_SERVICE_TEST=systemd ELCTL_BIN="$PWD/elctl" /tmp/eleos-integration.test -test.run '^TestSystemdService$' -test.v -test.timeout 10m
```

For Snap, build with Snapcraft and pass the resulting artifact. Installation uses
`--dangerous` because the local artifact has no Store assertion; confinement is
still strict and the tests require strict confinement support on the host.

```sh
snapcraft
CGO_ENABLED=0 go test -tags integration -c -o /tmp/eleos-integration.test ./integration
sudo env ELEOS_SERVICE_TEST=snap ELEOS_SNAP_FILE="$PWD/eleos_VERSION_ARCH.snap" /tmp/eleos-integration.test -test.run '^TestSnapService$' -test.v -test.timeout 15m
```

Replace `eleos_VERSION_ARCH.snap` with the built filename. Without the matching
`ELEOS_SERVICE_TEST` opt-in, service tests skip, including in the existing
container job. These tests verify boot enablement through systemd's enabled
state; they do not reboot the VM or test upgrading between release versions.
