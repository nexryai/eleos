// Package integration contains end-to-end tests that exercise the built
// elctl binary against the real kernel nftables implementation.
//
// These tests are gated behind the "integration" build tag. Packet tests need
// root privileges and nft/ip/ping and run inside the privileged CI container:
//
//	go build -o elctl main.go
//	go test -tags integration ./integration/...
//
// Service tests require a disposable Ubuntu VM with systemd (and snapd for
// Snap), plus ELEOS_SERVICE_TEST=systemd or snap. They install actual services
// and modify host nftables tables. See README.md in this directory for commands.
package integration
