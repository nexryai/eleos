// Package integration contains end-to-end tests that exercise the built
// rcfctl binary against the real kernel nftables implementation.
//
// These tests need root privileges and the nft/ip/ping commands, so they are
// gated behind the "integration" build tag and are meant to run inside the
// privileged CI container:
//
//	go build -o rcfctl main.go
//	go test -tags integration ./integration/...
package integration
