package product

import "strings"

type Linux struct{}

func (l Linux) UUID() string {
	return "691bd9e9086838de18847d3b"
}

func (l Linux) CheckCPE(cpe string) bool {
	return strings.HasPrefix(cpe, "cpe:2.3:o:linux:linux_kernel:")
}
