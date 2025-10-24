package product

import "strings"

type Linux struct{}

func (l Linux) UUID() string {
	return "33a7e4b2-f872-4f00-9653-135fd881c878"
}

func (l Linux) CheckCPE(cpe string) bool {
	return strings.HasPrefix(cpe, "cpe:2.3:o:linux:linux_kernel:")
}
