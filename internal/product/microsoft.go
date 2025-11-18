package product

import "strings"

type Windows struct{}

func (w Windows) UUID() string {
	return "691bdc62086838de18847d3d"
}

func (w Windows) CheckCPE(cpe string) bool {
	return strings.HasPrefix(cpe, "cpe:2.3:o:microsoft:windows_")
}
