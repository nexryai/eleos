package product

import "strings"

type Windows struct{}

func (w Windows) UUID() string {
	return "f5b9e6ef-1cd9-4da8-a7f1-7294ee63567b"
}

func (w Windows) CheckCPE(cpe string) bool {
	return strings.HasPrefix(cpe, "cpe:2.3:o:microsoft:windows_")
}
