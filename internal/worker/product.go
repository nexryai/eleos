package worker

import "github.com/nexryai/eleos/internal/product"

type Product interface {
	UUID() string
	CheckCPE(string) bool
}

var products = []Product{
	&product.Linux{},
	&product.Windows{},
}
