package main

import (
	"fmt"
	"os"

	"github.com/nexryai/eleos/internal/worker"
)

func main() {
	err := worker.ExecuteJob()
	if err != nil {
		fmt.Println("Error executing job:", err)
		os.Exit(1)
	}
}
