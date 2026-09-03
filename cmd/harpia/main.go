package main

import (
	"fmt"
	"os"
)

var (
	version   = "0.1.0"
	buildTime = "dev"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("v%s (build: %s)\n", version, buildTime)
		return
	}
	fmt.Printf("Harpia-Security v%s (build: %s)\n", version, buildTime)
	fmt.Println("Use --help para ver comandos disponíveis.")
}
