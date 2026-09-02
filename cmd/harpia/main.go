package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version   = "0.1.0"
	buildTime = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "harpia-security",
	Short: "Harpia-Security: CNAPP multi-cloud",
	Long: `Harpia-Security é uma plataforma CNAPP (Cloud-Native Application Protection Platform)
para scans agentless, misconfigurations, vulnerabilidades e inventário multi-cloud.
Suporta AWS, GCP, Azure e OCI.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Harpia-Security v%s (build: %s)\n", version, buildTime)
		fmt.Println("Use --help para ver comandos disponíveis.")
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Mostra a versão",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("v%s (build: %s)\n", version, buildTime)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
