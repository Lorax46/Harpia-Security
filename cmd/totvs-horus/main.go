// Package main is the entry point for the TOTVS Horus server.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Lorax46/TOTVS-Horus/pkg/web"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("[main] Starting TOTVS Horus Beta...")

	// Create mock services for beta
	scannerService := web.NewMockScannerService()
	inventoryService := web.NewMockInventoryService()
	complianceService := web.NewMockComplianceService()

	// Create HTTP server
	server := web.NewServer(web.Config{
		Addr:       getEnv("HORUS_ADDR", ":8080"),
		JWTSecret:  getEnv("HORUS_JWT_SECRET", "beta-secret-key-change-in-production"),
		Scanner:    scannerService,
		Inventory:  inventoryService,
		Compliance: complianceService,
	})

	// Handle graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("[main] Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("[main] Shutdown error: %v", err)
		}
		os.Exit(0)
	}()

	// Start server
	log.Printf("[main] TOTVS Horus Beta listening on %s", server.Addr())
	if err := server.Run(); err != nil {
		log.Fatalf("[main] Server error: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
