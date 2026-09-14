// Package main is the entry point for the Harpia Security server.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Lorax46/Harpia-Security/pkg/web"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	port := flag.Int("port", 9090, "Port to listen on")
	host := flag.String("host", "0.0.0.0", "Host to bind to")
	flag.Parse()

	log.Println("[main] Starting Harpia Security...")

	// Create web-compatible scanner service
	webScanner := web.NewScanService()

	inventoryService := web.NewMockInventoryService()
	complianceService := web.NewMockComplianceService()

	addr := *host + ":" + strconv.Itoa(*port)

	// Create HTTP server
	server := web.NewServer(web.Config{
		Addr:       addr,
		JWTSecret:  getEnv("HORUS_JWT_SECRET", "beta-secret-key-change-in-production"),
		Scanner:    webScanner,
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

	log.Printf("[main] Harpia Security listening on %s", addr)
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
