// Package main is the entry point for the Harpia Security server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Lorax46/Harpia-Security/pkg/inventory"
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

	// Create real inventory manager with all collectors
	inventoryManager := inventory.NewManager()

	// Register OCI collector (lazy-init from vault on first use)
	ociCollector := inventory.NewOCICollector()
	inventoryManager.RegisterCollector("oci", ociCollector)
	log.Println("[main] OCI collector registered (lazy-init from vault)")

	// Register AWS collector (lazy-init from vault)
	awsCollector := inventory.NewAWSCollector(nil) // provider set on first use
	inventoryManager.RegisterCollector("aws", awsCollector)
	log.Println("[main] AWS collector registered")

	// Register Azure collector (lazy-init from vault)
	azureCollector := inventory.NewAzureCollector()
	inventoryManager.RegisterCollector("azure", azureCollector)
	log.Println("[main] Azure collector registered")

	// Register GCP collector (lazy-init from vault)
	gcpCollector := inventory.NewGCPCollector(nil) // provider set on first use
	inventoryManager.RegisterCollector("gcp", gcpCollector)
	log.Println("[main] GCP collector registered")

	// Register Kubernetes collector (provider nil = not configured)
	k8sCollector := inventory.NewKubernetesCollector(nil)
	inventoryManager.RegisterCollector("kubernetes", k8sCollector)
	log.Println("[main] Kubernetes collector registered")

	// Register Google Workspace collector (provider nil = not configured)
	gwCollector := inventory.NewGoogleWorkspaceCollector(nil)
	inventoryManager.RegisterCollector("googleworkspace", gwCollector)
	log.Println("[main] Google Workspace collector registered")

	inventoryService := &inventoryServiceAdapter{manager: inventoryManager}
	complianceService := web.NewMockComplianceService()

	addr := net.JoinHostPort(*host, strconv.Itoa(*port))

	// Create HTTP server
	server := web.NewServer(web.Config{
		Addr:       addr,
		JWTSecret:  getEnv("HORUS_JWT_SECRET", "beta-secret-key-change-in-production"),
		Scanner:    webScanner,
		Inventory:  inventoryService,
		Compliance: complianceService,
	})

	// Connect real inventory manager to handlers
	server.SetInventoryManager(inventoryManager)

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

// inventoryServiceAdapter adapts inventory.Manager to web.InventoryService
type inventoryServiceAdapter struct {
	manager *inventory.Manager
}

func (s *inventoryServiceAdapter) ListResources(ctx context.Context, provider, service string, filter inventory.Filter) ([]inventory.Resource, error) {
	return s.manager.ListResources(provider, service, filter)
}

func (s *inventoryServiceAdapter) GetResource(ctx context.Context, provider, service, id string) (inventory.Resource, error) {
	resources, err := s.manager.ListResources(provider, service, inventory.Filter{Provider: provider, Service: service})
	if err != nil {
		return inventory.Resource{}, err
	}
	for _, r := range resources {
		if r.ID == id {
			return r, nil
		}
	}
	return inventory.Resource{}, fmt.Errorf("resource not found: %s", id)
}

func (s *inventoryServiceAdapter) SyncResources(ctx context.Context, provider string) error {
	return s.manager.SyncResources(provider)
}

func getEnv(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}
