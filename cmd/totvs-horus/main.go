// Package main is the entry point for the Harpia Security server.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/Lorax46/Harpia-Security/pkg/web"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("[main] Starting Harpia Security...")

	ctx := context.Background()

	// Create real scanner service
	scannerService, err := createScannerService(ctx)
	if err != nil {
		log.Printf("[main] Warning: Could not create real scanner service: %v", err)
		log.Println("[main] Falling back to mock scanner service")
	}

	// Use a web-compatible scanner service
	var webScanner web.ScannerService
	if scannerService != nil {
		log.Printf("[main] Scanner service created with %d checks", scannerService.GetRegistry().Count())
		webScanner = &webScannerAdapter{svc: scannerService}
	} else {
		webScanner = web.NewMockScannerService()
	}

	inventoryService := web.NewMockInventoryService()
	complianceService := web.NewMockComplianceService()

	// Create HTTP server
	server := web.NewServer(web.Config{
		Addr:       getEnv("HORUS_ADDR", ":8080"),
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

	log.Printf("[main] Harpia Security listening on %s", server.Addr())
	if err := server.Run(); err != nil {
		log.Fatalf("[main] Server error: %v", err)
	}
}

// webScannerAdapter adapts the scanner service to web.ScannerService interface
type webScannerAdapter struct {
	svc *scanner.Service
}

func (a *webScannerAdapter) ListScans(ctx context.Context) ([]web.Scan, error) {
	return []web.Scan{}, nil
}

func (a *webScannerAdapter) CreateScan(ctx context.Context, req web.CreateScanRequest) (*web.Scan, error) {
	return &web.Scan{
		ID:       "scan-" + req.Provider,
		Name:     req.Name,
		Provider: req.Provider,
		Status:   "pending",
	}, nil
}

func (a *webScannerAdapter) GetScan(ctx context.Context, id string) (*web.Scan, error) {
	return &web.Scan{
		ID: id, Name: "Scan", Provider: "aws",
		Status: "completed",
	}, nil
}

func (a *webScannerAdapter) RunScan(ctx context.Context, id string) error {
	_, err := a.svc.RunScan(ctx, "aws")
	return err
}

func (a *webScannerAdapter) DeleteScan(ctx context.Context, id string) error {
	return nil
}

func (a *webScannerAdapter) ListFindings(ctx context.Context, filter web.FindingsFilter) ([]models.Finding, error) {
	return []models.Finding{}, nil
}

func (a *webScannerAdapter) GetFinding(ctx context.Context, id string) (*models.Finding, error) {
	return &models.Finding{ID: id, Title: "Finding"}, nil
}

func (a *webScannerAdapter) UpdateFinding(ctx context.Context, id string, req web.UpdateFindingRequest) (*models.Finding, error) {
	return &models.Finding{ID: id, Title: "Finding", Status: models.Status(req.Status)}, nil
}

func (a *webScannerAdapter) ExportFindings(ctx context.Context, format string) ([]byte, error) {
	return []byte{}, nil
}

func createScannerService(ctx context.Context) (*scanner.Service, error) {
	region := getEnv("AWS_REGION", "us-east-1")
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")

	return scanner.NewService(ctx, region, accessKey, secretKey)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
