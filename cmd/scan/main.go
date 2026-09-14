package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/aws"
	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/oci"
	"github.com/Lorax46/Harpia-Security/internal/scanner/registry"
	awschecks "github.com/Lorax46/Harpia-Security/internal/scanner/checks/aws"
	ocichecks "github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Harpia Security CLI")

	provider := os.Getenv("PROVIDER")
	if provider == "" {
		provider = "aws"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	switch provider {
	case "aws":
		runAWSScan(ctx)
	case "oci":
		runOCIScan(ctx)
	default:
		log.Fatalf("Unknown provider: %s", provider)
	}
}

func runAWSScan(ctx context.Context) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")

	provider, err := aws.NewProvider(ctx, region, accessKey, secretKey)
	if err != nil {
		log.Fatalf("Failed to create AWS provider: %v", err)
	}

	reg := registry.New()
	for _, checks := range awschecks.Registry {
		for _, check := range checks {
			reg.Register(check)
		}
	}

	fmt.Printf("Loaded %d AWS checks\n", reg.Count())

	service := os.Getenv("SERVICE")
	var filtered []executor.Check
	for _, check := range reg.All() {
		if service == "" || check.Metadata().ServiceName == service {
			filtered = append(filtered, check)
		}
	}

	fmt.Printf("Running %d checks...\n", len(filtered))

	exec := executor.New(provider, filtered...)
	result := exec.Run(ctx)

	printResults(result)
}

func runOCIScan(ctx context.Context) {
	tenancyID := os.Getenv("OCI_TENANCY_ID")
	userID := os.Getenv("OCI_USER_ID")
	keyFingerprint := os.Getenv("OCI_KEY_FINGERPRINT")
	privateKeyPath := os.Getenv("OCI_PRIVATE_KEY_PATH")
	passphrase := os.Getenv("OCI_PASSPHRASE")
	region := os.Getenv("OCI_REGION")
	if region == "" {
		region = "us-ashburn-1"
	}

	if tenancyID == "" || userID == "" || keyFingerprint == "" || privateKeyPath == "" {
		log.Fatal("OCI credentials not set. Required: OCI_TENANCY_ID, OCI_USER_ID, OCI_KEY_FINGERPRINT, OCI_PRIVATE_KEY_PATH")
	}

	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("Failed to read OCI private key: %v", err)
	}

	provider, err := oci.NewProvider(ctx, region, tenancyID, userID, keyFingerprint, string(privateKey), passphrase)
	if err != nil {
		log.Fatalf("Failed to create OCI provider: %v", err)
	}

	reg := registry.New()
	for _, checks := range ocichecks.Registry {
		for _, check := range checks {
			reg.Register(check)
		}
	}

	fmt.Printf("Loaded %d OCI checks\n", reg.Count())

	service := os.Getenv("SERVICE")
	var filtered []executor.Check
	for _, check := range reg.All() {
		if service == "" || check.Metadata().ServiceName == service {
			filtered = append(filtered, check)
		}
	}

	fmt.Printf("Running %d checks...\n", len(filtered))

	exec := executor.New(provider, filtered...)
	result := exec.Run(ctx)

	printResults(result)
}

func printResults(result models.ScanResult) {
	separator := strings.Repeat("=", 80)
	fmt.Println("\n" + separator)
	fmt.Printf("SCAN RESULTS — %s | %s\n", result.Provider, result.Region)
	fmt.Println(separator)

	fmt.Printf("Started:  %s\n", result.StartedAt.Format(time.RFC3339))
	fmt.Printf("Finished: %s\n", result.FinishedAt.Format(time.RFC3339))
	fmt.Printf("Duration: %s\n", result.FinishedAt.Sub(result.StartedAt))
	fmt.Printf("Total:    %d findings\n", result.Summary.Total)
	fmt.Println()

	summary := result.Summary
	fmt.Println("SEVERITY BREAKDOWN:")
	fmt.Printf("  Critical:      %d\n", summary.Critical)
	fmt.Printf("  High:          %d\n", summary.High)
	fmt.Printf("  Medium:        %d\n", summary.Medium)
	fmt.Printf("  Low:           %d\n", summary.Low)
	fmt.Printf("  Informational: %d\n", summary.Informational)
	fmt.Println()

	if len(result.Findings) > 0 {
		fmt.Println("FINDINGS:")
		fmt.Println(strings.Repeat("-", 80))
		for _, f := range result.Findings {
			fmt.Printf("\n[%s] %s — %s\n", f.Status, f.Severity, f.ID)
			fmt.Printf("  Title:       %s\n", f.Title)
			fmt.Printf("  Service:     %s\n", f.Service)
			fmt.Printf("  Resource:    %s\n", f.ResourceID)
			fmt.Printf("  Extended:    %s\n", f.StatusExtended)
			if f.Remediation != "" {
				fmt.Printf("  Remediation: %s\n", f.Remediation)
			}
		}
	}

	if output := os.Getenv("OUTPUT"); output != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal results: %v", err)
		} else {
			os.WriteFile(output, data, 0644)
			fmt.Printf("\nResults exported to: %s\n", output)
		}
	}
}
