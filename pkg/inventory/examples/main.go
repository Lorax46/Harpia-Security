// Package main demonstrates usage of the inventory engine.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Lorax46/TOTVS-Horus/pkg/inventory"
	"github.com/Lorax46/TOTVS-Horus/pkg/inventory/plugins/aws"
	"github.com/Lorax46/TOTVS-Horus/pkg/inventory/plugins/azure"
	"github.com/Lorax46/TOTVS-Horus/pkg/inventory/plugins/gcp"
	"github.com/Lorax46/TOTVS-Horus/pkg/inventory/plugins/oci"
)

func main() {
	ctx := context.Background()

	// Create inventory engine with 5-minute cache TTL
	inv := inventory.New(ctx,
		inventory.WithCacheTTL(5*time.Minute),
	)

	// ============================================================
	// AWS
	// ============================================================
	fmt.Println("=== AWS ===")
	awsPlugin := aws.New(aws.PluginConfig{
		Region: "us-east-1",
	})

	// List EC2 instances
	ec2Instances, err := awsPlugin.EC2().ListInstances(ctx, aws.EC2Filter{
		Region: "us-east-1",
		State:  "running",
	})
	if err != nil {
		log.Printf("EC2 error: %v", err)
	}
	fmt.Printf("EC2 instances: %d\n", len(ec2Instances))

	// List S3 buckets
	s3Buckets, err := awsPlugin.S3().ListBuckets(ctx, aws.S3Filter{
		Region: "us-east-1",
	})
	if err != nil {
		log.Printf("S3 error: %v", err)
	}
	fmt.Printf("S3 buckets: %d\n", len(s3Buckets))

	// List IAM users
	iamUsers, err := awsPlugin.IAM().ListUsers(ctx, aws.IAMFilter{})
	if err != nil {
		log.Printf("IAM error: %v", err)
	}
	fmt.Printf("IAM users: %d\n", len(iamUsers))

	// ============================================================
	// GCP
	// ============================================================
	fmt.Println("\n=== GCP ===")
	gcpPlugin := gcp.New(gcp.PluginConfig{
		ProjectID: "my-project",
		Region:    "us-central1",
	})

	// List Compute Engine instances
	gceInstances, err := gcpPlugin.Compute().ListInstances(ctx, gcp.ComputeFilter{
		ProjectID: "my-project",
		Zone:      "us-central1-a",
	})
	if err != nil {
		log.Printf("GCE error: %v", err)
	}
	fmt.Printf("GCE instances: %d\n", len(gceInstances))

	// List GCS buckets
	gcsBuckets, err := gcpPlugin.Storage().ListBuckets(ctx, gcp.StorageFilter{
		ProjectID: "my-project",
	})
	if err != nil {
		log.Printf("GCS error: %v", err)
	}
	fmt.Printf("GCS buckets: %d\n", len(gcsBuckets))

	// ============================================================
	// Azure
	// ============================================================
	fmt.Println("\n=== Azure ===")
	azurePlugin := azure.New(azure.PluginConfig{
		SubscriptionID: "my-subscription",
		ResourceGroup:  "my-rg",
	})

	// List Virtual Machines
	vms, err := azurePlugin.Compute().ListVirtualMachines(ctx, azure.ComputeFilter{
		SubscriptionID: "my-subscription",
		ResourceGroup:  "my-rg",
	})
	if err != nil {
		log.Printf("Azure VM error: %v", err)
	}
	fmt.Printf("Azure VMs: %d\n", len(vms))

	// List Storage Accounts
	storageAccounts, err := azurePlugin.Storage().ListStorageAccounts(ctx, azure.StorageFilter{
		SubscriptionID: "my-subscription",
	})
	if err != nil {
		log.Printf("Azure Storage error: %v", err)
	}
	fmt.Printf("Azure Storage Accounts: %d\n", len(storageAccounts))

	// ============================================================
	// OCI
	// ============================================================
	fmt.Println("\n=== OCI ===")
	ociPlugin := oci.New(oci.PluginConfig{
		TenancyID:  "ocid1.tenancy...",
		Region:     "us-ashburn-1",
	})

	// List Core instances
	ociInstances, err := ociPlugin.Core().ListInstances(ctx, oci.CoreFilter{
		CompartmentID: "ocid1.compartment...",
		Region:        "us-ashburn-1",
	})
	if err != nil {
		log.Printf("OCI error: %v", err)
	}
	fmt.Printf("OCI instances: %d\n", len(ociInstances))

	// List Object Storage buckets
	ociBuckets, err := ociPlugin.ObjectStorage().ListBuckets(ctx, oci.ObjectStorageFilter{
		CompartmentID: "ocid1.compartment...",
	})
	if err != nil {
		log.Printf("OCI Object Storage error: %v", err)
	}
	fmt.Printf("OCI Object Storage buckets: %d\n", len(ociBuckets))

	// ============================================================
	// Cache Stats
	// ============================================================
	fmt.Println("\n=== Cache Stats ===")
	hits, misses, size := inv.Cache().Stats()
	fmt.Printf("Cache hits: %d, misses: %d, size: %d\n", hits, misses, size)
}
