// Quick test to verify OCI credentials work
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/oci"
	"github.com/Lorax46/Harpia-Security/pkg/credentials"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	vault := credentials.GetManager()
	if !vault.IsUnlocked() {
		vault.Unlock("harpia-default-secure-pass-2024")
	}

	creds := vault.GetByProvider("oci")
	fmt.Printf("Found %d OCI credentials\n", len(creds))
	if len(creds) == 0 {
		log.Fatal("No OCI creds")
	}

	cred := creds[0]
	fmt.Printf("Tenancy: %s...\n", cred.Data["tenancy_ocid"][:20])
	fmt.Printf("User: %s...\n", cred.Data["user_ocid"][:20])
	fmt.Printf("Region: %s\n", cred.Region)

	provider, err := oci.NewProvider(context.Background(), "sa-saopaulo-1",
		cred.Data["tenancy_ocid"],
		cred.Data["user_ocid"],
		cred.Data["fingerprint"],
		cred.Data["private_key"], "")
	if err != nil {
		log.Fatalf("Provider error: %v", err)
	}

	client, err := provider.Identity()
	if err != nil {
		log.Fatalf("Identity error: %v", err)
	}

	tenancyID := provider.TenancyId()
	resp, err := client.ListUsers(context.Background(), identity.ListUsersRequest{
		CompartmentId: &tenancyID,
	})
	if err != nil {
		log.Fatalf("ListUsers error: %v", err)
	}

	fmt.Printf("Found %d users!\n", len(resp.Items))
	for _, u := range resp.Items {
		fmt.Printf("  - %s\n", *u.Name)
	}
}
