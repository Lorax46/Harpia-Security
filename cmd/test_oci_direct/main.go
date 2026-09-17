package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/oci"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Use EXACT credentials from ~/.oci/config (which is known to work)
	keyData, _ := os.ReadFile("/home/ubuntu/.oci/oci_api_key.pem")
	privateKey := strings.TrimSpace(string(keyData))

	tenancyID := "ocid1.tenancy.oc1..aaaaaaaa5m7f77rn3fvxu5k2dplfeguxkyst3x65gb2dtbd355652xyyqb6q"
	userID := "ocid1.user.oc1..aaaaaaaascicu7gubljhji5n3wr5woyjcvua6qsfj6ottz5wkihwhzub72lq"
	fingerprint := "a9:51:72:c9:ec:bf:82:38:79:ee:c5:4d:63:a2:78:ce"

	provider, err := oci.NewProvider(context.Background(), "sa-saopaulo-1", tenancyID, userID, fingerprint, privateKey, "")
	if err != nil {
		log.Fatalf("Provider error: %v", err)
	}

	client, err := provider.Identity()
	if err != nil {
		log.Fatalf("Identity error: %v", err)
	}

	resp, err := client.ListUsers(context.Background(), identity.ListUsersRequest{
		CompartmentId: &tenancyID,
	})
	if err != nil {
		log.Fatalf("ListUsers error: %v", err)
	}

	fmt.Printf("SUCCESS! Found %d users:\n", len(resp.Items))
	for _, u := range resp.Items {
		fmt.Printf("  - %s\n", safeStr(u.Name))
	}
}

func safeStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
