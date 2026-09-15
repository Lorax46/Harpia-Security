// Package web provides bulk credential import handlers.
package web

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Lorax46/Harpia-Security/pkg/credentials"
	"github.com/gin-gonic/gin"
)

// BulkImportRequest represents a bulk import request
type BulkImportRequest struct {
	Providers []CredentialEntry `json:"providers"`
}

// CredentialEntry represents a single credential entry
type CredentialEntry struct {
	Provider       string `json:"provider" binding:"required"`
	Name           string `json:"name" binding:"required"`
	Region         string `json:"region"`
	AccessKey      string `json:"access_key"`
	SecretKey      string `json:"secret_key"`
	TenancyOCID    string `json:"tenancy_ocid"`
	UserOCID       string `json:"user_ocid"`
	Fingerprint    string `json:"fingerprint"`
	PrivateKey     string `json:"private_key"`
	SubscriptionID string `json:"subscription_id"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	TenantID       string `json:"tenant_id"`
	ProjectID      string `json:"project_id"`
	ServiceKey     string `json:"service_key"`
	APIToken       string `json:"api_token"`
	ZoneID         string `json:"zone_id"`
}

// BulkImportResult represents the result of a bulk import
type BulkImportResult struct {
	Total     int                    `json:"total"`
	Succeeded int                    `json:"succeeded"`
	Failed    int                    `json:"failed"`
	Errors    []string               `json:"errors"`
	Entries   []credentials.CredentialSummary `json:"entries"`
}

// BulkImportCredentials imports multiple credentials at once
func (h *Handler) BulkImportCredentials(c *gin.Context) {
	var req BulkImportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result := BulkImportResult{
		Total: len(req.Providers),
	}

	// Auto-unlock vault if not already unlocked
	if !h.vault.IsUnlocked() {
		passphrase := os.Getenv("HARPA_VAULT_PASS")
		if passphrase == "" {
			passphrase = "harpia-default-secure-pass-2024"
		}
		if err := h.vault.Unlock(passphrase); err != nil {
			c.JSON(500, gin.H{"error": "failed to unlock vault: " + err.Error()})
			return
		}
	}

	for _, entry := range req.Providers {
		credEntry := credentials.CredentialEntry{
			Provider: entry.Provider,
			Name:     entry.Name,
			Region:   entry.Region,
			Data:     make(map[string]string),
		}

		// Collect all sensitive fields
		if entry.AccessKey != "" {
			credEntry.Data["access_key"] = entry.AccessKey
		}
		if entry.SecretKey != "" {
			credEntry.Data["secret_key"] = entry.SecretKey
		}
		if entry.TenancyOCID != "" {
			credEntry.Data["tenancy_ocid"] = entry.TenancyOCID
		}
		if entry.UserOCID != "" {
			credEntry.Data["user_ocid"] = entry.UserOCID
		}
		if entry.Fingerprint != "" {
			credEntry.Data["fingerprint"] = entry.Fingerprint
		}
		if entry.PrivateKey != "" {
			credEntry.Data["private_key"] = entry.PrivateKey
		}
		if entry.SubscriptionID != "" {
			credEntry.Data["subscription_id"] = entry.SubscriptionID
		}
		if entry.ClientID != "" {
			credEntry.Data["client_id"] = entry.ClientID
		}
		if entry.ClientSecret != "" {
			credEntry.Data["client_secret"] = entry.ClientSecret
		}
		if entry.TenantID != "" {
			credEntry.Data["tenant_id"] = entry.TenantID
		}
		if entry.ProjectID != "" {
			credEntry.Data["project_id"] = entry.ProjectID
		}
		if entry.ServiceKey != "" {
			credEntry.Data["service_key"] = entry.ServiceKey
		}
		if entry.APIToken != "" {
			credEntry.Data["api_token"] = entry.APIToken
		}
		if entry.ZoneID != "" {
			credEntry.Data["zone_id"] = entry.ZoneID
		}

		// Save to vault
		if err := h.vault.Add(credEntry); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("failed to save %s: %v", entry.Name, err))
		} else {
			result.Succeeded++
			result.Entries = append(result.Entries, credentials.CredentialSummary{
				ID:       credEntry.ID,
				Provider: entry.Provider,
				Name:     entry.Name,
				Region:   entry.Region,
			})
		}
	}

	c.JSON(http.StatusOK, result)
}

// ImportCredentialsFromCSV imports credentials from a CSV file
func (h *Handler) ImportCredentialsFromCSV(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no file uploaded"})
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse CSV"})
		return
	}

	if len(records) < 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CSV must have header + at least one data row"})
		return
	}

	// Build header index
	header := make(map[string]int)
	for i, col := range records[0] {
		header[strings.ToLower(strings.TrimSpace(col))] = i
	}

	required := []string{"provider", "name"}
	for _, req := range required {
		if _, ok := header[req]; !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing required column: " + req})
			return
		}
	}

	result := BulkImportResult{}

	// Auto-unlock vault if not already unlocked
	if !h.vault.IsUnlocked() {
		passphrase := os.Getenv("HARPA_VAULT_PASS")
		if passphrase == "" {
			passphrase = "harpia-default-secure-pass-2024"
		}
		if err := h.vault.Unlock(passphrase); err != nil {
			c.JSON(500, gin.H{"error": "failed to unlock vault: " + err.Error()})
			return
		}
	}

	// Process each row
	for rowNum, record := range records[1:] {
		entry := credentials.CredentialEntry{
			Data: make(map[string]string),
		}

		// Required fields
		entry.Provider = getCSVValue(record, header, "provider")
		entry.Name = getCSVValue(record, header, "name")

		if entry.Provider == "" || entry.Name == "" {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("row %d: missing provider or name", rowNum+2))
			continue
		}

		// Optional fields
		entry.Region = getCSVValue(record, header, "region")

		// Map sensitive fields
		fieldMapping := map[string]string{
			"access_key":      "access_key",
			"secret_key":      "secret_key",
			"tenancy_ocid":    "tenancy_ocid",
			"user_ocid":       "user_ocid",
			"fingerprint":     "fingerprint",
			"private_key":     "private_key",
			"subscription_id": "subscription_id",
			"client_id":       "client_id",
			"client_secret":   "client_secret",
			"tenant_id":       "tenant_id",
			"project_id":      "project_id",
			"service_key":     "service_key",
			"api_token":       "api_token",
			"zone_id":         "zone_id",
		}

		for csvCol, dataKey := range fieldMapping {
			if val := getCSVValue(record, header, csvCol); val != "" {
				entry.Data[dataKey] = val
			}
		}

		// Save
		if err := h.vault.Add(entry); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("row %d: %v", rowNum+2, err))
		} else {
			result.Succeeded++
			result.Entries = append(result.Entries, credentials.CredentialSummary{
				ID:       entry.ID,
				Provider: entry.Provider,
				Name:     entry.Name,
				Region:   entry.Region,
			})
		}
	}

	result.Total = result.Succeeded + result.Failed

	c.JSON(http.StatusOK, result)
}

// GetImportTemplateCSV returns a template CSV for bulk import
func (h *Handler) GetImportTemplateCSV(c *gin.Context) {
	provider := c.DefaultQuery("provider", "all")

	var headers []string
	var example []string

	switch provider {
	case "oci":
		headers = []string{"provider", "name", "region", "tenancy_ocid", "user_ocid", "fingerprint", "private_key"}
		example = []string{"oci", "OCI Prod", "sa-saopaulo-1", "ocid1.tenancy...", "ocid1.user...", "xx:xx:xx...", "-----BEGIN PRIVATE KEY-----..."}
	case "aws":
		headers = []string{"provider", "name", "region", "access_key", "secret_key"}
		example = []string{"aws", "AWS Dev", "us-east-1", "AKIA...", "..."}
	case "azure":
		headers = []string{"provider", "name", "region", "subscription_id", "client_id", "client_secret", "tenant_id"}
		example = []string{"azure", "Azure Prod", "eastus", "sub-id", "client-id", "client-secret", "tenant-id"}
	case "gcp":
		headers = []string{"provider", "name", "region", "project_id", "service_key"}
		example = []string{"gcp", "GCP Dev", "us-central1", "project-id", "{...service account json...}"}
	case "cloudflare":
		headers = []string{"provider", "name", "api_token", "zone_id"}
		example = []string{"cloudflare", "CF Prod", "", "zone-id"}
	default:
		headers = []string{"provider", "name", "region", "access_key", "secret_key", "tenancy_ocid", "user_ocid", "fingerprint", "private_key", "subscription_id", "client_id", "client_secret", "tenant_id", "project_id", "service_key", "api_token", "zone_id"}
		example = []string{"oci", "OCI Prod", "sa-saopaulo-1", "", "", "ocid1.tenancy...", "ocid1.user...", "xx:xx...", "-----BEGIN...", "", "", "", "", "", "", "", ""}
	}

	csvData := strings.Join(headers, ",") + "\n" + strings.Join(example, ",") + "\n"

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=harpia-import-%s-template.csv", provider))
	c.String(http.StatusOK, csvData)
}

func getCSVValue(record []string, header map[string]int, col string) string {
	idx, ok := header[col]
	if !ok || idx >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[idx])
}
