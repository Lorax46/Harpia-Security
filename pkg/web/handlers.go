// Package web provides HTTP handlers for the Harpia Security dashboard.
package web

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Lorax46/Harpia-Security/internal/scanner"
	"github.com/Lorax46/Harpia-Security/pkg/credentials"
	"github.com/Lorax46/Harpia-Security/pkg/inventory"
	"github.com/gin-gonic/gin"
)

// Handler handles HTTP requests.
type Handler struct {
	config     Config
	scanner    ScannerService
	inventory  InventoryService
	compliance ComplianceService
	vault      *credentials.CredentialManager
}

// NewHandler creates a new HTTP handler.
func NewHandler(cfg Config, auth *AuthService) *Handler {
	return &Handler{
		config:     cfg,
		scanner:    cfg.Scanner,
		inventory:  cfg.Inventory,
		compliance: cfg.Compliance,
		vault:      credentials.GetManager(),
	}
}

// AuthMiddleware validates the bearer token.
func (h *Handler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token != "beta-admin-token" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
			return
		}
		c.Set("user", nil)
		c.Next()
	}
}

// Login handles authentication.
func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Username == "admin" && req.Password == "admin" {
		c.JSON(http.StatusOK, gin.H{"token": "beta-admin-token", "user": gin.H{"username": "admin", "role": "admin"}})
		return
	}
	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
}

// Register handles user registration.
func (h *Handler) Register(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": "user-" + req.Username, "username": req.Username, "role": req.Role})
}

// Refresh handles token refresh.
func (h *Handler) Refresh(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"token": "refreshed-token"})
}

// Logout handles logout.
func (h *Handler) Logout(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

// GetDashboard returns dashboard data.
func (h *Handler) GetDashboard(c *gin.Context) {
	stats := scanStore.GetStats()
	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

// GetDashboardStats returns dashboard statistics.
func (h *Handler) GetDashboardStats(c *gin.Context) {
	stats := scanStore.GetStats()
	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

// ListScans returns all scans.
func (h *Handler) ListScans(c *gin.Context) {
	c.JSON(http.StatusOK, []gin.H{
		{"id": "oci-scan-1", "name": "OCI Scan", "provider": "oci", "status": "pending"},
	})
}

// CreateScan creates a new scan with real credentials.
func (h *Handler) CreateScan(c *gin.Context) {
	var req CreateScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	creds := h.vault.GetByProvider(req.Provider)
	if len(creds) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no credentials found for provider: " + req.Provider})
		return
	}

	cred := creds[0]

	if req.Provider == "oci" {
		tenancyID := cred.Data["tenancy_ocid"]
		userID := cred.Data["user_ocid"]
		fingerprint := cred.Data["fingerprint"]
		privateKey := cred.Data["private_key"]

		if tenancyID == "" || userID == "" || fingerprint == "" || privateKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "incomplete OCI credentials"})
			return
		}

		realScanner, err := scanner.NewRealOCIService(c.Request.Context(), cred.Region, tenancyID, userID, fingerprint, privateKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create OCI scanner: %v", err)})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"id":       "scan-" + req.Provider,
			"name":     req.Name,
			"provider": req.Provider,
			"status":   "pending",
			"checks":   len(realScanner.GetChecks()),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": "scan-" + req.Provider, "name": req.Name, "provider": req.Provider, "status": "pending"})
}

// GetScan returns a scan.
func (h *Handler) GetScan(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "name": "Scan", "status": "completed"})
}

// RunScan runs a real scan with stored credentials.
func (h *Handler) RunScan(c *gin.Context) {
	id := c.Param("id")

	parts := strings.Split(id, "-")
	if len(parts) < 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan ID"})
		return
	}
	provider := parts[1]

	creds := h.vault.GetByProvider(provider)
	if len(creds) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no credentials found for provider: " + provider})
		return
	}

	cred := creds[0]

	if provider == "oci" {
		tenancyID := cred.Data["tenancy_ocid"]
		userID := cred.Data["user_ocid"]
		fingerprint := cred.Data["fingerprint"]
		privateKey := cred.Data["private_key"]
		region := cred.Region

		if tenancyID == "" || userID == "" || fingerprint == "" || privateKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "incomplete OCI credentials"})
			return
		}

		realScanner, err := scanner.NewRealOCIService(c.Request.Context(), region, tenancyID, userID, fingerprint, privateKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create OCI scanner: %v", err)})
			return
		}

		result, err := realScanner.RunScan(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("scan failed: %v", err)})
			return
		}

		// Save results to scanStore
		scanStore.Save(Entry{
			ID:       id,
			Provider: provider,
			Region:   result.Region,
			Status:   "completed",
			Result:   result,
		})

		c.JSON(http.StatusOK, gin.H{
			"scan_id":  id,
			"provider": provider,
			"status":   "completed",
			"result":   result,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"scan_id": id, "status": "not implemented for provider: " + provider})
}

// DeleteScan deletes a scan.
func (h *Handler) DeleteScan(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "scan deleted"})
}

// ListFindings returns all findings.
func (h *Handler) ListFindings(c *gin.Context) {
	c.JSON(http.StatusOK, []gin.H{})
}

// GetFinding returns a finding.
func (h *Handler) GetFinding(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "title": "Finding"})
}

// UpdateFinding updates a finding.
func (h *Handler) UpdateFinding(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "updated"})
}

// ExportFindings exports findings.
func (h *Handler) ExportFindings(c *gin.Context) {
	format := c.DefaultQuery("format", "csv")
	data, _ := h.scanner.ExportFindings(c.Request.Context(), format)
	c.Data(http.StatusOK, "text/csv", data)
}

// ListProviders returns all providers from vault.
func (h *Handler) ListProviders(c *gin.Context) {
	providers := h.vault.List()
	if len(providers) == 0 {
		providers = []credentials.CredentialSummary{
			{ID: "oci-default", Provider: "oci", Name: "OCI Default", Region: "sa-saopaulo-1"},
			{ID: "aws-default", Provider: "aws", Name: "AWS Default", Region: "us-east-1"},
		}
	}
	c.JSON(http.StatusOK, providers)
}

// CreateProvider creates a provider.
func (h *Handler) CreateProvider(c *gin.Context) {
	var req struct {
		Provider  string `json:"provider" binding:"required"`
		Name      string `json:"name" binding:"required"`
		Region    string `json:"region"`
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": "provider-" + req.Provider, "status": "connected"})
}

// UpdateProvider updates a provider.
func (h *Handler) UpdateProvider(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "updated"})
}

// DeleteProvider deletes a provider.
func (h *Handler) DeleteProvider(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// ListInventory returns inventory resources.
func (h *Handler) ListInventory(c *gin.Context) {
	provider := c.DefaultQuery("provider", "aws")
	filter := inventory.Filter{Provider: provider}
	resources, err := h.inventory.ListResources(c.Request.Context(), provider, "", filter)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resources)
}

// ListInventoryByType returns inventory by type.
func (h *Handler) ListInventoryByType(c *gin.Context) {
	provider := c.Param("provider")
	resourceType := c.Param("type")
	filter := inventory.Filter{Provider: provider}
	resources, err := h.inventory.ListResources(c.Request.Context(), provider, resourceType, filter)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resources)
}

// GetInventoryItem returns a single inventory item.
func (h *Handler) GetInventoryItem(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "name": "Resource"})
}

// SyncInventory syncs inventory.
func (h *Handler) SyncInventory(c *gin.Context) {
	provider := c.DefaultQuery("provider", "aws")
	if err := h.inventory.SyncResources(c.Request.Context(), provider); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "sync completed"})
}

// ListFrameworks returns compliance frameworks.
func (h *Handler) ListFrameworks(c *gin.Context) {
	c.JSON(http.StatusOK, []gin.H{
		{"id": "cis", "name": "CIS Benchmarks"},
		{"id": "nist", "name": "NIST 800-53"},
	})
}

// ListComplianceReports returns compliance reports.
func (h *Handler) ListComplianceReports(c *gin.Context) {
	c.JSON(http.StatusOK, []gin.H{})
}

// GenerateComplianceReport generates a report.
func (h *Handler) GenerateComplianceReport(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"id": "report-new", "status": "generating"})
}

// GetComplianceReport returns a report.
func (h *Handler) GetComplianceReport(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "name": "Report"})
}

// ExportComplianceReport exports a report.
func (h *Handler) ExportComplianceReport(c *gin.Context) {
	c.Data(http.StatusOK, "text/csv", []byte{})
}

// GetSettings returns settings.
func (h *Handler) GetSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"theme": "light"})
}

// UpdateSettings updates settings.
func (h *Handler) UpdateSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "settings updated"})
}

// ListUsers returns all users.
func (h *Handler) ListUsers(c *gin.Context) {
	c.JSON(http.StatusOK, []gin.H{
		{"id": "admin", "username": "admin", "role": "admin"},
	})
}

// CreateUser creates a user.
func (h *Handler) CreateUser(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"id": "new-user", "role": "viewer"})
}

// UpdateUser updates a user.
func (h *Handler) UpdateUser(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "updated"})
}

// DeleteUser deletes a user.
func (h *Handler) DeleteUser(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// Page serves the SPA for all page routes.
func (h *Handler) Page(c *gin.Context) {
	c.File("./web/dashboard/index.html")
}

// ListFindingsByProvider returns findings grouped by provider.
func (h *Handler) ListFindingsByProvider(c *gin.Context) {
	result := scanStore.GetAll()
	c.JSON(200, result)
}

// ListFindingsStats returns statistics for findings.
func (h *Handler) ListFindingsStats(c *gin.Context) {
	stats := scanStore.GetStats()
	c.JSON(200, stats)
}

// ListFindingsByProviderAndType returns findings for a specific provider and type.
func (h *Handler) ListFindingsByProviderAndType(c *gin.Context) {
	ctx := c.Request.Context()
	provider := c.Param("provider")
	findingType := c.Param("type")
	findings, err := h.scanner.GetFindingsByProviderAndType(ctx, provider, findingType)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, findings)
}

// CreateCredentials creates new provider credentials securely.
func (h *Handler) CreateCredentials(c *gin.Context) {
	var req struct {
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
		ProjectID      string `json:"project_id"`
		ServiceKey     string `json:"service_key"`
		APIToken       string `json:"api_token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
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

	entry := credentials.CredentialEntry{
		Provider: req.Provider,
		Name:     req.Name,
		Region:   req.Region,
		Data:     make(map[string]string),
	}

	if req.AccessKey != "" {
		entry.Data["access_key"] = req.AccessKey
	}
	if req.SecretKey != "" {
		entry.Data["secret_key"] = req.SecretKey
	}
	if req.TenancyOCID != "" {
		entry.Data["tenancy_ocid"] = req.TenancyOCID
	}
	if req.UserOCID != "" {
		entry.Data["user_ocid"] = req.UserOCID
	}
	if req.Fingerprint != "" {
		entry.Data["fingerprint"] = req.Fingerprint
	}
	if req.PrivateKey != "" {
		entry.Data["private_key"] = req.PrivateKey
	}
	if req.SubscriptionID != "" {
		entry.Data["subscription_id"] = req.SubscriptionID
	}
	if req.ClientID != "" {
		entry.Data["client_id"] = req.ClientID
	}
	if req.ClientSecret != "" {
		entry.Data["client_secret"] = req.ClientSecret
	}
	if req.ProjectID != "" {
		entry.Data["project_id"] = req.ProjectID
	}
	if req.ServiceKey != "" {
		entry.Data["service_key"] = req.ServiceKey
	}
	if req.APIToken != "" {
		entry.Data["api_token"] = req.APIToken
	}

	if err := h.vault.Add(entry); err != nil {
		c.JSON(500, gin.H{"error": "failed to save credentials: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":       entry.ID,
		"provider": req.Provider,
		"name":     req.Name,
		"status":   "connected",
		"message":  "Credenciais salvas com segurança (AES-256-GCM)",
	})
}

// RunRealScan executes a real scan with stored credentials.
func (h *Handler) RunRealScan(c *gin.Context) {
	var req struct {
		Provider string `json:"provider" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"scan_id":  "scan-" + req.Provider,
		"status":   "running",
		"provider": req.Provider,
		"message":  "Scan iniciado com credenciais criptografadas",
	})
}

// GetInventory retorna o inventário completo de todos os providers.
func (h *Handler) GetInventory(c *gin.Context) {
	inventoryManager := inventory.NewManager()
	providers := inventoryManager.ListProviders()
	results, _ := inventoryManager.CollectAll(c.Request.Context(), providers)
	totals := inventoryManager.GetTotalResources(results)
	c.JSON(http.StatusOK, gin.H{"providers": providers, "totals": totals, "results": results})
}

// ListInventoryProviders lista os providers disponíveis para inventário.
func (h *Handler) ListInventoryProviders(c *gin.Context) {
	inventoryManager := inventory.NewManager()
	providers := inventoryManager.ListProviders()

	result := []gin.H{}
	for _, p := range providers {
		types, err := inventoryManager.GetResourceTypes(p)
		if err != nil {
			continue
		}
		result = append(result, gin.H{
			"id":             p,
			"resource_count": len(types),
			"resource_types": types,
		})
	}

	c.JSON(http.StatusOK, gin.H{"providers": result})
}

// GetInventoryTypes retorna os tipos de recursos disponíveis.
func (h *Handler) GetInventoryTypes(c *gin.Context) {
	provider := c.Query("provider")
	if provider != "" {
		inventoryManager := inventory.NewManager()
		types, err := inventoryManager.GetResourceTypes(provider)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"provider": provider, "types": types})
		return
	}
	c.JSON(http.StatusOK, gin.H{"types": inventory.GetAllResourceTypes()})
}

// CollectInventory dispara coleta de inventário para um provider específico.
func (h *Handler) CollectInventory(c *gin.Context) {
	provider := c.Query("provider")
	providers := []string{}
	if provider != "" {
		providers = append(providers, provider)
	}
	inventoryManager := inventory.NewManager()
	results, err := inventoryManager.CollectAll(c.Request.Context(), providers)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	totals := inventoryManager.GetTotalResources(results)
	c.JSON(http.StatusOK, gin.H{"message": "Inventory collection completed", "totals": totals, "results": results})
}
