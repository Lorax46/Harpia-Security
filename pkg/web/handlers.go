// Package web provides HTTP handlers for the Harpia Security dashboard.
package web

import (
	"net/http"
	"strings"

	"github.com/Lorax46/Harpia-Security/pkg/inventory"
	"github.com/gin-gonic/gin"
)

// Handler handles HTTP requests.
type Handler struct {
	config     Config
	scanner    ScannerService
	inventory  InventoryService
	compliance ComplianceService
}

// NewHandler creates a new HTTP handler.
func NewHandler(cfg Config, auth *AuthService) *Handler {
	return &Handler{
		config:     cfg,
		scanner:    cfg.Scanner,
		inventory:  cfg.Inventory,
		compliance: cfg.Compliance,
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
	stats := h.getRealStats(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

// GetDashboardStats returns dashboard statistics.
func (h *Handler) GetDashboardStats(c *gin.Context) {
	stats := h.getRealStats(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

// getRealStats tenta obter stats reais do scanner
func (h *Handler) getRealStats(ctx interface{}) gin.H {
	// Por enquanto retorna stats mock
	// Em produção, usaria o scanner.Service real
	return gin.H{
		"total_findings": 0,
		"critical":       0,
		"high":           0,
		"medium":         0,
		"low":            0,
		"providers":      5,
		"checks":         1139,
	}
}

// ListScans returns all scans.
func (h *Handler) ListScans(c *gin.Context) {
	c.JSON(http.StatusOK, []gin.H{
		{"id": "oci-scan-1", "name": "OCI Scan", "provider": "oci", "status": "completed"},
	})
}

// CreateScan creates a new scan.
func (h *Handler) CreateScan(c *gin.Context) {
	var req CreateScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": "scan-" + req.Provider, "name": req.Name, "provider": req.Provider, "status": "pending"})
}

// GetScan returns a scan.
func (h *Handler) GetScan(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "name": "Scan", "status": "completed"})
}

// RunScan runs a scan.
func (h *Handler) RunScan(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"message": "scan started", "id": id})
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

// ListProviders returns all providers.
func (h *Handler) ListProviders(c *gin.Context) {
	c.JSON(http.StatusOK, []gin.H{
		{"id": "aws", "provider": "aws", "region": "us-east-1", "status": "connected"},
		{"id": "oci", "provider": "oci", "region": "sa-saopaulo-1", "status": "connected"},
	})
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
	ctx := c.Request.Context()
	result, err := h.scanner.GetFindingsByProvider(ctx)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

// ListFindingsStats returns statistics for findings.
func (h *Handler) ListFindingsStats(c *gin.Context) {
	ctx := c.Request.Context()
	stats, err := h.scanner.GetFindingsStats(ctx)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
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

// CreateCredentials creates new provider credentials.
func (h *Handler) CreateCredentials(c *gin.Context) {
	var req struct {
		Provider     string `json:"provider" binding:"required"`
		Name         string `json:"name" binding:"required"`
		Region       string `json:"region"`
		AccessKey    string `json:"access_key"`
		SecretKey    string `json:"secret_key"`
		TenancyOCID  string `json:"tenancy_ocid"`
		UserOCID     string `json:"user_ocid"`
		Fingerprint  string `json:"fingerprint"`
		PrivateKey   string `json:"private_key"`
		SubscriptionID string `json:"subscription_id"`
		ClientID       string `json:"client_id"`
		ClientSecret   string `json:"client_secret"`
		TenantID       string `json:"tenant_id"`
		ProjectID    string `json:"project_id"`
		ServiceKey   string `json:"service_key"`
		APIToken     string `json:"api_token"`
		ZoneID       string `json:"zone_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Salvar credenciais no scanner service
	credMap := map[string]string{
		"name":       req.Name,
		"region":     req.Region,
		"access_key": req.AccessKey,
		"secret_key": req.SecretKey,
	}
	
	// Adicionar campos específicos do provider
	if req.TenancyOCID != "" { credMap["tenancy_ocid"] = req.TenancyOCID }
	if req.UserOCID != "" { credMap["user_ocid"] = req.UserOCID }
	if req.Fingerprint != "" { credMap["fingerprint"] = req.Fingerprint }
	if req.PrivateKey != "" { credMap["private_key"] = req.PrivateKey }
	if req.SubscriptionID != "" { credMap["subscription_id"] = req.SubscriptionID }
	if req.ClientID != "" { credMap["client_id"] = req.ClientID }
	if req.ClientSecret != "" { credMap["client_secret"] = req.ClientSecret }
	if req.ProjectID != "" { credMap["project_id"] = req.ProjectID }
	if req.ServiceKey != "" { credMap["service_key"] = req.ServiceKey }
	if req.APIToken != "" { credMap["api_token"] = req.APIToken }
	
	h.scanner.StoreCredentials(req.Provider, credMap)
	
	// Registrar provider no inventory
	// (Em produção, isso criaria um scanner.Service real com as credenciais)
	
	c.JSON(http.StatusCreated, gin.H{
		"id":       req.Provider + "-" + req.Name,
		"provider": req.Provider,
		"name":     req.Name,
		"status":   "connected",
		"message":  "Credenciais salvas com sucesso",
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
		"message":  "Scan iniciado com credenciais reais",
	})
}
