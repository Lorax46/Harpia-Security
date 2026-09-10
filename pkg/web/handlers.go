// Package web provides HTTP handlers for the TORUS Horus dashboard.
package web

import (
	"net/http"
	"strings"

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
		c.Set("user", &Session{Username: "admin", Role: "admin", Token: token})
		c.Next()
	}
}

// Auth handlers

func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// For beta: accept any credentials with username "admin"
	if req.Username == "admin" && req.Password == "admin" {
		c.JSON(http.StatusOK, gin.H{"token": "beta-admin-token", "user": gin.H{"username": "admin", "role": "admin"}})
		return
	}
	// Check hardcoded user for demo
	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
}

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

func (h *Handler) Refresh(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"token": "refreshed-token"})
}

func (h *Handler) Logout(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

// Dashboard handlers

func (h *Handler) GetDashboard(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"stats": gin.H{
			"total_findings": 142,
			"critical":       12,
			"high":           35,
			"medium":         50,
			"low":            45,
			"providers":      4,
			"scans":          3,
		},
	})
}

func (h *Handler) GetDashboardStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"findings_by_provider": gin.H{
			"aws":   89,
			"gcp":   38,
			"azure": 15,
		},
		"findings_by_severity": gin.H{
			"critical": 12,
			"high":     35,
			"medium":   50,
			"low":      45,
		},
		"compliance_score": 85.5,
	})
}

// Scan handlers

func (h *Handler) ListScans(c *gin.Context) {
	scans, err := h.scanner.ListScans(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, scans)
}

func (h *Handler) CreateScan(c *gin.Context) {
	var req CreateScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	scan, err := h.scanner.CreateScan(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, scan)
}

func (h *Handler) GetScan(c *gin.Context) {
	id := c.Param("id")
	scan, err := h.scanner.GetScan(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, scan)
}

func (h *Handler) RunScan(c *gin.Context) {
	id := c.Param("id")
	if err := h.scanner.RunScan(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "scan started"})
}

func (h *Handler) DeleteScan(c *gin.Context) {
	id := c.Param("id")
	if err := h.scanner.DeleteScan(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "scan deleted"})
}

// Finding handlers

func (h *Handler) ListFindings(c *gin.Context) {
	filter := FindingsFilter{
		Provider: c.Query("provider"),
		Severity: c.Query("severity"),
		Status:   c.Query("status"),
	}
	findings, err := h.scanner.ListFindings(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, findings)
}

func (h *Handler) GetFinding(c *gin.Context) {
	id := c.Param("id")
	finding, err := h.scanner.GetFinding(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, finding)
}

func (h *Handler) UpdateFinding(c *gin.Context) {
	id := c.Param("id")
	var req UpdateFindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	finding, err := h.scanner.UpdateFinding(c.Request.Context(), id, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, finding)
}

func (h *Handler) ExportFindings(c *gin.Context) {
	format := c.DefaultQuery("format", "csv")
	data, err := h.scanner.ExportFindings(c.Request.Context(), format)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Data(http.StatusOK, "text/csv", data)
}

// Provider handlers

func (h *Handler) ListProviders(c *gin.Context) {
	c.JSON(http.StatusOK, []gin.H{
		{"id": "aws-prod", "provider": "aws", "region": "us-east-1", "status": "connected"},
		{"id": "gcp-dev", "provider": "gcp", "region": "us-central1", "status": "connected"},
		{"id": "azure-main", "provider": "azure", "region": "eastus", "status": "connected"},
	})
}

func (h *Handler) CreateProvider(c *gin.Context) {
	var req ProviderConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": "provider-" + req.Provider, "status": "connected"})
}

func (h *Handler) UpdateProvider(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "updated"})
}

func (h *Handler) DeleteProvider(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "deleted"})
}

// Inventory handlers

func (h *Handler) ListInventory(c *gin.Context) {
	provider := c.DefaultQuery("provider", "aws")
	resources, err := h.inventory.ListResources(c.Request.Context(), provider, "", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resources)
}

func (h *Handler) ListInventoryByType(c *gin.Context) {
	provider := c.Param("provider")
	resourceType := c.Param("type")
	resources, err := h.inventory.ListResources(c.Request.Context(), provider, resourceType, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resources)
}

func (h *Handler) GetInventoryItem(c *gin.Context) {
	provider := c.Param("provider")
	resourceType := c.Param("type")
	id := c.Param("id")
	resource, err := h.inventory.GetResource(c.Request.Context(), provider, resourceType, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resource)
}

func (h *Handler) SyncInventory(c *gin.Context) {
	provider := c.DefaultQuery("provider", "aws")
	if err := h.inventory.SyncResources(c.Request.Context(), provider); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "sync completed"})
}

// Compliance handlers

func (h *Handler) ListFrameworks(c *gin.Context) {
	frameworks := h.compliance.ListFrameworks(c.Request.Context())
	c.JSON(http.StatusOK, frameworks)
}

func (h *Handler) ListComplianceReports(c *gin.Context) {
	reports, err := h.compliance.ListReports(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, reports)
}

func (h *Handler) GenerateComplianceReport(c *gin.Context) {
	var req struct {
		FrameworkID string `json:"framework_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": "report-1", "framework_id": req.FrameworkID, "status": "generating"})
}

func (h *Handler) GetComplianceReport(c *gin.Context) {
	id := c.Param("id")
	report, err := h.compliance.GetReport(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, report)
}

func (h *Handler) ExportComplianceReport(c *gin.Context) {
	id := c.Param("id")
	format := c.DefaultQuery("format", "csv")
	data, err := h.compliance.ExportReport(c.Request.Context(), id, format)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Data(http.StatusOK, "text/csv", data)
}

// Settings handlers

func (h *Handler) GetSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"providers": []gin.H{
			{"id": "aws-prod", "provider": "aws", "region": "us-east-1"},
			{"id": "gcp-dev", "provider": "gcp", "region": "us-central1"},
		},
	})
}

func (h *Handler) UpdateSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "settings updated"})
}

// User handlers

func (h *Handler) ListUsers(c *gin.Context) {
	c.JSON(http.StatusOK, []gin.H{
		{"id": "admin", "username": "admin", "role": "admin"},
	})
}

func (h *Handler) CreateUser(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"id": "new-user", "role": "viewer"})
}

func (h *Handler) UpdateUser(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "updated"})
}

func (h *Handler) DeleteUser(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "deleted"})
}
