// Package web provides HTTP handlers for the Harpia Security dashboard.
package web

import (
	"net/http"

	"github.com/Lorax46/Harpia-Security/pkg/inventory"
	"github.com/gin-gonic/gin"
)

// RegisterScanRoutes registers scan-related routes (credentials and real scans)
func (h *Handler) RegisterScanRoutes(api *gin.RouterGroup) {
	scans := api.Group("/scans-v2")
	{
		scans.GET("", h.ListScans)
		scans.POST("", h.CreateScan)
		scans.POST("/credentials", h.CreateCredentials)
		scans.POST("/run-real", h.RunRealScan)
	}
}

// RegisterInventoryRoutes registers inventory-related routes
func (h *Handler) RegisterInventoryRoutes(api *gin.RouterGroup) {
	inventoryGroup := api.Group("/inventory-v2")
	{
		inventoryGroup.GET("/providers", h.ListInventoryProvidersV2)
		inventoryGroup.GET("/:provider/tables", h.ListInventoryTables)
		inventoryGroup.GET("/:provider/resources", h.ListInventoryResources)
		inventoryGroup.POST("/:provider/sync", h.SyncInventoryV2)
	}
}

// ListInventoryProvidersV2 lists available inventory providers
func (h *Handler) ListInventoryProvidersV2(c *gin.Context) {
	svc := inventory.GetService()
	providers := svc.ListProviders()
	
	result := []gin.H{}
	for _, p := range providers {
		result = append(result, gin.H{
			"id":     p,
			"tables": svc.ListTables(p),
		})
	}
	
	c.JSON(200, result)
}

// ListInventoryTables lists tables for a provider
func (h *Handler) ListInventoryTables(c *gin.Context) {
	provider := c.Param("provider")
	svc := inventory.GetService()
	tables := svc.ListTables(provider)
	
	c.JSON(200, gin.H{
		"provider": provider,
		"tables":   tables,
	})
}

// ListInventoryResources lists resources for a provider
func (h *Handler) ListInventoryResources(c *gin.Context) {
	provider := c.Param("provider")
	service := c.Query("service")
	region := c.Query("region")
	category := c.Query("category")
	
	svc := inventory.GetService()
	filter := inventory.Filter{
		Provider: provider,
		Service:  service,
		Region:   region,
		Category: category,
	}
	
	resources, err := svc.ListResources(provider, service, filter)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(200, gin.H{
		"provider":  provider,
		"count":     len(resources),
		"resources": resources,
	})
}

// SyncInventoryV2 syncs inventory for a provider
func (h *Handler) SyncInventoryV2(c *gin.Context) {
	provider := c.Param("provider")
	
	svc := inventory.GetService()
	if err := svc.SyncResources(provider); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(200, gin.H{
		"message": "Sync completed for " + provider,
	})
}

// UnlockVault unlocks the credential vault with a passphrase
func (h *Handler) UnlockVault(c *gin.Context) {
	var req struct {
		Passphrase string `json:"passphrase" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	if err := h.vault.Unlock(req.Passphrase); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid passphrase"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Vault unlocked"})
}

// LockVault locks the credential vault
func (h *Handler) LockVault(c *gin.Context) {
	h.vault.Lock()
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Vault locked"})
}

// GetVaultStatus returns the vault status
func (h *Handler) GetVaultStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"unlocked": h.vault.IsUnlocked(),
	})
}
