// Package web provides HTTP handlers for the Harpia Security dashboard.
package web

import (
	"log"
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
	var providers []string
	if h.inventoryMgr != nil {
		providers = h.inventoryMgr.ListProviders()
	} else {
		svc := inventory.GetService()
		providers = svc.ListProviders()
	}

	result := []gin.H{}
	for _, p := range providers {
		var tables []string
		if h.inventoryMgr != nil {
			if types, err := h.inventoryMgr.GetResourceTypes(p); err == nil {
				for _, t := range types {
					tables = append(tables, t.Name)
				}
			}
		} else {
			svc := inventory.GetService()
			tables = svc.ListTables(p)
		}
		result = append(result, gin.H{
			"id":     p,
			"tables": tables,
		})
	}

	c.JSON(200, result)
}

// ListInventoryTables lists tables for a provider
func (h *Handler) ListInventoryTables(c *gin.Context) {
	provider := c.Param("provider")
	var tables []string
	if h.inventoryMgr != nil {
		if types, err := h.inventoryMgr.GetResourceTypes(provider); err == nil {
			for _, t := range types {
				tables = append(tables, t.Name)
			}
		}
	} else {
		svc := inventory.GetService()
		tables = svc.ListTables(provider)
	}

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

	filter := inventory.Filter{
		Provider: provider,
		Service:  service,
		Region:   region,
		Category: category,
	}

	var resources []inventory.Resource
	var err error
	if h.inventoryMgr != nil {
		resources, err = h.inventoryMgr.ListResources(provider, service, filter)
	} else {
		svc := inventory.GetService()
		resources, err = svc.ListResources(provider, service, filter)
	}
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

	log.Printf("[HANDLER] SyncInventoryV2 called for provider: %s", provider)
	log.Printf("[HANDLER] h.inventoryMgr is nil: %v", h.inventoryMgr == nil)

	var err error
	if h.inventoryMgr != nil {
		log.Printf("[HANDLER] Calling h.inventoryMgr.SyncResources(%s)", provider)
		err = h.inventoryMgr.SyncResources(provider)
	} else {
		log.Printf("[HANDLER] Using inventory.GetService()")
		svc := inventory.GetService()
		err = svc.SyncResources(provider)
	}
	if err != nil {
		log.Printf("[HANDLER] Sync error for %s: %v", provider, err)
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[HANDLER] Sync completed for %s", provider)
	c.JSON(200, gin.H{
		"message": "Sync completed for " + provider,
	})
}

// ensureOCICollector creates the OCI collector from vault credentials
func ensureOCICollector(mgr *inventory.Manager) {
	// This is handled by the collector's lazy init
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
