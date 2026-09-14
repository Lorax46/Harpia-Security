package web

import (
	"net/http"

	"github.com/Lorax46/Harpia-Security/pkg/inventory"
	"github.com/gin-gonic/gin"
)

// RegisterInventoryRoutes registra rotas de inventário
func (h *Handler) RegisterInventoryRoutes(api *gin.RouterGroup) {
	inventoryGroup := api.Group("/inventory-v2")
	{
		inventoryGroup.GET("/providers", h.ListInventoryProvidersV2)
		inventoryGroup.GET("/:provider/tables", h.ListInventoryTables)
		inventoryGroup.GET("/:provider/resources", h.ListInventoryResources)
		inventoryGroup.POST("/:provider/sync", h.SyncInventoryV2)
	}
}

// ListInventoryProvidersV2 lista providers disponíveis
func (h *Handler) ListInventoryProvidersV2(c *gin.Context) {
	svc := inventory.NewService()
	providers := svc.ListProviders()
	
	result := []gin.H{}
	for _, p := range providers {
		result = append(result, gin.H{
			"id":     p,
			"tables": svc.ListTables(p),
		})
	}
	
	c.JSON(http.StatusOK, result)
}

// ListInventoryTables lista tabelas de um provider
func (h *Handler) ListInventoryTables(c *gin.Context) {
	provider := c.Param("provider")
	svc := inventory.NewService()
	tables := svc.ListTables(provider)
	
	c.JSON(http.StatusOK, gin.H{
		"provider": provider,
		"tables":   tables,
	})
}

// ListInventoryResources lista recursos de um provider
func (h *Handler) ListInventoryResources(c *gin.Context) {
	provider := c.Param("provider")
	service := c.Query("service")
	region := c.Query("region")
	
	svc := inventory.NewService()
	filter := inventory.Filter{
		Provider: provider,
		Service:  service,
		Region:   region,
	}
	
	resources, err := svc.ListResources(provider, service, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"provider":  provider,
		"count":     len(resources),
		"resources": resources,
	})
}

// SyncInventoryV2 sincroniza recursos de um provider
func (h *Handler) SyncInventoryV2(c *gin.Context) {
	provider := c.Param("provider")
	
	svc := inventory.NewService()
	if err := svc.SyncResources(provider); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Sync started for " + provider,
	})
}
