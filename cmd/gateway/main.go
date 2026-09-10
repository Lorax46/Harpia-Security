// Package main is the entry point for the API Gateway
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/Lorax46/Harpia-Security/internal/database"
	"github.com/Lorax46/Harpia-Security/internal/models"
	"github.com/Lorax46/Harpia-Security/pkg/web"
	"gorm.io/gorm"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("[gateway] Starting Harpia Security API Gateway...")

	// Connect to database
	dbConfig := database.NewConfig()
	db, err := database.Connect(dbConfig)
	if err != nil {
		log.Fatalf("[gateway] Database connection failed: %v", err)
	}

	// Run migrations
	if err := database.Migrate(); err != nil {
		log.Fatalf("[gateway] Migration failed: %v", err)
	}

	// Create default admin user
	createDefaultAdmin(db)

	// Create mock services
	scannerService := web.NewMockScannerService()
	inventoryService := web.NewMockInventoryService()
	complianceService := web.NewMockComplianceService()

	// Create HTTP server
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.Use(corsMiddleware())

	// Health check
	engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now().UTC(),
		})
	})

	// Setup routes
	handler := web.NewHandler(web.Config{
		Scanner:    scannerService,
		Inventory:  inventoryService,
		Compliance: complianceService,
	}, nil)

	setupRoutes(engine, handler)

	// Start server
	addr := getEnv("GATEWAY_ADDR", ":8080")
	srv := &http.Server{
		Addr:    addr,
		Handler: engine,
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("[gateway] Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("[gateway] Shutdown error: %v", err)
		}
		os.Exit(0)
	}()

	log.Printf("[gateway] Listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[gateway] Server error: %v", err)
	}
}

func setupRoutes(engine *gin.Engine, handler *web.Handler) {
	// Static files
	engine.Static("/static", "./web/dashboard/assets")
	engine.StaticFile("/", "./web/dashboard/index.html")

	// Auth
	auth := engine.Group("/api/auth")
	{
		auth.POST("/login", handler.Login)
		auth.POST("/register", handler.Register)
		auth.POST("/refresh", handler.Refresh)
		auth.POST("/logout", handler.Logout)
	}

	// Protected API routes
	api := engine.Group("/api")
	api.Use(handler.AuthMiddleware())
	{
		// Dashboard
		api.GET("/dashboard", handler.GetDashboard)
		api.GET("/dashboard/stats", handler.GetDashboardStats)

		// Scans
		api.GET("/scans", handler.ListScans)
		api.POST("/scans", handler.CreateScan)
		api.GET("/scans/:id", handler.GetScan)
		api.POST("/scans/:id/run", handler.RunScan)
		api.DELETE("/scans/:id", handler.DeleteScan)

		// Findings
		api.GET("/findings", handler.ListFindings)
		api.GET("/findings/:id", handler.GetFinding)
		api.PUT("/findings/:id", handler.UpdateFinding)
		api.GET("/findings/export", handler.ExportFindings)

		// Providers
		api.GET("/providers", handler.ListProviders)
		api.POST("/providers", handler.CreateProvider)
		api.PUT("/providers/:id", handler.UpdateProvider)
		api.DELETE("/providers/:id", handler.DeleteProvider)

		// Inventory
		api.GET("/inventory", handler.ListInventory)
		api.GET("/inventory/:provider/:type", handler.ListInventoryByType)
		api.GET("/inventory/:provider/:type/:id", handler.GetInventoryItem)
		api.POST("/inventory/sync", handler.SyncInventory)

		// Compliance
		api.GET("/compliance/frameworks", handler.ListFrameworks)
		api.GET("/compliance/reports", handler.ListComplianceReports)
		api.POST("/compliance/reports", handler.GenerateComplianceReport)
		api.GET("/compliance/reports/:id", handler.GetComplianceReport)
		api.GET("/compliance/reports/:id/export", handler.ExportComplianceReport)

		// Settings
		api.GET("/settings", handler.GetSettings)
		api.PUT("/settings", handler.UpdateSettings)
		api.GET("/users", handler.ListUsers)
		api.POST("/users", handler.CreateUser)
		api.PUT("/users/:id", handler.UpdateUser)
		api.DELETE("/users/:id", handler.DeleteUser)
	}

	// SPA fallback
	engine.NoRoute(func(c *gin.Context) {
		c.File("./web/dashboard/index.html")
	})
}

func createDefaultAdmin(db *gorm.DB) {
	var count int64
	db.Model(&models.User{}).Count(&count)
	if count == 0 {
		admin := &models.User{
			Username:     "admin",
			Email:        "admin@horus.local",
			PasswordHash: "$2a$10$dummyhash", // bcrypt hash of "admin"
			Role:         "admin",
			IsActive:     true,
		}
		db.Create(admin)
		log.Println("[gateway] Default admin user created (admin/admin)")
	}
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
