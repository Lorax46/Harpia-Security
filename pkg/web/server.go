package web

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Config configures the HTTP server.
type Config struct {
	Addr       string
	JWTSecret  string
	Scanner    ScannerService
	Inventory  InventoryService
	Compliance ComplianceService
}

// Server is the HTTP server.
type Server struct {
	engine  *gin.Engine
	addr    string
	handler *Handler
	auth    *AuthService
}

// NewServer creates a new HTTP server.
func NewServer(cfg Config) *Server {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.Use(corsMiddleware())
	engine.Use(requestLogger())

	auth := NewAuthService(cfg.JWTSecret)
	handler := NewHandler(cfg, auth)

	s := &Server{
		engine:  engine,
		addr:    cfg.Addr,
		handler: handler,
		auth:    auth,
	}

	s.setupRoutes(auth)
	return s
}

// setupRoutes registers all routes.
func (s *Server) setupRoutes(auth *AuthService) {
	// Static files
	s.engine.Static("/static", "./web/dashboard/static")

	// Auth (NO middleware)
	authGroup := s.engine.Group("/api/auth")
	{
		authGroup.POST("/login", s.handler.Login)
		authGroup.POST("/register", s.handler.Register)
		authGroup.POST("/refresh", s.handler.Refresh)
		authGroup.POST("/logout", s.handler.Logout)
	}

	// Protected API routes
	api := s.engine.Group("/api")
	api.Use(s.handler.AuthMiddleware())
	{
		api.GET("/dashboard", s.handler.GetDashboard)
		api.GET("/dashboard/stats", s.handler.GetDashboardStats)

		api.GET("/scans", s.handler.ListScans)
		api.POST("/scans", s.handler.CreateScan)
		api.GET("/scans/:id", s.handler.GetScan)
		api.POST("/scans/:id/run", s.handler.RunScan)
		api.DELETE("/scans/:id", s.handler.DeleteScan)

		api.GET("/findings", s.handler.ListFindings)
		api.GET("/findings-by-provider", s.handler.ListFindingsByProvider)
		api.GET("/findings-stats", s.handler.ListFindingsStats)
		api.GET("/findings/:provider/:type", s.handler.ListFindingsByProviderAndType)
		api.GET("/finding/:id", s.handler.GetFinding)
		api.PUT("/finding/:id", s.handler.UpdateFinding)
		api.GET("/findings/export", s.handler.ExportFindings)

		api.GET("/providers", s.handler.ListProviders)
		api.POST("/providers", s.handler.CreateProvider)
		api.PUT("/providers/:id", s.handler.UpdateProvider)
		api.DELETE("/providers/:id", s.handler.DeleteProvider)

		api.GET("/inventory", s.handler.ListInventory)
		api.GET("/inventory/:provider/:type", s.handler.ListInventoryByType)
		api.GET("/inventory/:provider/:type/:id", s.handler.GetInventoryItem)
		api.POST("/inventory/sync", s.handler.SyncInventory)

		api.GET("/compliance/frameworks", s.handler.ListFrameworks)
		api.GET("/compliance/reports", s.handler.ListComplianceReports)
		api.POST("/compliance/reports", s.handler.GenerateComplianceReport)
		api.GET("/compliance/reports/:id", s.handler.GetComplianceReport)
		api.GET("/compliance/reports/:id/export", s.handler.ExportComplianceReport)

		api.GET("/settings", s.handler.GetSettings)
		api.PUT("/settings", s.handler.UpdateSettings)
		api.GET("/users", s.handler.ListUsers)
		api.POST("/users", s.handler.CreateUser)
		api.PUT("/users/:id", s.handler.UpdateUser)
		api.DELETE("/users/:id", s.handler.DeleteUser)
	}

	// Scan & Credentials routes
	s.handler.RegisterScanRoutes(api)

	// Inventory routes
	s.handler.RegisterInventoryRoutes(api)

	// Vault routes
	api.POST("/vault/unlock", s.handler.UnlockVault)
	api.POST("/vault/lock", s.handler.LockVault)
	api.GET("/vault/status", s.handler.GetVaultStatus)

	// Bulk import routes
	api.POST("/import/bulk", s.handler.BulkImportCredentials)
	api.POST("/import/csv", s.handler.ImportCredentialsFromCSV)
	api.GET("/import/template", s.handler.GetImportTemplateCSV)

	// Page routes (SPA)
	pageRoutes := []string{"/", "/dashboard", "/findings", "/inventory", "/automation", "/configuration"}
	for _, route := range pageRoutes {
		s.engine.GET(route, s.handler.Page)
	}

	// SPA fallback
	s.engine.NoRoute(func(c *gin.Context) {
		c.File("./web/dashboard/index.html")
	})
}

// Run starts the HTTP server.
func (s *Server) Run() error {
	log.Printf("[web] Listening on %s", s.addr)
	return s.engine.Run(s.addr)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return nil
}

// ServeHTTP implements http.Handler for testing
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.engine.ServeHTTP(w, r)
}

// Addr returns the server address.
func (s *Server) Addr() string {
	return s.addr
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

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery
		c.Next()
		latency := time.Since(start)
		if raw != "" {
			path = path + "?" + raw
		}
		log.Printf("[web] %s %s %d %v", c.Request.Method, path, c.Writer.Status(), latency)
	}
}
