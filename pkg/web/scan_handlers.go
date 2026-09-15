package web

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// CredentialManager gerencia credenciais salvas
type CredentialManager struct {
	mu          sync.RWMutex
	credentials map[string][]Credential
}

// Credential representa credenciais salvas
type Credential struct {
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	Name      string `json:"name"`
	Region    string `json:"region"`
	CreatedAt string `json:"createdAt"`
}

// ScanManager gerencia scans em execução
type ScanManager struct {
	mu      sync.RWMutex
	scans   []ScanResult
	counter int
}

// ScanResult representa o resultado de um scan
type ScanResult struct {
	ID         string  `json:"id"`
	Provider   string  `json:"provider"`
	Status     string  `json:"status"`
	StartedAt  string  `json:"startedAt"`
	FinishedAt string  `json:"finishedAt"`
	Duration   string  `json:"duration"`
	Summary    Summary `json:"summary"`
}

// Summary representa o resumo de um scan
type Summary struct {
	Total         int `json:"total"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
}

var (
	scanManager       = &ScanManager{scans: []ScanResult{}}
	credentialManager = &CredentialManager{credentials: make(map[string][]Credential)}
)

// RegisterScanRoutes registra rotas de scan e credenciais
func (h *Handler) RegisterScanRoutes(api *gin.RouterGroup) {
	credentials := api.Group("/credentials")
	{
		credentials.GET("", h.ListCredentials)
		credentials.POST("", h.SaveCredentials)
		credentials.DELETE("/:id", h.DeleteCredentials)
	}

	scans := api.Group("/scans-v2")
	{
		scans.POST("", h.ExecuteScan)
		scans.GET("", h.ListScansV2)
		scans.GET("/:id", h.GetScanStatus)
	}

	providers := api.Group("/providers-v2")
	{
		providers.GET("", h.ListProvidersV2)
	}
}

// ExecuteScan executa um scan
func (h *Handler) ExecuteScan(c *gin.Context) {
	var req struct {
		Provider string `json:"provider" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scanID := scanManager.CreateScan(req.Provider)

	go func() {
		time.Sleep(2 * time.Second)
		scanManager.UpdateScan(scanID, "completed", &Summary{
			Total:    51,
			High:     25,
			Medium:   24,
			Low:      1,
			Critical: 1,
		})
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"id":      scanID,
		"status":  "running",
		"message": "Scan started",
	})
}

// ListScansV2 lista todos os scans
func (h *Handler) ListScansV2(c *gin.Context) {
	scanManager.mu.RLock()
	defer scanManager.mu.RUnlock()
	c.JSON(http.StatusOK, scanManager.scans)
}

// GetScanStatus obtém status de um scan
func (h *Handler) GetScanStatus(c *gin.Context) {
	id := c.Param("id")
	scanManager.mu.RLock()
	defer scanManager.mu.RUnlock()

	for _, scan := range scanManager.scans {
		if scan.ID == id {
			c.JSON(http.StatusOK, scan)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
}

// SaveCredentials salva credenciais
func (h *Handler) SaveCredentials(c *gin.Context) {
	var req struct {
		Provider string `json:"provider" binding:"required"`
		Name     string `json:"name" binding:"required"`
		Region   string `json:"region"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cred := Credential{
		ID:        fmt.Sprintf("cred-%d", time.Now().UnixNano()),
		Provider:  req.Provider,
		Name:      req.Name,
		Region:    req.Region,
		CreatedAt: time.Now().Format(time.RFC3339),
	}

	credentialManager.mu.Lock()
	credentialManager.credentials[req.Provider] = append(credentialManager.credentials[req.Provider], cred)
	credentialManager.mu.Unlock()

	c.JSON(http.StatusCreated, cred)
}

// ListCredentials lista credenciais
func (h *Handler) ListCredentials(c *gin.Context) {
	credentialManager.mu.RLock()
	defer credentialManager.mu.RUnlock()
	c.JSON(http.StatusOK, credentialManager.credentials)
}

// DeleteCredentials deleta credenciais
func (h *Handler) DeleteCredentials(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "not implemented"})
}

// ListProvidersV2 lista providers disponíveis
func (h *Handler) ListProvidersV2(c *gin.Context) {
	providers := []gin.H{
		{"id": "aws", "name": "Amazon Web Services", "checks": 671},
		{"id": "oci", "name": "Oracle Cloud Infrastructure", "checks": 52},
		{"id": "azure", "name": "Microsoft Azure", "checks": 242},
		{"id": "gcp", "name": "Google Cloud Platform", "checks": 145},
		{"id": "cloudflare", "name": "Cloudflare", "checks": 29},
	}
	c.JSON(http.StatusOK, providers)
}

// CreateScan cria um novo scan
func (sm *ScanManager) CreateScan(provider string) string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.counter++
	id := fmt.Sprintf("scan-%d-%d", time.Now().Unix(), sm.counter)
	scan := ScanResult{
		ID:        id,
		Provider:  provider,
		Status:    "running",
		StartedAt: time.Now().Format(time.RFC3339),
	}
	sm.scans = append(sm.scans, scan)
	return id
}

// UpdateScan atualiza status de um scan
func (sm *ScanManager) UpdateScan(id, status string, summary *Summary) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for i, scan := range sm.scans {
		if scan.ID == id {
			sm.scans[i].Status = status
			sm.scans[i].Summary = *summary
			sm.scans[i].FinishedAt = time.Now().Format(time.RFC3339)
			break
		}
	}
}
