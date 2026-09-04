package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/executor"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	oci_checks "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/oci"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/providers/oci"
)

// ScanRequest representa uma requisição de scan
type ScanRequest struct {
	Provider    string   `json:"provider"`
	Region      string   `json:"region"`
	TenancyID   string   `json:"tenancy_id"`
	UserID      string   `json:"user_id"`
	Fingerprint string   `json:"fingerprint"`
	PrivateKey  string   `json:"private_key"`
	Passphrase  string   `json:"passphrase"`
	Services    []string `json:"services,omitempty"`
}

// ScanResponse representa uma resposta de scan
type ScanResponse struct {
	Success    bool             `json:"success"`
	Message    string           `json:"message"`
	ScanID     string           `json:"scan_id"`
	Provider   string           `json:"provider"`
	StartedAt  time.Time        `json:"started_at"`
	FinishedAt time.Time        `json:"finished_at"`
	Summary    models.Summary   `json:"summary"`
	Findings   []models.Finding `json:"findings"`
}

// ErrorResponse representa uma resposta de erro
type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

var scanHistory = make(map[string]models.ScanResult)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/api/scan", handleScan)
	mux.HandleFunc("/api/findings", handleFindings)
	mux.HandleFunc("/api/findings/", handleFindingsDetail)
	
	handler := corsMiddleware(mux)
	
	port := ":8083"
	log.Printf("TOTVS Horus Scanner API rodando em http://0.0.0.0%s", port)
	log.Fatal(http.ListenAndServe(port, handler))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "healthy", "service": "totvs-horus-scanner"})
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	
	if req.Provider == "" {
		writeError(w, http.StatusBadRequest, "Provider is required")
		return
	}
	
	result := executeScan(r.Context(), req)
	
	resp := ScanResponse{
		Success:    true,
		Message:    fmt.Sprintf("Scan completed with %d findings", len(result.Findings)),
		ScanID:     fmt.Sprintf("scan-%d", time.Now().Unix()),
		Provider:   req.Provider,
		StartedAt:  result.StartedAt,
		FinishedAt: result.FinishedAt,
		Summary:    result.Summary,
		Findings:   result.Findings,
	}
	
	scanHistory[resp.ScanID] = result
	
	writeJSON(w, http.StatusOK, resp)
}

func executeScan(ctx context.Context, req ScanRequest) models.ScanResult {
	provider, err := oci.NewProvider(ctx, req.Region, req.TenancyID, req.UserID, req.Fingerprint, req.PrivateKey, req.Passphrase)
	if err != nil {
		log.Printf("Erro ao criar provider: %v", err)
		return models.ScanResult{Provider: req.Provider, Region: req.Region}
	}
	
	exec := executor.New(provider)
	
	switch req.Provider {
	case "oci":
		addOCIChecks(exec, req.Services)
	default:
		log.Printf("Provider %s not supported yet", req.Provider)
	}
	
	result := exec.Run(ctx)
	result.Region = req.Region
	
	return result
}

func addOCIChecks(exec *executor.Executor, services []string) {
	servicesToRun := services
	if len(servicesToRun) == 0 {
		servicesToRun = make([]string, 0)
		for service := range oci_checks.Registry {
			servicesToRun = append(servicesToRun, service)
		}
	}
	
	for _, service := range servicesToRun {
		if checks, ok := oci_checks.Registry[service]; ok {
			for _, check := range checks {
				exec.Add(check)
			}
		}
	}
}

func handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var allFindings []models.Finding
	for _, result := range scanHistory {
		allFindings = append(allFindings, result.Findings...)
	}
	
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"count":    len(allFindings),
		"findings": allFindings,
	})
}

func handleFindingsDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		writeError(w, http.StatusBadRequest, "Scan ID not specified")
		return
	}
	
	scanID := parts[3]
	
	result, ok := scanHistory[scanID]
	if !ok {
		writeError(w, http.StatusNotFound, "Scan not found")
		return
	}
	
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"scan_id": scanID,
		"result":  result,
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Success: false, Error: msg})
}
