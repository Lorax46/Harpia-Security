package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerEndpoints(t *testing.T) {
	// Create test server
	scannerService := NewScanService()
	complianceService := NewMockComplianceService()
	inventoryService := NewMockInventoryService()

	server := NewServer(Config{
		Addr:       ":0",
		JWTSecret:  "test-secret",
		Scanner:    scannerService,
		Inventory:  inventoryService,
		Compliance: complianceService,
	})

	// Test GET index page
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	t.Logf("GET / -> %d", w.Result().StatusCode)
	if w.Result().StatusCode != http.StatusOK && w.Result().StatusCode != http.StatusFound {
		t.Errorf("GET / returned %d, want 200 or 302", w.Result().StatusCode)
	}

	// Test POST login
	body := `{"username":"admin","password":"admin"}`
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	t.Logf("POST /api/auth/login -> %d: %s", w.Result().StatusCode, w.Body.String())
	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("POST /api/auth/login returned %d, want 200", w.Result().StatusCode)
	}

	// Test GET /api/scans without token
	req = httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	t.Logf("GET /api/scans (sem token) -> %d", w.Result().StatusCode)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/scans without token returned %d, want 401", w.Result().StatusCode)
	}

	// Test GET /api/scans with token
	req = httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	req.Header.Set("Authorization", "Bearer beta-admin-token")
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	t.Logf("GET /api/scans (com token) -> %d: %s", w.Result().StatusCode, w.Body.String())
	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("GET /api/scans with token returned %d, want 200", w.Result().StatusCode)
	}
}
