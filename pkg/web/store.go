// Package web provides real scan result storage.
package web

import (
	"sync"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// scanResults stores all scan findings globally.
var scanResults = struct {
	mu      sync.RWMutex
	Results map[string][]models.Finding
}{
	Results: make(map[string][]models.Finding),
}

// SaveFindings saves findings for a scan.
func SaveFindings(scanID string, findings []models.Finding) {
	scanResults.mu.Lock()
	defer scanResults.mu.Unlock()
	scanResults.Results[scanID] = findings
}

// GetFindings retrieves findings by scan ID.
func GetFindings(scanID string) []models.Finding {
	scanResults.mu.RLock()
	defer scanResults.mu.RUnlock()
	return scanResults.Results[scanID]
}

// GetAllFindings returns all findings grouped by provider.
func GetAllFindings() map[string][]models.Finding {
	scanResults.mu.RLock()
	defer scanResults.mu.RUnlock()

	result := make(map[string][]models.Finding)
	for _, findings := range scanResults.Results {
		for _, f := range findings {
			result[f.Provider] = append(result[f.Provider], f)
		}
	}
	return result
}

// GetStats returns aggregated statistics.
func GetStats() map[string]interface{} {
	scanResults.mu.RLock()
	defer scanResults.mu.RUnlock()

	stats := map[string]interface{}{
		"total":     0,
		"critical":  0,
		"high":      0,
		"medium":    0,
		"low":       0,
		"providers": make(map[string]map[string]int),
	}

	providersStats := stats["providers"].(map[string]map[string]int)

	for _, findings := range scanResults.Results {
		for _, f := range findings {
			stats["total"] = stats["total"].(int) + 1

			p := f.Provider
			if _, ok := providersStats[p]; !ok {
				providersStats[p] = map[string]int{
					"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "pass": 0, "fail": 0,
				}
			}
			providersStats[p]["total"]++

			switch f.Severity {
			case "critical":
				stats["critical"] = stats["critical"].(int) + 1
				providersStats[p]["critical"]++
			case "high":
				stats["high"] = stats["high"].(int) + 1
				providersStats[p]["high"]++
			case "medium":
				stats["medium"] = stats["medium"].(int) + 1
				providersStats[p]["medium"]++
			case "low":
				stats["low"] = stats["low"].(int) + 1
				providersStats[p]["low"]++
			}

			if string(f.Status) == "PASS" {
				providersStats[p]["pass"]++
			} else {
				providersStats[p]["fail"]++
			}
		}
	}

	return stats
}

// FindingsByProviderAndType returns findings filtered by type.
func FindingsByProviderAndType(provider, findingType string) []models.Finding {
	scanResults.mu.RLock()
	defer scanResults.mu.RUnlock()

	var filtered []models.Finding
	for _, findings := range scanResults.Results {
		for _, f := range findings {
			if f.Provider == provider {
				if findingType == "all" {
					filtered = append(filtered, f)
				} else if findingType == "fail" && string(f.Status) != "PASS" {
					filtered = append(filtered, f)
				} else if findingType == "pass" && string(f.Status) == "PASS" {
					filtered = append(filtered, f)
				} else if f.Severity == findingType {
					filtered = append(filtered, f)
				}
			}
		}
	}
	return filtered
}

// GetScans returns all scans.
func GetScans() []map[string]interface{} {
	scanResults.mu.RLock()
	defer scanResults.mu.RUnlock()

	var scans []map[string]interface{}
	seen := make(map[string]bool)
	for _, findings := range scanResults.Results {
		if len(findings) > 0 && !seen[findings[0].Provider] {
			seen[findings[0].Provider] = true
			scans = append(scans, map[string]interface{}{
				"id":        findings[0].Provider + "-scan",
				"provider":  findings[0].Provider,
				"status":    "completed",
				"findings":  len(findings),
				"last_scan": time.Now(),
			})
		}
	}
	return scans
}

// Entry type for compatibility
type Entry struct {
	ID        string             `json:"id"`
	Name      string             `json:"name"`
	Provider  string             `json:"provider"`
	Region    string             `json:"region"`
	Status    string             `json:"status"`
	Result    *models.ScanResult `json:"result"`
	CreatedAt time.Time          `json:"created_at"`
}

// Store type for compatibility
type Store struct {
	Save    func(entry Entry)
	Get     func(id string) (Entry, bool)
	GetAll  func() map[string][]models.Finding
	GetStats func() map[string]interface{}
}

// scanStore variable for compatibility
var scanStore = &Store{
	Save: func(entry Entry) {
		if entry.Result != nil {
			SaveFindings(entry.ID, entry.Result.Findings)
		}
	},
	Get: func(id string) (Entry, bool) {
		findings := GetFindings(id)
		return Entry{ID: id}, len(findings) > 0
	},
	GetAll:  GetAllFindings,
	GetStats: GetStats,
}

// Save for compatibility
func Save(entry Entry) {
	if entry.Result != nil {
		SaveFindings(entry.ID, entry.Result.Findings)
	}
}

// Get for compatibility
func Get(id string) (Entry, bool) {
	findings := GetFindings(id)
	return Entry{ID: id}, len(findings) > 0
}

// GetAll for compatibility
func GetAll() map[string][]models.Finding {
	return GetAllFindings()
}

// GetStore for compatibility
func GetStore() *Store {
	return scanStore
}
