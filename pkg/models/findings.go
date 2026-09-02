package models

import "time"

// Severity nível de criticidade
type Severity string

const (
	Critical      Severity = "critical"
	High          Severity = "high"
	Medium        Severity = "medium"
	Low           Severity = "low"
	Informational Severity = "informational"
)

// Finding representa um achado de segurança
type Finding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    Severity  `json:"severity"`
	Provider    string    `json:"provider"`
	Service     string    `json:"service"`
	ResourceID  string    `json:"resource_id"`
	Region      string    `json:"region"`
	Benchmark   string    `json:"benchmark,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	FoundAt     time.Time `json:"found_at"`
}

// ScanResult resultado de um scan
type ScanResult struct {
	Provider   string    `json:"provider"`
	Region     string    `json:"region"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Findings   []Finding `json:"findings"`
	Summary    Summary   `json:"summary"`
}

// Summary resumo de achados por severidade
type Summary struct {
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
	Total         int `json:"total"`
}

// InventoryItem recurso descoberto
type InventoryItem struct {
	Provider   string            `json:"provider"`
	Type       string            `json:"type"`
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Region     string            `json:"region"`
	Endpoints  []Endpoint        `json:"endpoints,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	Discovered time.Time         `json:"discovered"`
}

// Endpoint representa um endpoint de rede exposto
type Endpoint struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Public   bool   `json:"public"`
	Service  string `json:"service"`
}
