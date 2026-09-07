package models

import (
	"time"
)

// Status de um finding
type Status string

const (
	StatusPass    Status = "PASS"
	StatusFail    Status = "FAIL"
	StatusInfo    Status = "INFO"
	StatusManual  Status = "MANUAL"
)

// Finding representa um achado de segurança (estilo Prowler)
type Finding struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Severity        string    `json:"severity"`
	Status          Status    `json:"status"`
	StatusExtended  string    `json:"status_extended"`
	Provider        string    `json:"provider"`
	Service         string    `json:"service"`
	ResourceID      string    `json:"resource_id"`
	ResourceARN     string    `json:"resource_arn"`
	Region          string    `json:"region"`
	Remediation     string    `json:"remediation,omitempty"`
	RemediationURL  string    `json:"remediation_url,omitempty"`
	Benchmark       string    `json:"benchmark,omitempty"`
	Categories      []string  `json:"categories,omitempty"`
	FoundAt         time.Time `json:"found_at"`
}

// CheckMetadata define metadados de um check
type CheckMetadata struct {
	Provider         string   `json:"provider"`
	CheckID          string   `json:"check_id"`
	CheckTitle       string   `json:"check_title"`
	CheckType        []string `json:"check_type"`
	ServiceName      string   `json:"service_name"`
	SubServiceName   string   `json:"sub_service_name"`
	ResourceIdTemplate string `json:"resource_id_template"`
	Severity         string   `json:"severity"`
	ResourceType     string   `json:"resource_type"`
	ResourceGroup    string   `json:"resource_group"`
	Description      string   `json:"description"`
	Risk             string   `json:"risk"`
	RelatedURL       string   `json:"related_url"`
	RemediationText  string   `json:"remediation_text"`
	RemediationURL   string   `json:"remediation_url"`
	Categories       []string `json:"categories"`
	DependsOn        []string `json:"depends_on"`
	RelatedTo        []string `json:"related_to"`
	Notes            string   `json:"notes"`
}

// ScanResult agrupa os resultados de um scan
type ScanResult struct {
	Provider   string    `json:"provider"`
	Region     string    `json:"region"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Findings   []Finding `json:"findings"`
	Summary    Summary   `json:"summary"`
}

// Summary conta findings por severidade
type Summary struct {
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
	Total         int `json:"total"`
}
