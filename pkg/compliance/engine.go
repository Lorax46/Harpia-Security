// Package compliance provides compliance framework mapping and reporting.
package compliance

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// Framework represents a compliance framework.
type Framework struct {
	ID          string
	Name        string
	Version     string
	Description string
	Categories  []string
}

// FrameworkMapping maps a check ID to compliance controls.
type FrameworkMapping struct {
	FrameworkID string
	ControlID   string
	Description string
	Severity    string
}

// ComplianceResult represents a compliance check result.
type ComplianceResult struct {
	Framework   Framework
	ControlID   string
	Description string
	Severity    string
	Status      models.Status
	Findings    []models.Finding
}

// ComplianceEngine runs compliance checks.
type ComplianceEngine struct {
	registry *Registry
}

// Registry holds all compliance framework definitions.
type Registry struct {
	Frameworks map[string]Framework
	Mappings   map[string][]FrameworkMapping
}

// NewEngine creates a new compliance engine.
func NewEngine() *ComplianceEngine {
	return &ComplianceEngine{
		registry: NewRegistry(),
	}
}

// NewRegistry creates a new compliance registry.
func NewRegistry() *Registry {
	r := &Registry{
		Frameworks: make(map[string]Framework),
		Mappings:   make(map[string][]FrameworkMapping),
	}
	r.registerFrameworks()
	r.registerMappings()
	return r
}

// registerFrameworks registers all supported compliance frameworks.
func (r *Registry) registerFrameworks() {
	r.Frameworks["cis_kubernetes_v1.6.0"] = Framework{
		ID:          "cis_kubernetes_v1.6.0",
		Name:        "CIS Kubernetes Benchmark",
		Version:     "v1.6.0",
		Description: "CIS Kubernetes Benchmark for securing Kubernetes clusters",
		Categories:  []string{"kubernetes", "cis", "benchmark"},
	}
	r.Frameworks["cis_aws_v1.5.0"] = Framework{
		ID:          "cis_aws_v1.5.0",
		Name:        "CIS AWS Foundations Benchmark",
		Version:     "v1.5.0",
		Description: "CIS AWS Foundations Benchmark for securing AWS accounts",
		Categories:  []string{"aws", "cis", "benchmark"},
	}
	r.Frameworks["cis_azure_v1.5.0"] = Framework{
		ID:          "cis_azure_v1.5.0",
		Name:        "CIS Azure Foundations Benchmark",
		Version:     "v1.5.0",
		Description: "CIS Azure Foundations Benchmark for securing Azure subscriptions",
		Categories:  []string{"azure", "cis", "benchmark"},
	}
	r.Frameworks["cis_gcp_v1.3.0"] = Framework{
		ID:          "cis_gcp_v1.3.0",
		Name:        "CIS GCP Foundations Benchmark",
		Version:     "v1.3.0",
		Description: "CIS GCP Foundations Benchmark for securing GCP projects",
		Categories:  []string{"gcp", "cis", "benchmark"},
	}
	r.Frameworks["soc2_type2"] = Framework{
		ID:          "soc2_type2",
		Name:        "SOC 2 Type II",
		Version:     "2017",
		Description: "SOC 2 Type II for service organizations",
		Categories:  []string{"soc2", "compliance", "audit"},
	}
	r.Frameworks["hipaa"] = Framework{
		ID:          "hipaa",
		Name:        "HIPAA",
		Version:     "2013",
		Description: "Health Insurance Portability and Accountability Act",
		Categories:  []string{"hipaa", "healthcare", "compliance"},
	}
	r.Frameworks["pci_dss_v4.0"] = Framework{
		ID:          "pci_dss_v4.0",
		Name:        "PCI DSS",
		Version:     "v4.0",
		Description: "Payment Card Industry Data Security Standard",
		Categories:  []string{"pci", "payment", "compliance"},
	}
	r.Frameworks["nist_800_53_rev5"] = Framework{
		ID:          "nist_800_53_rev5",
		Name:        "NIST SP 800-53",
		Version:     "Rev 5",
		Description: "Security and Privacy Controls for Information Systems",
		Categories:  []string{"nist", "federal", "compliance"},
	}
	r.Frameworks["iso_27001_2022"] = Framework{
		ID:          "iso_27001_2022",
		Name:        "ISO 27001",
		Version:     "2022",
		Description: "Information Security Management Systems",
		Categories:  []string{"iso", "international", "compliance"},
	}
	r.Frameworks["gdpr"] = Framework{
		ID:          "gdpr",
		Name:        "GDPR",
		Version:     "2018",
		Description: "General Data Protection Regulation",
		Categories:  []string{"gdpr", "privacy", "eu"},
	}
	r.Frameworks["fedramp_moderate"] = Framework{
		ID:          "fedramp_moderate",
		Name:        "FedRAMP",
		Version:     "Moderate",
		Description: "Federal Risk and Authorization Management Program",
		Categories:  []string{"fedramp", "federal", "cloud"},
	}
	r.Frameworks["cisa_kev"] = Framework{
		ID:          "cisa_kev",
		Name:        "CISA KEV",
		Version:     "2024",
		Description: "Known Exploited Vulnerabilities Catalog",
		Categories:  []string{"cisa", "vulnerabilities", "federal"},
	}
	r.Frameworks["mitre_attack"] = Framework{
		ID:          "mitre_attack",
		Name:        "MITRE ATT&CK",
		Version:     "v14.0",
		Description: "Adversarial Tactics, Techniques, and Common Knowledge",
		Categories:  []string{"mitre", "threat-modeling", "security"},
	}
}

// registerMappings registers check-to-framework mappings.
func (r *Registry) registerMappings() {
	// CIS Kubernetes mappings
	r.Mappings["kubernetes_cis_benchmark"] = []FrameworkMapping{
		{FrameworkID: "cis_kubernetes_v1.6.0", ControlID: "CIS-1.1", Description: "Master Node Configuration Files", Severity: "medium"},
		{FrameworkID: "cis_kubernetes_v1.6.0", ControlID: "CIS-1.2", Description: "API Server", Severity: "high"},
		{FrameworkID: "cis_kubernetes_v1.6.0", ControlID: "CIS-1.3", Description: "Controller Manager", Severity: "medium"},
		{FrameworkID: "cis_kubernetes_v1.6.0", ControlID: "CIS-1.4", Description: "Scheduler", Severity: "low"},
		{FrameworkID: "cis_kubernetes_v1.6.0", ControlID: "CIS-2", Description: "etcd", Severity: "high"},
		{FrameworkID: "cis_kubernetes_v1.6.0", ControlID: "CIS-3", Description: "Control Plane Configuration", Severity: "medium"},
		{FrameworkID: "cis_kubernetes_v1.6.0", ControlID: "CIS-4", Description: "Worker Nodes", Severity: "high"},
		{FrameworkID: "cis_kubernetes_v1.6.0", ControlID: "CIS-5", Description: "Policies", Severity: "high"},
	}

	// SOC 2 mappings
	r.Mappings["iam_user_mfa_enabled"] = []FrameworkMapping{
		{FrameworkID: "soc2_type2", ControlID: "CC6.1", Description: "Logical and Physical Access Controls", Severity: "high"},
		{FrameworkID: "soc2_type2", ControlID: "CC6.2", Description: "User Authentication", Severity: "high"},
	}
	r.Mappings["iam_password_policy_minimum_length_14"] = []FrameworkMapping{
		{FrameworkID: "soc2_type2", ControlID: "CC6.1", Description: "Logical and Physical Access Controls", Severity: "high"},
	}
	r.Mappings["cloudtrail_multi_region_enabled"] = []FrameworkMapping{
		{FrameworkID: "soc2_type2", ControlID: "CC6.6", Description: "Monitoring Activities", Severity: "high"},
		{FrameworkID: "soc2_type2", ControlID: "CC7.2", Description: "System Monitoring", Severity: "high"},
	}
	r.Mappings["s3_bucket_encryption"] = []FrameworkMapping{
		{FrameworkID: "soc2_type2", ControlID: "CC6.7", Description: "Data Encryption", Severity: "high"},
	}

	// HIPAA mappings
	r.Mappings["iam_user_mfa_enabled"] = append(r.Mappings["iam_user_mfa_enabled"], []FrameworkMapping{
		{FrameworkID: "hipaa", ControlID: "164.312(d)", Description: "Person or Entity Authentication", Severity: "high"},
	}...)
	r.Mappings["s3_bucket_encryption"] = append(r.Mappings["s3_bucket_encryption"], []FrameworkMapping{
		{FrameworkID: "hipaa", ControlID: "164.312(a)(2)(iv)", Description: "Encryption and Decryption", Severity: "high"},
		{FrameworkID: "hipaa", ControlID: "164.312(e)(2)(ii)", Description: "Encryption in Transit", Severity: "high"},
	}...)
	r.Mappings["cloudtrail_multi_region_enabled"] = append(r.Mappings["cloudtrail_multi_region_enabled"], []FrameworkMapping{
		{FrameworkID: "hipaa", ControlID: "164.312(b)", Description: "Audit Controls", Severity: "high"},
	}...)
	r.Mappings["rds_instance_storage_encrypted"] = []FrameworkMapping{
		{FrameworkID: "hipaa", ControlID: "164.312(a)(2)(iv)", Description: "Encryption and Decryption", Severity: "high"},
		{FrameworkID: "hipaa", ControlID: "164.312(e)(2)(ii)", Description: "Encryption in Transit", Severity: "high"},
	}

	// PCI DSS mappings
	r.Mappings["iam_user_mfa_enabled"] = append(r.Mappings["iam_user_mfa_enabled"], []FrameworkMapping{
		{FrameworkID: "pci_dss_v4.0", ControlID: "8.3", Description: "Multi-factor Authentication", Severity: "critical"},
	}...)
	r.Mappings["iam_password_policy_minimum_length_14"] = append(r.Mappings["iam_password_policy_minimum_length_14"], []FrameworkMapping{
		{FrameworkID: "pci_dss_v4.0", ControlID: "8.2.3", Description: "Password Complexity", Severity: "high"},
	}...)
	r.Mappings["s3_bucket_encryption"] = append(r.Mappings["s3_bucket_encryption"], []FrameworkMapping{
		{FrameworkID: "pci_dss_v4.0", ControlID: "3.4", Description: "Render PAN Unreadable", Severity: "critical"},
	}...)
	r.Mappings["cloudtrail_multi_region_enabled"] = append(r.Mappings["cloudtrail_multi_region_enabled"], []FrameworkMapping{
		{FrameworkID: "pci_dss_v4.0", ControlID: "10.2", Description: "Audit Trail", Severity: "high"},
	}...)
	r.Mappings["vpc_flow_logs_enabled"] = []FrameworkMapping{
		{FrameworkID: "pci_dss_v4.0", ControlID: "10.2", Description: "Audit Trail", Severity: "high"},
		{FrameworkID: "pci_dss_v4.0", ControlID: "10.3", Description: "Audit Trail Content", Severity: "high"},
	}
	r.Mappings["securityhub_enabled"] = []FrameworkMapping{
		{FrameworkID: "pci_dss_v4.0", ControlID: "11.4", Description: "Intrusion Detection/Prevention", Severity: "high"},
	}

	// NIST 800-53 mappings
	r.Mappings["iam_user_mfa_enabled"] = append(r.Mappings["iam_user_mfa_enabled"], []FrameworkMapping{
		{FrameworkID: "nist_800_53_rev5", ControlID: "IA-2", Description: "Identification and Authentication", Severity: "high"},
		{FrameworkID: "nist_800_53_rev5", ControlID: "IA-5", Description: "Authenticator Management", Severity: "high"},
	}...)
	r.Mappings["cloudtrail_multi_region_enabled"] = append(r.Mappings["cloudtrail_multi_region_enabled"], []FrameworkMapping{
		{FrameworkID: "nist_800_53_rev5", ControlID: "AU-2", Description: "Event Logging", Severity: "high"},
		{FrameworkID: "nist_800_53_rev5", ControlID: "AU-3", Description: "Content of Audit Records", Severity: "high"},
		{FrameworkID: "nist_800_53_rev5", ControlID: "AU-6", Description: "Audit Review", Severity: "high"},
	}...)
	r.Mappings["s3_bucket_encryption"] = append(r.Mappings["s3_bucket_encryption"], []FrameworkMapping{
		{FrameworkID: "nist_800_53_rev5", ControlID: "SC-28", Description: "Protection of Information at Rest", Severity: "high"},
	}...)
	r.Mappings["vpc_flow_logs_enabled"] = append(r.Mappings["vpc_flow_logs_enabled"], []FrameworkMapping{
		{FrameworkID: "nist_800_53_rev5", ControlID: "AU-2", Description: "Event Logging", Severity: "high"},
	}...)

	// ISO 27001 mappings
	r.Mappings["iam_user_mfa_enabled"] = append(r.Mappings["iam_user_mfa_enabled"], []FrameworkMapping{
		{FrameworkID: "iso_27001_2022", ControlID: "A.9.4.2", Description: "Secure Log-on Procedures", Severity: "high"},
	}...)
	r.Mappings["cloudtrail_multi_region_enabled"] = append(r.Mappings["cloudtrail_multi_region_enabled"], []FrameworkMapping{
		{FrameworkID: "iso_27001_2022", ControlID: "A.8.15", Description: "Logging", Severity: "high"},
	}...)
	r.Mappings["s3_bucket_encryption"] = append(r.Mappings["s3_bucket_encryption"], []FrameworkMapping{
		{FrameworkID: "iso_27001_2022", ControlID: "A.8.24", Description: "Use of Cryptography", Severity: "high"},
	}...)

	// GDPR mappings
	r.Mappings["s3_bucket_encryption"] = append(r.Mappings["s3_bucket_encryption"], []FrameworkMapping{
		{FrameworkID: "gdpr", ControlID: "Art. 32", Description: "Security of Processing", Severity: "high"},
	}...)
	r.Mappings["cloudtrail_multi_region_enabled"] = append(r.Mappings["cloudtrail_multi_region_enabled"], []FrameworkMapping{
		{FrameworkID: "gdpr", ControlID: "Art. 30", Description: "Records of Processing Activities", Severity: "high"},
	}...)
	r.Mappings["iam_user_mfa_enabled"] = append(r.Mappings["iam_user_mfa_enabled"], []FrameworkMapping{
		{FrameworkID: "gdpr", ControlID: "Art. 32", Description: "Security of Processing", Severity: "high"},
	}...)

	// FedRAMP mappings
	r.Mappings["iam_user_mfa_enabled"] = append(r.Mappings["iam_user_mfa_enabled"], []FrameworkMapping{
		{FrameworkID: "fedramp_moderate", ControlID: "IA-2", Description: "Identification and Authentication", Severity: "high"},
	}...)
	r.Mappings["cloudtrail_multi_region_enabled"] = append(r.Mappings["cloudtrail_multi_region_enabled"], []FrameworkMapping{
		{FrameworkID: "fedramp_moderate", ControlID: "AU-2", Description: "Audit Events", Severity: "high"},
	}...)
	r.Mappings["s3_bucket_encryption"] = append(r.Mappings["s3_bucket_encryption"], []FrameworkMapping{
		{FrameworkID: "fedramp_moderate", ControlID: "SC-28", Description: "Protection of Information at Rest", Severity: "high"},
	}...)

	// CISA KEV mappings
	r.Mappings["image_vulnerability_scan"] = []FrameworkMapping{
		{FrameworkID: "cisa_kev", ControlID: "CVE-2024", Description: "Known Exploited Vulnerabilities", Severity: "critical"},
	}
	r.Mappings["container_privileged"] = []FrameworkMapping{
		{FrameworkID: "cisa_kev", ControlID: "Misconfig", Description: "Container Misconfiguration", Severity: "high"},
	}

	// MITRE ATT&CK mappings
	r.Mappings["iam_user_mfa_enabled"] = append(r.Mappings["iam_user_mfa_enabled"], []FrameworkMapping{
		{FrameworkID: "mitre_attack", ControlID: "T1078", Description: "Valid Accounts", Severity: "high"},
		{FrameworkID: "mitre_attack", ControlID: "T1110", Description: "Brute Force", Severity: "high"},
	}...)
	r.Mappings["cloudtrail_multi_region_enabled"] = append(r.Mappings["cloudtrail_multi_region_enabled"], []FrameworkMapping{
		{FrameworkID: "mitre_attack", ControlID: "T1562", Description: "Impair Defenses", Severity: "high"},
	}...)
	r.Mappings["s3_bucket_encryption"] = append(r.Mappings["s3_bucket_encryption"], []FrameworkMapping{
		{FrameworkID: "mitre_attack", ControlID: "T1530", Description: "Data from Cloud Storage", Severity: "high"},
	}...)
	r.Mappings["vpc_flow_logs_enabled"] = append(r.Mappings["vpc_flow_logs_enabled"], []FrameworkMapping{
		{FrameworkID: "mitre_attack", ControlID: "T1046", Description: "Network Service Discovery", Severity: "medium"},
	}...)
	r.Mappings["container_privileged"] = append(r.Mappings["container_privileged"], []FrameworkMapping{
		{FrameworkID: "mitre_attack", ControlID: "T1610", Description: "Deploy Container", Severity: "high"},
	}...)
	r.Mappings["kubernetes_cis_benchmark"] = append(r.Mappings["kubernetes_cis_benchmark"], []FrameworkMapping{
		{FrameworkID: "mitre_attack", ControlID: "T1526", Description: "Cloud Service Discovery", Severity: "medium"},
	}...)
}

// GetFrameworks returns all registered frameworks.
func (r *Registry) GetFrameworks() []Framework {
	frameworks := make([]Framework, 0, len(r.Frameworks))
	for _, f := range r.Frameworks {
		frameworks = append(frameworks, f)
	}
	return frameworks
}

// GetMappings returns mappings for a check ID.
func (r *Registry) GetMappings(checkID string) []FrameworkMapping {
	return r.Mappings[checkID]
}

// GetFramework returns a framework by ID.
func (r *Registry) GetFramework(id string) (Framework, bool) {
	f, ok := r.Frameworks[id]
	return f, ok
}

// RunCompliance runs compliance checks for a specific framework.
func (e *ComplianceEngine) RunCompliance(ctx context.Context, frameworkID string, findings []models.Finding) ([]ComplianceResult, error) {
	framework, ok := e.registry.GetFramework(frameworkID)
	if !ok {
		return nil, fmt.Errorf("framework %s not found", frameworkID)
	}

	results := []ComplianceResult{}

	// Group findings by control
	controlFindings := make(map[string][]models.Finding)
	for _, f := range findings {
		mappings := e.registry.GetMappings(f.ID)
		for _, m := range mappings {
			if m.FrameworkID == frameworkID {
				controlFindings[m.ControlID] = append(controlFindings[m.ControlID], f)
			}
		}
	}

	// Create results for each control
	for controlID, finds := range controlFindings {
		status := models.StatusPass
		for _, f := range finds {
			if f.Status == models.StatusFail {
				status = models.StatusFail
				break
			}
		}

		results = append(results, ComplianceResult{
			Framework:   framework,
			ControlID:   controlID,
			Description: getControlDescription(frameworkID, controlID),
			Severity:    getControlSeverity(frameworkID, controlID),
			Status:      status,
			Findings:    finds,
		})
	}

	return results, nil
}

// RunAllFrameworks runs compliance checks against all frameworks.
func (e *ComplianceEngine) RunAllFrameworks(ctx context.Context, findings []models.Finding) (map[string][]ComplianceResult, error) {
	allResults := make(map[string][]ComplianceResult)

	for _, framework := range e.registry.GetFrameworks() {
		results, err := e.RunCompliance(ctx, framework.ID, findings)
		if err != nil {
			continue
		}
		allResults[framework.ID] = results
	}

	return allResults, nil
}

// GenerateReport generates a compliance report.
func (e *ComplianceEngine) GenerateReport(results []ComplianceResult) ComplianceReport {
	report := ComplianceReport{
		GeneratedAt: time.Now().UTC(),
		Framework:   results[0].Framework,
		Total:       len(results),
		Passed:      0,
		Failed:      0,
		Manual:      0,
		Results:     results,
	}

	for _, r := range results {
		switch r.Status {
		case models.StatusPass:
			report.Passed++
		case models.StatusFail:
			report.Failed++
		case models.StatusManual:
			report.Manual++
		}
	}

	return report
}

// ComplianceReport represents a compliance report.
type ComplianceReport struct {
	GeneratedAt time.Time
	Framework   Framework
	Total       int
	Passed      int
	Failed      int
	Manual      int
	Results     []ComplianceResult
}

// PassRate returns the pass rate as a percentage.
func (r ComplianceReport) PassRate() float64 {
	if r.Total == 0 {
		return 0
	}
	return float64(r.Passed) / float64(r.Total) * 100
}

func getControlDescription(frameworkID, controlID string) string {
	descriptions := map[string]map[string]string{
		"soc2_type2": {
			"CC6.1": "Logical and Physical Access Controls",
			"CC6.2": "User Authentication",
			"CC6.6": "Monitoring Activities",
			"CC6.7": "Data Encryption",
			"CC7.2": "System Monitoring",
		},
		"hipaa": {
			"164.312(d)":  "Person or Entity Authentication",
			"164.312(a)(2)(iv)": "Encryption and Decryption",
			"164.312(e)(2)(ii)": "Encryption in Transit",
			"164.312(b)":  "Audit Controls",
		},
		"pci_dss_v4.0": {
			"8.3":  "Multi-factor Authentication",
			"8.2.3": "Password Complexity",
			"3.4":  "Render PAN Unreadable",
			"10.2": "Audit Trail",
			"10.3": "Audit Trail Content",
			"11.4": "Intrusion Detection/Prevention",
		},
		"nist_800_53_rev5": {
			"IA-2":   "Identification and Authentication",
			"IA-5":   "Authenticator Management",
			"AU-2":   "Event Logging",
			"AU-3":   "Content of Audit Records",
			"AU-6":   "Audit Review",
			"SC-28":  "Protection of Information at Rest",
		},
		"iso_27001_2022": {
			"A.9.4.2": "Secure Log-on Procedures",
			"A.8.15":  "Logging",
			"A.8.24":  "Use of Cryptography",
		},
		"gdpr": {
			"Art. 32": "Security of Processing",
			"Art. 30": "Records of Processing Activities",
		},
		"fedramp_moderate": {
			"IA-2":  "Identification and Authentication",
			"AU-2":  "Audit Events",
			"SC-28": "Protection of Information at Rest",
		},
		"mitre_attack": {
			"T1078":  "Valid Accounts",
			"T1110":  "Brute Force",
			"T1562":  "Impair Defenses",
			"T1530":  "Data from Cloud Storage",
			"T1046":  "Network Service Discovery",
			"T1610":  "Deploy Container",
			"T1526":  "Cloud Service Discovery",
		},
	}

	if fw, ok := descriptions[frameworkID]; ok {
		if desc, ok := fw[controlID]; ok {
			return desc
		}
	}
	return "Unknown Control"
}

func getControlSeverity(frameworkID, controlID string) string {
	severities := map[string]map[string]string{
		"soc2_type2": {
			"CC6.1": "high", "CC6.2": "high", "CC6.6": "high", "CC6.7": "high", "CC7.2": "high",
		},
		"hipaa": {
			"164.312(d)": "high", "164.312(a)(2)(iv)": "high", "164.312(e)(2)(ii)": "high", "164.312(b)": "high",
		},
		"pci_dss_v4.0": {
			"8.3": "critical", "8.2.3": "high", "3.4": "critical", "10.2": "high", "10.3": "high", "11.4": "high",
		},
		"nist_800_53_rev5": {
			"IA-2": "high", "IA-5": "high", "AU-2": "high", "AU-3": "high", "AU-6": "high", "SC-28": "high",
		},
		"iso_27001_2022": {
			"A.9.4.2": "high", "A.8.15": "high", "A.8.24": "high",
		},
		"gdpr": {
			"Art. 32": "high", "Art. 30": "high",
		},
		"fedramp_moderate": {
			"IA-2": "high", "AU-2": "high", "SC-28": "high",
		},
		"mitre_attack": {
			"T1078": "high", "T1110": "high", "T1562": "high", "T1530": "high", "T1046": "medium", "T1610": "high", "T1526": "medium",
		},
	}

	if fw, ok := severities[frameworkID]; ok {
		if sev, ok := fw[controlID]; ok {
			return sev
		}
	}
	return "medium"
}
