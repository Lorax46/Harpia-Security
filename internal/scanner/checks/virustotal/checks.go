package virustotal

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type virustotalProvider interface {
	Virustotal(ctx context.Context) (interface{}, error)
}

// FileScanCheck - File scanning is enabled
type FileScanCheck struct {
	metadata models.CheckMetadata
}

func NewFileScanCheck() *FileScanCheck {
	return &FileScanCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_file_scan",
			CheckTitle:      "File scanning is enabled",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "File",
			Description:     "File scanning is enabled",
			RemediationText: "Review and remediate file scanning is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *FileScanCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *FileScanCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_file_scan
	_ = findings
	return findings, nil
}

// UrlScanCheck - URL scanning is enabled
type UrlScanCheck struct {
	metadata models.CheckMetadata
}

func NewUrlScanCheck() *UrlScanCheck {
	return &UrlScanCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_url_scan",
			CheckTitle:      "URL scanning is enabled",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "URL",
			Description:     "URL scanning is enabled",
			RemediationText: "Review and remediate url scanning is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *UrlScanCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UrlScanCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_url_scan
	_ = findings
	return findings, nil
}

// DomainScanCheck - Domain scanning is enabled
type DomainScanCheck struct {
	metadata models.CheckMetadata
}

func NewDomainScanCheck() *DomainScanCheck {
	return &DomainScanCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_domain_scan",
			CheckTitle:      "Domain scanning is enabled",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "Domain",
			Description:     "Domain scanning is enabled",
			RemediationText: "Review and remediate domain scanning is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *DomainScanCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DomainScanCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_domain_scan
	_ = findings
	return findings, nil
}

// IpScanCheck - IP scanning is enabled
type IpScanCheck struct {
	metadata models.CheckMetadata
}

func NewIpScanCheck() *IpScanCheck {
	return &IpScanCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_ip_scan",
			CheckTitle:      "IP scanning is enabled",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "IP",
			Description:     "IP scanning is enabled",
			RemediationText: "Review and remediate ip scanning is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *IpScanCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IpScanCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_ip_scan
	_ = findings
	return findings, nil
}

// HashScanCheck - Hash scanning is enabled
type HashScanCheck struct {
	metadata models.CheckMetadata
}

func NewHashScanCheck() *HashScanCheck {
	return &HashScanCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_hash_scan",
			CheckTitle:      "Hash scanning is enabled",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "Hash",
			Description:     "Hash scanning is enabled",
			RemediationText: "Review and remediate hash scanning is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *HashScanCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HashScanCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_hash_scan
	_ = findings
	return findings, nil
}

// ApiIntegrationCheck - VirusTotal API integration is configured
type ApiIntegrationCheck struct {
	metadata models.CheckMetadata
}

func NewApiIntegrationCheck() *ApiIntegrationCheck {
	return &ApiIntegrationCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_api_integration",
			CheckTitle:      "VirusTotal API integration is configured",
			ServiceName:     "virustotal",
			Severity:        "medium",
			ResourceType:    "Integration",
			Description:     "VirusTotal API integration is configured",
			RemediationText: "Review and remediate virustotal api integration is configured",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *ApiIntegrationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiIntegrationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_api_integration
	_ = findings
	return findings, nil
}

// ReputationCheckCheck - Reputation checks are performed
type ReputationCheckCheck struct {
	metadata models.CheckMetadata
}

func NewReputationCheckCheck() *ReputationCheckCheck {
	return &ReputationCheckCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_reputation_check",
			CheckTitle:      "Reputation checks are performed",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "Reputation",
			Description:     "Reputation checks are performed",
			RemediationText: "Review and remediate reputation checks are performed",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *ReputationCheckCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ReputationCheckCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_reputation_check
	_ = findings
	return findings, nil
}

// MalwareDetectionCheck - Malware detection is enabled
type MalwareDetectionCheck struct {
	metadata models.CheckMetadata
}

func NewMalwareDetectionCheck() *MalwareDetectionCheck {
	return &MalwareDetectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_malware_detection",
			CheckTitle:      "Malware detection is enabled",
			ServiceName:     "virustotal",
			Severity:        "critical",
			ResourceType:    "Malware",
			Description:     "Malware detection is enabled",
			RemediationText: "Review and remediate malware detection is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *MalwareDetectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MalwareDetectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_malware_detection
	_ = findings
	return findings, nil
}

// PhishingDetectionCheck - Phishing detection is enabled
type PhishingDetectionCheck struct {
	metadata models.CheckMetadata
}

func NewPhishingDetectionCheck() *PhishingDetectionCheck {
	return &PhishingDetectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_phishing_detection",
			CheckTitle:      "Phishing detection is enabled",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "Phishing",
			Description:     "Phishing detection is enabled",
			RemediationText: "Review and remediate phishing detection is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *PhishingDetectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PhishingDetectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_phishing_detection
	_ = findings
	return findings, nil
}

// IocFeedCheck - IOC feed is integrated
type IocFeedCheck struct {
	metadata models.CheckMetadata
}

func NewIocFeedCheck() *IocFeedCheck {
	return &IocFeedCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_ioc_feed",
			CheckTitle:      "IOC feed is integrated",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "IOC",
			Description:     "IOC feed is integrated",
			RemediationText: "Review and remediate ioc feed is integrated",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *IocFeedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IocFeedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_ioc_feed
	_ = findings
	return findings, nil
}

// YaraRulesCheck - YARA rules are configured
type YaraRulesCheck struct {
	metadata models.CheckMetadata
}

func NewYaraRulesCheck() *YaraRulesCheck {
	return &YaraRulesCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_yara_rules",
			CheckTitle:      "YARA rules are configured",
			ServiceName:     "virustotal",
			Severity:        "medium",
			ResourceType:    "YARA",
			Description:     "YARA rules are configured",
			RemediationText: "Review and remediate yara rules are configured",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *YaraRulesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *YaraRulesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_yara_rules
	_ = findings
	return findings, nil
}

// SigmaRulesCheck - Sigma rules are configured
type SigmaRulesCheck struct {
	metadata models.CheckMetadata
}

func NewSigmaRulesCheck() *SigmaRulesCheck {
	return &SigmaRulesCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_sigma_rules",
			CheckTitle:      "Sigma rules are configured",
			ServiceName:     "virustotal",
			Severity:        "medium",
			ResourceType:    "Sigma",
			Description:     "Sigma rules are configured",
			RemediationText: "Review and remediate sigma rules are configured",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *SigmaRulesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SigmaRulesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_sigma_rules
	_ = findings
	return findings, nil
}

// IntelligenceCheck - VirusTotal intelligence is integrated
type IntelligenceCheck struct {
	metadata models.CheckMetadata
}

func NewIntelligenceCheck() *IntelligenceCheck {
	return &IntelligenceCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_intelligence",
			CheckTitle:      "VirusTotal intelligence is integrated",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "Intelligence",
			Description:     "VirusTotal intelligence is integrated",
			RemediationText: "Review and remediate virustotal intelligence is integrated",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *IntelligenceCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IntelligenceCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_intelligence
	_ = findings
	return findings, nil
}

// RetrohuntCheck - Retrohunt is configured
type RetrohuntCheck struct {
	metadata models.CheckMetadata
}

func NewRetrohuntCheck() *RetrohuntCheck {
	return &RetrohuntCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_retrohunt",
			CheckTitle:      "Retrohunt is configured",
			ServiceName:     "virustotal",
			Severity:        "medium",
			ResourceType:    "Retrohunt",
			Description:     "Retrohunt is configured",
			RemediationText: "Review and remediate retrohunt is configured",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *RetrohuntCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RetrohuntCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_retrohunt
	_ = findings
	return findings, nil
}

// LivehuntCheck - Livehunt is configured
type LivehuntCheck struct {
	metadata models.CheckMetadata
}

func NewLivehuntCheck() *LivehuntCheck {
	return &LivehuntCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_livehunt",
			CheckTitle:      "Livehunt is configured",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "Livehunt",
			Description:     "Livehunt is configured",
			RemediationText: "Review and remediate livehunt is configured",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *LivehuntCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LivehuntCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_livehunt
	_ = findings
	return findings, nil
}

// NetworkTrafficCheck - Network traffic analysis is enabled
type NetworkTrafficCheck struct {
	metadata models.CheckMetadata
}

func NewNetworkTrafficCheck() *NetworkTrafficCheck {
	return &NetworkTrafficCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_network_traffic",
			CheckTitle:      "Network traffic analysis is enabled",
			ServiceName:     "virustotal",
			Severity:        "medium",
			ResourceType:    "Network",
			Description:     "Network traffic analysis is enabled",
			RemediationText: "Review and remediate network traffic analysis is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *NetworkTrafficCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkTrafficCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_network_traffic
	_ = findings
	return findings, nil
}

// BehaviorAnalysisCheck - Behavior analysis is enabled
type BehaviorAnalysisCheck struct {
	metadata models.CheckMetadata
}

func NewBehaviorAnalysisCheck() *BehaviorAnalysisCheck {
	return &BehaviorAnalysisCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_behavior_analysis",
			CheckTitle:      "Behavior analysis is enabled",
			ServiceName:     "virustotal",
			Severity:        "medium",
			ResourceType:    "Behavior",
			Description:     "Behavior analysis is enabled",
			RemediationText: "Review and remediate behavior analysis is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *BehaviorAnalysisCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BehaviorAnalysisCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_behavior_analysis
	_ = findings
	return findings, nil
}

// SandboxCheck - Sandbox analysis is enabled
type SandboxCheck struct {
	metadata models.CheckMetadata
}

func NewSandboxCheck() *SandboxCheck {
	return &SandboxCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_sandbox",
			CheckTitle:      "Sandbox analysis is enabled",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "Sandbox",
			Description:     "Sandbox analysis is enabled",
			RemediationText: "Review and remediate sandbox analysis is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *SandboxCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SandboxCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_sandbox
	_ = findings
	return findings, nil
}

// RelationshipsCheck - Relationship analysis is enabled
type RelationshipsCheck struct {
	metadata models.CheckMetadata
}

func NewRelationshipsCheck() *RelationshipsCheck {
	return &RelationshipsCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_relationships",
			CheckTitle:      "Relationship analysis is enabled",
			ServiceName:     "virustotal",
			Severity:        "low",
			ResourceType:    "Relationship",
			Description:     "Relationship analysis is enabled",
			RemediationText: "Review and remediate relationship analysis is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *RelationshipsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RelationshipsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_relationships
	_ = findings
	return findings, nil
}

// CommentsCheck - Community comments are monitored
type CommentsCheck struct {
	metadata models.CheckMetadata
}

func NewCommentsCheck() *CommentsCheck {
	return &CommentsCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_comments",
			CheckTitle:      "Community comments are monitored",
			ServiceName:     "virustotal",
			Severity:        "low",
			ResourceType:    "Comment",
			Description:     "Community comments are monitored",
			RemediationText: "Review and remediate community comments are monitored",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *CommentsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CommentsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_comments
	_ = findings
	return findings, nil
}

// VotesCheck - Community votes are monitored
type VotesCheck struct {
	metadata models.CheckMetadata
}

func NewVotesCheck() *VotesCheck {
	return &VotesCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_votes",
			CheckTitle:      "Community votes are monitored",
			ServiceName:     "virustotal",
			Severity:        "low",
			ResourceType:    "Vote",
			Description:     "Community votes are monitored",
			RemediationText: "Review and remediate community votes are monitored",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *VotesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *VotesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_votes
	_ = findings
	return findings, nil
}

// SigmaSearchCheck - Sigma rule search is enabled
type SigmaSearchCheck struct {
	metadata models.CheckMetadata
}

func NewSigmaSearchCheck() *SigmaSearchCheck {
	return &SigmaSearchCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_sigma_search",
			CheckTitle:      "Sigma rule search is enabled",
			ServiceName:     "virustotal",
			Severity:        "medium",
			ResourceType:    "SigmaSearch",
			Description:     "Sigma rule search is enabled",
			RemediationText: "Review and remediate sigma rule search is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *SigmaSearchCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SigmaSearchCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_sigma_search
	_ = findings
	return findings, nil
}

// HuntingCheck - Hunting notifications are configured
type HuntingCheck struct {
	metadata models.CheckMetadata
}

func NewHuntingCheck() *HuntingCheck {
	return &HuntingCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_hunting",
			CheckTitle:      "Hunting notifications are configured",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "Hunting",
			Description:     "Hunting notifications are configured",
			RemediationText: "Review and remediate hunting notifications are configured",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *HuntingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HuntingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_hunting
	_ = findings
	return findings, nil
}

// MonitorCheck - File monitoring is enabled
type MonitorCheck struct {
	metadata models.CheckMetadata
}

func NewMonitorCheck() *MonitorCheck {
	return &MonitorCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_monitor",
			CheckTitle:      "File monitoring is enabled",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "Monitor",
			Description:     "File monitoring is enabled",
			RemediationText: "Review and remediate file monitoring is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *MonitorCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_monitor
	_ = findings
	return findings, nil
}

// PrivateScanCheck - Private scanning is enabled
type PrivateScanCheck struct {
	metadata models.CheckMetadata
}

func NewPrivateScanCheck() *PrivateScanCheck {
	return &PrivateScanCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_private_scan",
			CheckTitle:      "Private scanning is enabled",
			ServiceName:     "virustotal",
			Severity:        "medium",
			ResourceType:    "PrivateScan",
			Description:     "Private scanning is enabled",
			RemediationText: "Review and remediate private scanning is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *PrivateScanCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PrivateScanCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_private_scan
	_ = findings
	return findings, nil
}

// PremiumApiCheck - Premium API is configured
type PremiumApiCheck struct {
	metadata models.CheckMetadata
}

func NewPremiumApiCheck() *PremiumApiCheck {
	return &PremiumApiCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_premium_api",
			CheckTitle:      "Premium API is configured",
			ServiceName:     "virustotal",
			Severity:        "low",
			ResourceType:    "Premium",
			Description:     "Premium API is configured",
			RemediationText: "Review and remediate premium api is configured",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *PremiumApiCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PremiumApiCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_premium_api
	_ = findings
	return findings, nil
}

// BulkScanCheck - Bulk scanning is enabled
type BulkScanCheck struct {
	metadata models.CheckMetadata
}

func NewBulkScanCheck() *BulkScanCheck {
	return &BulkScanCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_bulk_scan",
			CheckTitle:      "Bulk scanning is enabled",
			ServiceName:     "virustotal",
			Severity:        "medium",
			ResourceType:    "BulkScan",
			Description:     "Bulk scanning is enabled",
			RemediationText: "Review and remediate bulk scanning is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *BulkScanCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BulkScanCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_bulk_scan
	_ = findings
	return findings, nil
}

// CertificateScanCheck - Certificate scanning is enabled
type CertificateScanCheck struct {
	metadata models.CheckMetadata
}

func NewCertificateScanCheck() *CertificateScanCheck {
	return &CertificateScanCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_certificate_scan",
			CheckTitle:      "Certificate scanning is enabled",
			ServiceName:     "virustotal",
			Severity:        "high",
			ResourceType:    "Certificate",
			Description:     "Certificate scanning is enabled",
			RemediationText: "Review and remediate certificate scanning is enabled",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *CertificateScanCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CertificateScanCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_certificate_scan
	_ = findings
	return findings, nil
}

// ContactedDomainsCheck - Contacted domains are monitored
type ContactedDomainsCheck struct {
	metadata models.CheckMetadata
}

func NewContactedDomainsCheck() *ContactedDomainsCheck {
	return &ContactedDomainsCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_contacted_domains",
			CheckTitle:      "Contacted domains are monitored",
			ServiceName:     "virustotal",
			Severity:        "medium",
			ResourceType:    "Domain",
			Description:     "Contacted domains are monitored",
			RemediationText: "Review and remediate contacted domains are monitored",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *ContactedDomainsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContactedDomainsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_contacted_domains
	_ = findings
	return findings, nil
}

// ContactedIpsCheck - Contacted IPs are monitored
type ContactedIpsCheck struct {
	metadata models.CheckMetadata
}

func NewContactedIpsCheck() *ContactedIpsCheck {
	return &ContactedIpsCheck{
		metadata: models.CheckMetadata{
			Provider:        "virustotal",
			CheckID:         "virustotal_contacted_ips",
			CheckTitle:      "Contacted IPs are monitored",
			ServiceName:     "virustotal",
			Severity:        "medium",
			ResourceType:    "IP",
			Description:     "Contacted IPs are monitored",
			RemediationText: "Review and remediate contacted ips are monitored",
			Categories:      []string{"virustotal", "security"},
		},
	}
}

func (c *ContactedIpsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContactedIpsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(virustotalProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement virustotalProvider")
	}
	client, err := p.Virustotal(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement virustotal_contacted_ips
	_ = findings
	return findings, nil
}
