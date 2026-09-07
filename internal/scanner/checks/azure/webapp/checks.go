package webapp

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type webAppProvider interface {
	WebAppsClient(ctx context.Context) (*armappservice.WebAppsClient, error)
}

// ==================== HTTPS Only ====================

type HTTPSOnlyCheck struct {
	metadata models.CheckMetadata
}

func NewHTTPSOnlyCheck() *HTTPSOnlyCheck {
	return &HTTPSOnlyCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "webapp_https_only",
			CheckTitle:      "Web Apps should have HTTPS Only enabled",
			ServiceName:     "webapp",
			Severity:        "critical",
			ResourceType:    "WebApp",
			ResourceGroup:   "AppService",
			Description:     "Web Apps should have HTTPS Only enabled to encrypt all traffic",
			Risk:            "Without HTTPS, data can be intercepted",
			RemediationText: "Enable HTTPS Only on Web Apps",
			Categories:      []string{"webapp", "network"},
		},
	}
}

func (c *HTTPSOnlyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HTTPSOnlyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(webAppProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa webAppProvider")
	}

	client, err := p.WebAppsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar web apps: %w", err)
		}
		for _, app := range page.Value {
			if app == nil || app.Name == nil {
				continue
			}
			httpsOnly := app.Properties != nil && app.Properties.HTTPSOnly != nil && *app.Properties.HTTPSOnly
			status := models.StatusFail
			ext := fmt.Sprintf("Web App %s does not have HTTPS Only enabled", *app.Name)
			if httpsOnly {
				status = models.StatusPass
				ext = fmt.Sprintf("Web App %s has HTTPS Only enabled", *app.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "webapp",
				ResourceID:      *app.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== Minimum TLS Version ====================

type MinimumTLSVersionCheck struct {
	metadata models.CheckMetadata
}

func NewMinimumTLSVersionCheck() *MinimumTLSVersionCheck {
	return &MinimumTLSVersionCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "webapp_minimum_tls_version",
			CheckTitle:      "Web Apps should use TLS 1.2 minimum",
			ServiceName:     "webapp",
			Severity:        "high",
			ResourceType:    "WebApp",
			ResourceGroup:   "AppService",
			Description:     "Web Apps should use TLS 1.2 as minimum version",
			Risk:            "Older TLS versions are vulnerable to known attacks",
			RemediationText: "Set minimum TLS version to 1.2 on Web Apps",
			Categories:      []string{"webapp", "network"},
		},
	}
}

func (c *MinimumTLSVersionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MinimumTLSVersionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(webAppProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa webAppProvider")
	}

	client, err := p.WebAppsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar web apps: %w", err)
		}
		for _, app := range page.Value {
			if app == nil || app.Name == nil {
				continue
			}
			tlsOK := app.Properties != nil && app.Properties.SiteConfig != nil && app.Properties.SiteConfig.MinTLSVersion != nil && *app.Properties.SiteConfig.MinTLSVersion == "1.2"
			status := models.StatusFail
			ext := fmt.Sprintf("Web App %s does not require TLS 1.2", *app.Name)
			if tlsOK {
				status = models.StatusPass
				ext = fmt.Sprintf("Web App %s requires TLS 1.2", *app.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "webapp",
				ResourceID:      *app.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== FTP Disabled ====================

type FTPDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewFTPDisabledCheck() *FTPDisabledCheck {
	return &FTPDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "webapp_ftp_disabled",
			CheckTitle:      "Web Apps should have FTP/SCM access restricted",
			ServiceName:     "webapp",
			Severity:        "medium",
			ResourceType:    "WebApp",
			ResourceGroup:   "AppService",
			Description:     "Web Apps should have FTP access disabled to reduce attack surface",
			Risk:            "FTP allows file uploads that could be exploited",
			RemediationText: "Disable FTP state on Web Apps (set to 'Disabled')",
			Categories:      []string{"webapp", "network"},
		},
	}
}

func (c *FTPDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *FTPDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(webAppProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa webAppProvider")
	}

	client, err := p.WebAppsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar web apps: %w", err)
		}
		for _, app := range page.Value {
			if app == nil || app.Name == nil {
				continue
			}
			ftpDisabled := app.Properties != nil && app.Properties.SiteConfig != nil && app.Properties.SiteConfig.FtpsState != nil && *app.Properties.SiteConfig.FtpsState == "Disabled"
			status := models.StatusFail
			ext := fmt.Sprintf("Web App %s has FTP enabled", *app.Name)
			if ftpDisabled {
				status = models.StatusPass
				ext = fmt.Sprintf("Web App %s has FTP disabled", *app.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "webapp",
				ResourceID:      *app.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}
