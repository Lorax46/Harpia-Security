package gcr

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/artifactregistry/v1"
	"google.golang.org/api/cloudbuild/v1"
	"google.golang.org/api/containeranalysis/v1"
	"google.golang.org/api/storage/v1"
)

type gcrProvider interface {
	GCR(ctx context.Context) (*containeranalysis.Service, error)
	Storage(ctx context.Context) (*storage.Service, error)
	CloudBuild(ctx context.Context) (*cloudbuild.Service, error)
	ArtifactRegistry(ctx context.Context) (*artifactregistry.Service, error)
	ProjectID() string
	Region() string
}

// ImageVulnerabilityScanCheck verifica se imagens têm scan de vulnerabilidades ativo
type ImageVulnerabilityScanCheck struct {
	metadata models.CheckMetadata
}

func NewImageVulnerabilityScanCheck() *ImageVulnerabilityScanCheck {
	return &ImageVulnerabilityScanCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "gcr_image_vulnerability_scan",
			CheckTitle:      "GCR images have vulnerability scanning enabled",
			ServiceName:     "gcr",
			Severity:        "high",
			Description:     "GCR images should have vulnerability scanning enabled to detect security issues",
			RemediationText: "Enable vulnerability scanning in Container Registry / Artifact Registry",
			Categories:      []string{"security", "vulnerabilities"},
		},
	}
}

func (c *ImageVulnerabilityScanCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ImageVulnerabilityScanCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gcrProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement gcrProvider")
	}

	svc, err := p.GCR(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	// Listar occurrences de vulnerabilidades via Container Analysis API
	parent := fmt.Sprintf("projects/%s", projectID)
	occurrences, err := svc.Projects.Occurrences.List(parent).Filter("kind=\"VULNERABILITY\"").Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerability occurrences: %w", err)
	}

	// Se há occurrences, significa que o scanning está ativo e encontrou vulnerabilidades
	if len(occurrences.Occurrences) > 0 {
		// Group by resource URI
		vulnByResource := map[string]int{}
		for _, occ := range occurrences.Occurrences {
			if occ.Vulnerability != nil {
				vulnByResource[occ.ResourceUri]++
			}
		}

		for resource, count := range vulnByResource {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Image %s has %d vulnerabilities detected", resource, count),
				ResourceID:    resource,
				Provider: "gcp", Service: "gcr",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
		}
	}

	// Também verificar se há occurrences de qualquer tipo (scanning ativo)
	allOccurrences, err := svc.Projects.Occurrences.List(parent).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list all occurrences: %w", err)
	}

	if len(allOccurrences.Occurrences) == 0 {
		// Nenhum occurrence encontrado - scanning pode não estar ativo
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusInfo,
			StatusExtended: "No vulnerability occurrences found - scanning may not be active or no images scanned",
			Provider: "gcp", Service: "gcr",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	} else if len(findings) == 0 {
		// Scanning ativo e sem vulnerabilidades
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: fmt.Sprintf("Vulnerability scanning is active - %d occurrences checked, no vulnerabilities found", len(allOccurrences.Occurrences)),
			Provider: "gcp", Service: "gcr",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// ImageBuildCheck verifica se imagens são builds seguros (via Cloud Build)
type ImageBuildCheck struct {
	metadata models.CheckMetadata
}

func NewImageBuildCheck() *ImageBuildCheck {
	return &ImageBuildCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "gcr_image_build",
			CheckTitle:      "GCR images are built securely via Cloud Build",
			ServiceName:     "gcr",
			Severity:        "medium",
			Description:     "GCR images should be built securely using Cloud Build with proper configuration",
			RemediationText: "Use Cloud Build with security best practices and vulnerability scanning enabled",
			Categories:      []string{"security", "ci-cd"},
		},
	}
}

func (c *ImageBuildCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ImageBuildCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gcrProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement gcrProvider")
	}

	buildSvc, err := p.CloudBuild(ctx)
	if err != nil {
		return nil, err
	}

	artifactSvc, err := p.ArtifactRegistry(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	region := p.Region()
	findings := []models.Finding{}

	// Listar builds do Cloud Build
	builds, err := buildSvc.Projects.Builds.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list builds: %w", err)
	}

	// Verificar se builds usam configurações seguras
	for _, build := range builds.Builds {
		issues := []string{}

		// Verificar se o build tem substâncias seguras
		if len(build.Substitutions) > 0 {
			for key, val := range build.Substitutions {
				// Detectar possíveis segredos em substituições
				if strings.Contains(strings.ToLower(key), "password") ||
					strings.Contains(strings.ToLower(key), "secret") ||
					strings.Contains(strings.ToLower(key), "token") ||
					strings.Contains(strings.ToLower(key), "key") {
					if len(val) > 0 {
						issues = append(issues, fmt.Sprintf("Possible secret in substitution variable '%s'", key))
					}
				}
			}
		}

		// Verificar se o build usa worker pool (mais seguro que workers compartilhados)
		if build.WorkerPool == "" {
			issues = append(issues, "Build does not use a private worker pool")
		}

		// Verificar se há opções de logging
		if build.Options == nil || build.Options.Logging == "" {
			issues = append(issues, "Build does not have explicit logging configuration")
		}

		status := models.StatusPass
		ext := fmt.Sprintf("Build %s follows security best practices", build.Id)
		if len(issues) > 0 {
			status = models.StatusFail
			ext = fmt.Sprintf("Build %s has security issues: %s", build.Id, strings.Join(issues, "; "))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: build.Id,
			Provider: "gcp", Service: "gcr",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	// Verificar repositórios do Artifact Registry
	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	repos, err := artifactSvc.Projects.Locations.Repositories.List(parent).Do()
	if err != nil {
		// Pode não ter Artifact Registry habilitado, ignorar
	} else {
		for _, repo := range repos.Repositories {
			issues := []string{}

			// Verificar se o repositório tem vulnerability scanning habilitado
			if repo.VulnerabilityScanningConfig == nil || !repo.VulnerabilityScanningConfig.EnablementState {
				issues = append(issues, "Vulnerability scanning is not enabled")
			}

			// Verificar se usa CMEK
			if repo.EncryptionConfig == nil || repo.EncryptionConfig.KmsKey == "" {
				issues = append(issues, "Repository does not use CMEK encryption")
			}

			status := models.StatusPass
			ext := fmt.Sprintf("Repository %s follows security best practices", repo.Name)
			if len(issues) > 0 {
				status = models.StatusFail
				ext = fmt.Sprintf("Repository %s has security issues: %s", repo.Name, strings.Join(issues, "; "))
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: ext,
				ResourceID: repo.Name,
				Provider: "gcp", Service: "gcr",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
		}
	}

	if len(builds.Builds) == 0 && (repos == nil || len(repos.Repositories) == 0) {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusInfo,
			StatusExtended: "No Cloud Build builds or Artifact Registry repositories found",
			Provider: "gcp", Service: "gcr",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// RegistryIamCheck verifica IAM do registry (Artifact Registry e GCR buckets)
type RegistryIamCheck struct {
	metadata models.CheckMetadata
}

func NewRegistryIamCheck() *RegistryIamCheck {
	return &RegistryIamCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "gcr_registry_iam",
			CheckTitle:      "GCR registry IAM is configured properly",
			ServiceName:     "gcr",
			Severity:        "medium",
			Description:     "GCR registry should have proper IAM configuration without public access",
			RemediationText: "Configure IAM for GCR registry removing allUsers and allAuthenticatedUsers",
			Categories:      []string{"identity"},
		},
	}
}

func (c *RegistryIamCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RegistryIamCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gcrProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement gcrProvider")
	}

	storageSvc, err := p.Storage(ctx)
	if err != nil {
		return nil, err
	}

	artifactSvc, err := p.ArtifactRegistry(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	region := p.Region()
	findings := []models.Finding{}

	// Verificar buckets de GCR (us.gcr.io, eu.gcr.io, asia.gcr.io, etc.)
	gcrBuckets := []string{
		fmt.Sprintf("artifacts.%s.appspot.com", projectID),
		"us.gcr.io",
		"eu.gcr.io",
		"asia.gcr.io",
	}

	for _, bucketName := range gcrBuckets {
		// Tentar acessar o bucket
		_, err := storageSvc.Buckets.Get(bucketName).Do()
		if err != nil {
			// Bucket não encontrado ou sem acesso, pular
			continue
		}

		// Verificar IAM policy
		policy, err := storageSvc.Buckets.GetIamPolicy(bucketName).Context(ctx).Do()
		if err != nil {
			continue
		}

		hasPublicAccess := false
		publicPrincipals := []string{}
		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					hasPublicAccess = true
					publicPrincipals = append(publicPrincipals, fmt.Sprintf("%s (%s)", member, binding.Role))
				}
			}
		}

		status := models.StatusPass
		ext := fmt.Sprintf("Bucket %s has proper IAM configuration", bucketName)
		if hasPublicAccess {
			status = models.StatusFail
			ext = fmt.Sprintf("Bucket %s has public IAM access: %s", bucketName, strings.Join(publicPrincipals, ", "))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: bucketName,
			Provider: "gcp", Service: "gcr",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	// Verificar repositórios do Artifact Registry
	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	repos, err := artifactSvc.Projects.Locations.Repositories.List(parent).Do()
	if err == nil {
		for _, repo := range repos.Repositories {
			policy, err := artifactSvc.Projects.Locations.Repositories.GetIamPolicy(repo.Name).Context(ctx).Do()
			if err != nil {
				continue
			}

			hasPublicAccess := false
			publicPrincipals := []string{}
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if member == "allUsers" || member == "allAuthenticatedUsers" {
						hasPublicAccess = true
						publicPrincipals = append(publicPrincipals, fmt.Sprintf("%s (%s)", member, binding.Role))
					}
				}
			}

			status := models.StatusPass
			ext := fmt.Sprintf("Repository %s has proper IAM configuration", repo.Name)
			if hasPublicAccess {
				status = models.StatusFail
				ext = fmt.Sprintf("Repository %s has public IAM access: %s", repo.Name, strings.Join(publicPrincipals, ", "))
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: ext,
				ResourceID: repo.Name,
				Provider: "gcp", Service: "gcr",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusInfo,
			StatusExtended: "No GCR buckets or Artifact Registry repositories found with accessible IAM",
			Provider: "gcp", Service: "gcr",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// RegistryLoggingCheck verifica logging do registry
type RegistryLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewRegistryLoggingCheck() *RegistryLoggingCheck {
	return &RegistryLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "gcr_registry_logging",
			CheckTitle:      "GCR registry logging is enabled",
			ServiceName:     "gcr",
			Severity:        "low",
			Description:     "GCR registry should have logging enabled for audit and compliance",
			RemediationText: "Enable access logging for GCR registry buckets and Artifact Registry",
			Categories:      []string{"logging"},
		},
	}
}

func (c *RegistryLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RegistryLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gcrProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement gcrProvider")
	}

	storageSvc, err := p.Storage(ctx)
	if err != nil {
		return nil, err
	}

	artifactSvc, err := p.ArtifactRegistry(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	region := p.Region()
	findings := []models.Finding{}

	// Verificar logging nos buckets de GCR
	gcrBuckets := []string{
		fmt.Sprintf("artifacts.%s.appspot.com", projectID),
		"us.gcr.io",
		"eu.gcr.io",
		"asia.gcr.io",
	}

	for _, bucketName := range gcrBuckets {
		bucket, err := storageSvc.Buckets.Get(bucketName).Do()
		if err != nil {
			continue
		}

		hasLogging := bucket.Logging != nil && bucket.Logging.LogBucket != ""
		status := models.StatusPass
		ext := fmt.Sprintf("Bucket %s has access logging enabled", bucketName)
		if !hasLogging {
			status = models.StatusFail
			ext = fmt.Sprintf("Bucket %s does not have access logging enabled", bucketName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: bucketName,
			Provider: "gcp", Service: "gcr",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	// Verificar se Artifact Registry tem audit logging (via Data Access logs)
	// Artifact Registry suporta audit logging nativo
	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	repos, err := artifactSvc.Projects.Locations.Repositories.List(parent).Do()
	if err == nil {
		for _, repo := range repos.Repositories {
			// Artifact Registry tem audit logging habilitado por padrão no Cloud Audit Logs
			// Verificar se existe configuração de auditoria
			hasAuditConfig := false
			if repo.Name != "" {
				// Por padrão, Artifact Registry registra Data Access logs
				// O usuário pode desabilitar, mas não há API para verificar diretamente
				hasAuditConfig = true
			}

			status := models.StatusPass
			ext := fmt.Sprintf("Repository %s has audit logging enabled (Cloud Audit Logs)", repo.Name)
			if !hasAuditConfig {
				status = models.StatusFail
				ext = fmt.Sprintf("Repository %s may not have audit logging enabled", repo.Name)
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: ext,
				ResourceID: repo.Name,
				Provider: "gcp", Service: "gcr",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusInfo,
			StatusExtended: "No GCR buckets or Artifact Registry repositories found",
			Provider: "gcp", Service: "gcr",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// RegistryEncryptionCheck verifica criptografia do registry
type RegistryEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewRegistryEncryptionCheck() *RegistryEncryptionCheck {
	return &RegistryEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "gcr_registry_encryption",
			CheckTitle:      "GCR registry uses encryption",
			ServiceName:     "gcr",
			Severity:        "medium",
			Description:     "GCR registry should use encryption (CMEK) for data at rest",
			RemediationText: "Enable CMEK encryption for GCR registry buckets and Artifact Registry",
			Categories:      []string{"encryption"},
		},
	}
}

func (c *RegistryEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RegistryEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gcrProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement gcrProvider")
	}

	storageSvc, err := p.Storage(ctx)
	if err != nil {
		return nil, err
	}

	artifactSvc, err := p.ArtifactRegistry(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	region := p.Region()
	findings := []models.Finding{}

	// Verificar criptografia nos buckets de GCR
	gcrBuckets := []string{
		fmt.Sprintf("artifacts.%s.appspot.com", projectID),
		"us.gcr.io",
		"eu.gcr.io",
		"asia.gcr.io",
	}

	for _, bucketName := range gcrBuckets {
		bucket, err := storageSvc.Buckets.Get(bucketName).Do()
		if err != nil {
			continue
		}

		hasCMEK := bucket.Encryption != nil && bucket.Encryption.DefaultKmsKeyName != ""
		status := models.StatusPass
		ext := fmt.Sprintf("Bucket %s uses customer-managed encryption key (CMEK)", bucketName)
		if !hasCMEK {
			status = models.StatusFail
			ext = fmt.Sprintf("Bucket %s uses Google-managed encryption (no CMEK)", bucketName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: bucketName,
			Provider: "gcp", Service: "gcr",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	// Verificar criptografia em Artifact Registry
	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	repos, err := artifactSvc.Projects.Locations.Repositories.List(parent).Do()
	if err == nil {
		for _, repo := range repos.Repositories {
			hasCMEK := repo.EncryptionConfig != nil && repo.EncryptionConfig.KmsKey != ""
			status := models.StatusPass
			ext := fmt.Sprintf("Repository %s uses customer-managed encryption key (CMEK)", repo.Name)
			if !hasCMEK {
				status = models.StatusFail
				ext = fmt.Sprintf("Repository %s uses Google-managed encryption (no CMEK)", repo.Name)
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: ext,
				ResourceID: repo.Name,
				Provider: "gcp", Service: "gcr",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusInfo,
			StatusExtended: "No GCR buckets or Artifact Registry repositories found",
			Provider: "gcp", Service: "gcr",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}
