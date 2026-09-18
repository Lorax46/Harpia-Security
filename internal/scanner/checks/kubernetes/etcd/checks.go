package etcd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/kubernetes"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// ---- EtcdClientCertAuthCheck ----

type EtcdClientCertAuthCheck struct {
	metadata models.CheckMetadata
}

func NewEtcdClientCertAuthCheck() *EtcdClientCertAuthCheck {
	return &EtcdClientCertAuthCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "etcd_client_cert_auth",
			CheckTitle:     "etcd should require client certificate authentication",
			Description:    "etcd should have client-cert-auth enabled",
			Severity:       "critical",
			ServiceName:    "etcd",
			ResourceType:   "Configuration",
			RemediationText: "Enable client-cert-auth on etcd",
			Categories:     []string{"etcd", "authentication"},
		},
	}
}

func (c *EtcdClientCertAuthCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EtcdClientCertAuthCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	etcdPods, err := kube.ListPods(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range etcdPods.Items {
		if !strings.Contains(pod.Name, "etcd") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			found := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "--client-cert-auth=true") {
					found = true
					break
				}
			}

			status := models.StatusFail
			msg := fmt.Sprintf("Container %s/%s does not have client-cert-auth enabled", pod.Name, container.Name)
			if found {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s/%s has client-cert-auth enabled", pod.Name, container.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "etcd",
				ResourceID:     fmt.Sprintf("%s/%s", pod.Name, container.Name),
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "No etcd pods found in kube-system namespace",
			Provider:       "kubernetes",
			Service:        "etcd",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- EtcdNoAutoTlsCheck ----

type EtcdNoAutoTlsCheck struct {
	metadata models.CheckMetadata
}

func NewEtcdNoAutoTlsCheck() *EtcdNoAutoTlsCheck {
	return &EtcdNoAutoTlsCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "etcd_no_auto_tls",
			CheckTitle:     "etcd should not have auto-tls enabled",
			Description:    "etcd should have auto-tls disabled",
			Severity:       "critical",
			ServiceName:    "etcd",
			ResourceType:   "Configuration",
			RemediationText: "Disable auto-tls on etcd",
			Categories:     []string{"etcd", "tls"},
		},
	}
}

func (c *EtcdNoAutoTlsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EtcdNoAutoTlsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	etcdPods, err := kube.ListPods(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range etcdPods.Items {
		if !strings.Contains(pod.Name, "etcd") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			enabled := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "--auto-tls=true") {
					enabled = true
					break
				}
			}

			status := models.StatusPass
			msg := fmt.Sprintf("Container %s/%s does not have auto-tls enabled", pod.Name, container.Name)
			if enabled {
				status = models.StatusFail
				msg = fmt.Sprintf("Container %s/%s has auto-tls enabled", pod.Name, container.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "etcd",
				ResourceID:     fmt.Sprintf("%s/%s", pod.Name, container.Name),
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "No etcd pods found in kube-system namespace",
			Provider:       "kubernetes",
			Service:        "etcd",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- EtcdNoPeerAutoTlsCheck ----

type EtcdNoPeerAutoTlsCheck struct {
	metadata models.CheckMetadata
}

func NewEtcdNoPeerAutoTlsCheck() *EtcdNoPeerAutoTlsCheck {
	return &EtcdNoPeerAutoTlsCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "etcd_no_peer_auto_tls",
			CheckTitle:     "etcd should not have peer-auto-tls enabled",
			Description:    "etcd should have peer-auto-tls disabled",
			Severity:       "critical",
			ServiceName:    "etcd",
			ResourceType:   "Configuration",
			RemediationText: "Disable peer-auto-tls on etcd",
			Categories:     []string{"etcd", "tls"},
		},
	}
}

func (c *EtcdNoPeerAutoTlsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EtcdNoPeerAutoTlsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	etcdPods, err := kube.ListPods(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range etcdPods.Items {
		if !strings.Contains(pod.Name, "etcd") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			enabled := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "--peer-auto-tls=true") {
					enabled = true
					break
				}
			}

			status := models.StatusPass
			msg := fmt.Sprintf("Container %s/%s does not have peer-auto-tls enabled", pod.Name, container.Name)
			if enabled {
				status = models.StatusFail
				msg = fmt.Sprintf("Container %s/%s has peer-auto-tls enabled", pod.Name, container.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "etcd",
				ResourceID:     fmt.Sprintf("%s/%s", pod.Name, container.Name),
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "No etcd pods found in kube-system namespace",
			Provider:       "kubernetes",
			Service:        "etcd",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- EtcdPeerClientCertAuthCheck ----

type EtcdPeerClientCertAuthCheck struct {
	metadata models.CheckMetadata
}

func NewEtcdPeerClientCertAuthCheck() *EtcdPeerClientCertAuthCheck {
	return &EtcdPeerClientCertAuthCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "etcd_peer_client_cert_auth",
			CheckTitle:     "etcd should require peer client certificate authentication",
			Description:    "etcd should have peer-client-cert-auth enabled",
			Severity:       "critical",
			ServiceName:    "etcd",
			ResourceType:   "Configuration",
			RemediationText: "Enable peer-client-cert-auth on etcd",
			Categories:     []string{"etcd", "authentication"},
		},
	}
}

func (c *EtcdPeerClientCertAuthCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EtcdPeerClientCertAuthCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	etcdPods, err := kube.ListPods(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range etcdPods.Items {
		if !strings.Contains(pod.Name, "etcd") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			found := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "--peer-client-cert-auth=true") {
					found = true
					break
				}
			}

			status := models.StatusFail
			msg := fmt.Sprintf("Container %s/%s does not have peer-client-cert-auth enabled", pod.Name, container.Name)
			if found {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s/%s has peer-client-cert-auth enabled", pod.Name, container.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "etcd",
				ResourceID:     fmt.Sprintf("%s/%s", pod.Name, container.Name),
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "No etcd pods found in kube-system namespace",
			Provider:       "kubernetes",
			Service:        "etcd",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- EtcdPeerTlsCheck ----

type EtcdPeerTlsCheck struct {
	metadata models.CheckMetadata
}

func NewEtcdPeerTlsCheck() *EtcdPeerTlsCheck {
	return &EtcdPeerTlsCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "etcd_peer_tls",
			CheckTitle:     "etcd should use TLS for peer communication",
			Description:    "etcd should have peer-cert-file and peer-key-file configured",
			Severity:       "critical",
			ServiceName:    "etcd",
			ResourceType:   "Configuration",
			RemediationText: "Configure peer-cert-file and peer-key-file on etcd",
			Categories:     []string{"etcd", "tls"},
		},
	}
}

func (c *EtcdPeerTlsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EtcdPeerTlsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	etcdPods, err := kube.ListPods(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range etcdPods.Items {
		if !strings.Contains(pod.Name, "etcd") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			hasCert := false
			hasKey := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "--peer-cert-file") {
					hasCert = true
				}
				if strings.Contains(arg, "--peer-key-file") {
					hasKey = true
				}
			}

			enabled := hasCert && hasKey
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s/%s does not have peer TLS configured", pod.Name, container.Name)
			if enabled {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s/%s has peer TLS configured", pod.Name, container.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "etcd",
				ResourceID:     fmt.Sprintf("%s/%s", pod.Name, container.Name),
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "No etcd pods found in kube-system namespace",
			Provider:       "kubernetes",
			Service:        "etcd",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- EtcdTlsCheck ----

type EtcdTlsCheck struct {
	metadata models.CheckMetadata
}

func NewEtcdTlsCheck() *EtcdTlsCheck {
	return &EtcdTlsCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "etcd_tls",
			CheckTitle:     "etcd should use TLS for client communication",
			Description:    "etcd should have cert-file and key-file configured",
			Severity:       "critical",
			ServiceName:    "etcd",
			ResourceType:   "Configuration",
			RemediationText: "Configure cert-file and key-file on etcd",
			Categories:     []string{"etcd", "tls"},
		},
	}
}

func (c *EtcdTlsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EtcdTlsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	etcdPods, err := kube.ListPods(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range etcdPods.Items {
		if !strings.Contains(pod.Name, "etcd") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			hasCert := false
			hasKey := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "--cert-file") {
					hasCert = true
				}
				if strings.Contains(arg, "--key-file") {
					hasKey = true
				}
			}

			enabled := hasCert && hasKey
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s/%s does not have TLS configured", pod.Name, container.Name)
			if enabled {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s/%s has TLS configured", pod.Name, container.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "etcd",
				ResourceID:     fmt.Sprintf("%s/%s", pod.Name, container.Name),
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "No etcd pods found in kube-system namespace",
			Provider:       "kubernetes",
			Service:        "etcd",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- EtcdUniqueCaCheck ----

type EtcdUniqueCaCheck struct {
	metadata models.CheckMetadata
}

func NewEtcdUniqueCaCheck() *EtcdUniqueCaCheck {
	return &EtcdUniqueCaCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "etcd_unique_ca",
			CheckTitle:     "etcd should use a unique CA for client and peer certificates",
			Description:    "etcd should have a trusted-ca-file configured",
			Severity:       "critical",
			ServiceName:    "etcd",
			ResourceType:   "Configuration",
			RemediationText: "Configure a unique trusted-ca-file on etcd",
			Categories:     []string{"etcd", "tls"},
		},
	}
}

func (c *EtcdUniqueCaCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EtcdUniqueCaCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	etcdPods, err := kube.ListPods(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range etcdPods.Items {
		if !strings.Contains(pod.Name, "etcd") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			hasCa := false
			hasPeerCa := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "--trusted-ca-file") {
					hasCa = true
				}
				if strings.Contains(arg, "--peer-trusted-ca-file") {
					hasPeerCa = true
				}
			}

			enabled := hasCa && hasPeerCa
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s/%s does not have unique CA configured", pod.Name, container.Name)
			if enabled {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s/%s has unique CA configured", pod.Name, container.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "etcd",
				ResourceID:     fmt.Sprintf("%s/%s", pod.Name, container.Name),
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "No etcd pods found in kube-system namespace",
			Provider:       "kubernetes",
			Service:        "etcd",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}
