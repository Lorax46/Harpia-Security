package kubelet

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/kubernetes"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// ---- KubeletAuthorizationModeCheck ----

type KubeletAuthorizationModeCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletAuthorizationModeCheck() *KubeletAuthorizationModeCheck {
	return &KubeletAuthorizationModeCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_authorization_mode",
			CheckTitle:     "Kubelet should use Webhook authorization mode",
			Description:    "Kubelet should have authorization-mode set to Webhook",
			Severity:       "critical",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Set --authorization-mode=Webhook on kubelet",
			Categories:     []string{"kubelet", "authorization"},
		},
	}
}

func (c *KubeletAuthorizationModeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletAuthorizationModeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	nodes, err := kube.ListNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	// Check kubelet config via configmap or node annotations
	configMaps, err := kube.ListConfigMaps(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list configmaps: %w", err)
	}

	for _, cm := range configMaps.Items {
		if strings.Contains(cm.Name, "kubelet-config") {
			hasWebhook := false
			for _, data := range cm.Data {
				if strings.Contains(data, "authorizationMode: Webhook") ||
					strings.Contains(data, "authorization-mode: Webhook") {
					hasWebhook = true
					break
				}
			}

			status := models.StatusFail
			msg := fmt.Sprintf("ConfigMap %s does not have authorization-mode set to Webhook", cm.Name)
			if hasWebhook {
				status = models.StatusPass
				msg = fmt.Sprintf("ConfigMap %s has authorization-mode set to Webhook", cm.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "kubelet",
				ResourceID:     cm.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		if len(nodes.Items) > 0 {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusInfo,
				StatusExtended: "No kubelet-config ConfigMap found; check node configuration",
				Provider:       "kubernetes",
				Service:        "kubelet",
				ResourceID:     "",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	return findings, nil
}

// ---- KubeletClientCaFileCheck ----

type KubeletClientCaFileCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletClientCaFileCheck() *KubeletClientCaFileCheck {
	return &KubeletClientCaFileCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_client_ca_file",
			CheckTitle:     "Kubelet should use client CA file",
			Description:    "Kubelet should have client-ca-file configured",
			Severity:       "critical",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Set --client-ca-file on kubelet",
			Categories:     []string{"kubelet", "tls"},
		},
	}
}

func (c *KubeletClientCaFileCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletClientCaFileCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	configMaps, err := kube.ListConfigMaps(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list configmaps: %w", err)
	}

	for _, cm := range configMaps.Items {
		if strings.Contains(cm.Name, "kubelet-config") {
			hasCA := false
			for _, data := range cm.Data {
				if strings.Contains(data, "clientCAFile") || strings.Contains(data, "client-ca-file") {
					hasCA = true
					break
				}
			}

			status := models.StatusFail
			msg := fmt.Sprintf("ConfigMap %s does not have client-ca-file configured", cm.Name)
			if hasCA {
				status = models.StatusPass
				msg = fmt.Sprintf("ConfigMap %s has client-ca-file configured", cm.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "kubelet",
				ResourceID:     cm.Name,
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
			StatusExtended: "No kubelet-config ConfigMap found",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletConfFileOwnershipCheck ----

type KubeletConfFileOwnershipCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletConfFileOwnershipCheck() *KubeletConfFileOwnershipCheck {
	return &KubeletConfFileOwnershipCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_conf_file_ownership",
			CheckTitle:     "kubelet.conf should have root:root ownership",
			Description:    "kubelet.conf should be owned by root:root",
			Severity:       "medium",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Change ownership of kubelet.conf to root:root",
			Categories:     []string{"kubelet", "permissions"},
		},
	}
}

func (c *KubeletConfFileOwnershipCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletConfFileOwnershipCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	pods, err := kube.ListPods(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range pods.Items {
		if !strings.Contains(pod.Name, "kubelet") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusManual,
				StatusExtended: fmt.Sprintf("Verify ownership of kubelet.conf is root:root on %s/%s", pod.Name, container.Name),
				Provider:       "kubernetes",
				Service:        "kubelet",
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
			Status:         models.StatusManual,
			StatusExtended: "Verify ownership of kubelet.conf is root:root on all nodes",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletConfFilePermissionsCheck ----

type KubeletConfFilePermissionsCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletConfFilePermissionsCheck() *KubeletConfFilePermissionsCheck {
	return &KubeletConfFilePermissionsCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_conf_file_permissions",
			CheckTitle:     "kubelet.conf should have 0600 permissions",
			Description:    "kubelet.conf should have 0600 or more restrictive permissions",
			Severity:       "medium",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Set permissions of kubelet.conf to 0600",
			Categories:     []string{"kubelet", "permissions"},
		},
	}
}

func (c *KubeletConfFilePermissionsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletConfFilePermissionsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	pods, err := kube.ListPods(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range pods.Items {
		if !strings.Contains(pod.Name, "kubelet") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusManual,
				StatusExtended: fmt.Sprintf("Verify permissions of kubelet.conf are 0600 on %s/%s", pod.Name, container.Name),
				Provider:       "kubernetes",
				Service:        "kubelet",
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
			Status:         models.StatusManual,
			StatusExtended: "Verify permissions of kubelet.conf are 0600 on all nodes",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletConfigYamlOwnershipCheck ----

type KubeletConfigYamlOwnershipCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletConfigYamlOwnershipCheck() *KubeletConfigYamlOwnershipCheck {
	return &KubeletConfigYamlOwnershipCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_config_yaml_ownership",
			CheckTitle:     "kubelet config.yaml should have root:root ownership",
			Description:    "kubelet config.yaml should be owned by root:root",
			Severity:       "medium",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Change ownership of config.yaml to root:root",
			Categories:     []string{"kubelet", "permissions"},
		},
	}
}

func (c *KubeletConfigYamlOwnershipCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletConfigYamlOwnershipCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	pods, err := kube.ListPods(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range pods.Items {
		if !strings.Contains(pod.Name, "kubelet") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusManual,
				StatusExtended: fmt.Sprintf("Verify ownership of config.yaml is root:root on %s/%s", pod.Name, container.Name),
				Provider:       "kubernetes",
				Service:        "kubelet",
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
			Status:         models.StatusManual,
			StatusExtended: "Verify ownership of config.yaml is root:root on all nodes",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletConfigYamlPermissionsCheck ----

type KubeletConfigYamlPermissionsCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletConfigYamlPermissionsCheck() *KubeletConfigYamlPermissionsCheck {
	return &KubeletConfigYamlPermissionsCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_config_yaml_permissions",
			CheckTitle:     "kubelet config.yaml should have 0600 permissions",
			Description:    "kubelet config.yaml should have 0600 or more restrictive permissions",
			Severity:       "medium",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Set permissions of config.yaml to 0600",
			Categories:     []string{"kubelet", "permissions"},
		},
	}
}

func (c *KubeletConfigYamlPermissionsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletConfigYamlPermissionsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	pods, err := kube.ListPods(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range pods.Items {
		if !strings.Contains(pod.Name, "kubelet") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusManual,
				StatusExtended: fmt.Sprintf("Verify permissions of config.yaml are 0600 on %s/%s", pod.Name, container.Name),
				Provider:       "kubernetes",
				Service:        "kubelet",
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
			Status:         models.StatusManual,
			StatusExtended: "Verify permissions of config.yaml are 0600 on all nodes",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletDisableAnonymousAuthCheck ----

type KubeletDisableAnonymousAuthCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletDisableAnonymousAuthCheck() *KubeletDisableAnonymousAuthCheck {
	return &KubeletDisableAnonymousAuthCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_disable_anonymous_auth",
			CheckTitle:     "Kubelet should disable anonymous authentication",
			Description:    "Kubelet should have anonymous-auth set to false",
			Severity:       "critical",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Set --anonymous-auth=false on kubelet",
			Categories:     []string{"kubelet", "authentication"},
		},
	}
}

func (c *KubeletDisableAnonymousAuthCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletDisableAnonymousAuthCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	configMaps, err := kube.ListConfigMaps(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list configmaps: %w", err)
	}

	for _, cm := range configMaps.Items {
		if strings.Contains(cm.Name, "kubelet-config") {
			hasAnonAuth := false
			disabled := false
			for _, data := range cm.Data {
				if strings.Contains(data, "anonymousAuth") || strings.Contains(data, "anonymous-auth") {
					hasAnonAuth = true
					if strings.Contains(data, "false") {
						disabled = true
						break
					}
				}
			}

			status := models.StatusFail
			msg := fmt.Sprintf("ConfigMap %s does not have anonymous-auth disabled", cm.Name)
			if !hasAnonAuth {
				status = models.StatusFail
				msg = fmt.Sprintf("ConfigMap %s missing anonymous-auth configuration", cm.Name)
			} else if disabled {
				status = models.StatusPass
				msg = fmt.Sprintf("ConfigMap %s has anonymous-auth disabled", cm.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "kubelet",
				ResourceID:     cm.Name,
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
			StatusExtended: "No kubelet-config ConfigMap found",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletDisableReadOnlyPortCheck ----

type KubeletDisableReadOnlyPortCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletDisableReadOnlyPortCheck() *KubeletDisableReadOnlyPortCheck {
	return &KubeletDisableReadOnlyPortCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_disable_read_only_port",
			CheckTitle:     "Kubelet should disable read-only port",
			Description:    "Kubelet should have read-only-port set to 0",
			Severity:       "high",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Set --read-only-port=0 on kubelet",
			Categories:     []string{"kubelet", "network"},
		},
	}
}

func (c *KubeletDisableReadOnlyPortCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletDisableReadOnlyPortCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	configMaps, err := kube.ListConfigMaps(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list configmaps: %w", err)
	}

	for _, cm := range configMaps.Items {
		if strings.Contains(cm.Name, "kubelet-config") {
			hasPort := false
			disabled := false
			for _, data := range cm.Data {
				if strings.Contains(data, "readOnlyPort") || strings.Contains(data, "read-only-port") {
					hasPort = true
					if strings.Contains(data, "0") {
						disabled = true
						break
					}
				}
			}

			status := models.StatusFail
			msg := fmt.Sprintf("ConfigMap %s does not have read-only-port disabled", cm.Name)
			if !hasPort {
				status = models.StatusFail
				msg = fmt.Sprintf("ConfigMap %s missing read-only-port configuration", cm.Name)
			} else if disabled {
				status = models.StatusPass
				msg = fmt.Sprintf("ConfigMap %s has read-only-port disabled", cm.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "kubelet",
				ResourceID:     cm.Name,
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
			StatusExtended: "No kubelet-config ConfigMap found",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletEventRecordQpsCheck ----

type KubeletEventRecordQpsCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletEventRecordQpsCheck() *KubeletEventRecordQpsCheck {
	return &KubeletEventRecordQpsCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_event_record_qps",
			CheckTitle:     "Kubelet should limit event record QPS",
			Description:    "Kubelet should have event-qps set to limit event recording",
			Severity:       "medium",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Set --event-qps on kubelet",
			Categories:     []string{"kubelet", "performance"},
		},
	}
}

func (c *KubeletEventRecordQpsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletEventRecordQpsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	configMaps, err := kube.ListConfigMaps(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list configmaps: %w", err)
	}

	for _, cm := range configMaps.Items {
		if strings.Contains(cm.Name, "kubelet-config") {
			hasQps := false
			for _, data := range cm.Data {
				if strings.Contains(data, "eventRecordQPS") || strings.Contains(data, "event-qps") {
					hasQps = true
					break
				}
			}

			status := models.StatusFail
			msg := fmt.Sprintf("ConfigMap %s does not have event-qps configured", cm.Name)
			if hasQps {
				status = models.StatusPass
				msg = fmt.Sprintf("ConfigMap %s has event-qps configured", cm.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "kubelet",
				ResourceID:     cm.Name,
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
			StatusExtended: "No kubelet-config ConfigMap found",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletManageIptablesCheck ----

type KubeletManageIptablesCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletManageIptablesCheck() *KubeletManageIptablesCheck {
	return &KubeletManageIptablesCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_manage_iptables",
			CheckTitle:     "Kubelet should manage iptables",
			Description:    "Kubelet should have make-iptables-util-chains set to true",
			Severity:       "medium",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Set --make-iptables-util-chains=true on kubelet",
			Categories:     []string{"kubelet", "network"},
		},
	}
}

func (c *KubeletManageIptablesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletManageIptablesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	configMaps, err := kube.ListConfigMaps(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list configmaps: %w", err)
	}

	for _, cm := range configMaps.Items {
		if strings.Contains(cm.Name, "kubelet-config") {
			hasIptables := false
			enabled := false
			for _, data := range cm.Data {
				if strings.Contains(data, "makeIPTablesUtilChains") || strings.Contains(data, "make-iptables-util-chains") {
					hasIptables = true
					if strings.Contains(data, "true") {
						enabled = true
						break
					}
				}
			}

			status := models.StatusFail
			msg := fmt.Sprintf("ConfigMap %s does not have make-iptables-util-chains enabled", cm.Name)
			if !hasIptables {
				status = models.StatusFail
				msg = fmt.Sprintf("ConfigMap %s missing make-iptables-util-chains configuration", cm.Name)
			} else if enabled {
				status = models.StatusPass
				msg = fmt.Sprintf("ConfigMap %s has make-iptables-util-chains enabled", cm.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "kubelet",
				ResourceID:     cm.Name,
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
			StatusExtended: "No kubelet-config ConfigMap found",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletRotateCertificatesCheck ----

type KubeletRotateCertificatesCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletRotateCertificatesCheck() *KubeletRotateCertificatesCheck {
	return &KubeletRotateCertificatesCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_rotate_certificates",
			CheckTitle:     "Kubelet should rotate certificates",
			Description:    "Kubelet should have rotate-certificates set to true",
			Severity:       "high",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Set --rotate-certificates=true on kubelet",
			Categories:     []string{"kubelet", "tls"},
		},
	}
}

func (c *KubeletRotateCertificatesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletRotateCertificatesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	configMaps, err := kube.ListConfigMaps(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list configmaps: %w", err)
	}

	for _, cm := range configMaps.Items {
		if strings.Contains(cm.Name, "kubelet-config") {
			hasRotate := false
			enabled := false
			for _, data := range cm.Data {
				if strings.Contains(data, "rotateCertificates") || strings.Contains(data, "rotate-certificates") {
					hasRotate = true
					if strings.Contains(data, "true") {
						enabled = true
						break
					}
				}
			}

			status := models.StatusFail
			msg := fmt.Sprintf("ConfigMap %s does not have rotate-certificates enabled", cm.Name)
			if !hasRotate {
				status = models.StatusFail
				msg = fmt.Sprintf("ConfigMap %s missing rotate-certificates configuration", cm.Name)
			} else if enabled {
				status = models.StatusPass
				msg = fmt.Sprintf("ConfigMap %s has rotate-certificates enabled", cm.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "kubelet",
				ResourceID:     cm.Name,
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
			StatusExtended: "No kubelet-config ConfigMap found",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletServiceFileOwnershipCheck ----

type KubeletServiceFileOwnershipCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletServiceFileOwnershipCheck() *KubeletServiceFileOwnershipCheck {
	return &KubeletServiceFileOwnershipCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_service_file_ownership",
			CheckTitle:     "kubelet.service should have root:root ownership",
			Description:    "kubelet.service should be owned by root:root",
			Severity:       "medium",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Change ownership of kubelet.service to root:root",
			Categories:     []string{"kubelet", "permissions"},
		},
	}
}

func (c *KubeletServiceFileOwnershipCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletServiceFileOwnershipCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	pods, err := kube.ListPods(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range pods.Items {
		if !strings.Contains(pod.Name, "kubelet") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusManual,
				StatusExtended: fmt.Sprintf("Verify ownership of kubelet.service is root:root on %s/%s", pod.Name, container.Name),
				Provider:       "kubernetes",
				Service:        "kubelet",
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
			Status:         models.StatusManual,
			StatusExtended: "Verify ownership of kubelet.service is root:root on all nodes",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletServiceFilePermissionsCheck ----

type KubeletServiceFilePermissionsCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletServiceFilePermissionsCheck() *KubeletServiceFilePermissionsCheck {
	return &KubeletServiceFilePermissionsCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_service_file_permissions",
			CheckTitle:     "kubelet.service should have 0600 permissions",
			Description:    "kubelet.service should have 0600 or more restrictive permissions",
			Severity:       "medium",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Set permissions of kubelet.service to 0600",
			Categories:     []string{"kubelet", "permissions"},
		},
	}
}

func (c *KubeletServiceFilePermissionsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletServiceFilePermissionsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	pods, err := kube.ListPods(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range pods.Items {
		if !strings.Contains(pod.Name, "kubelet") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusManual,
				StatusExtended: fmt.Sprintf("Verify permissions of kubelet.service are 0600 on %s/%s", pod.Name, container.Name),
				Provider:       "kubernetes",
				Service:        "kubelet",
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
			Status:         models.StatusManual,
			StatusExtended: "Verify permissions of kubelet.service are 0600 on all nodes",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletStreamingConnectionTimeoutCheck ----

type KubeletStreamingConnectionTimeoutCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletStreamingConnectionTimeoutCheck() *KubeletStreamingConnectionTimeoutCheck {
	return &KubeletStreamingConnectionTimeoutCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_streaming_connection_timeout",
			CheckTitle:     "Kubelet should set streaming connection idle timeout",
			Description:    "Kubelet should have streaming-connection-idle-timeout configured",
			Severity:       "medium",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Set --streaming-connection-idle-timeout on kubelet",
			Categories:     []string{"kubelet", "network"},
		},
	}
}

func (c *KubeletStreamingConnectionTimeoutCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletStreamingConnectionTimeoutCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	configMaps, err := kube.ListConfigMaps(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list configmaps: %w", err)
	}

	for _, cm := range configMaps.Items {
		if strings.Contains(cm.Name, "kubelet-config") {
			hasTimeout := false
			for _, data := range cm.Data {
				if strings.Contains(data, "streamingConnectionIdleTimeout") || strings.Contains(data, "streaming-connection-idle-timeout") {
					hasTimeout = true
					break
				}
			}

			status := models.StatusFail
			msg := fmt.Sprintf("ConfigMap %s does not have streaming-connection-idle-timeout configured", cm.Name)
			if hasTimeout {
				status = models.StatusPass
				msg = fmt.Sprintf("ConfigMap %s has streaming-connection-idle-timeout configured", cm.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "kubelet",
				ResourceID:     cm.Name,
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
			StatusExtended: "No kubelet-config ConfigMap found",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletStrongCiphersCheck ----

type KubeletStrongCiphersCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletStrongCiphersCheck() *KubeletStrongCiphersCheck {
	return &KubeletStrongCiphersCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_strong_ciphers",
			CheckTitle:     "Kubelet should use strong cipher suites",
			Description:    "Kubelet should use TLS cipher suites that are strong",
			Severity:       "medium",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Configure kubelet with strong cipher suites",
			Categories:     []string{"kubelet", "tls"},
		},
	}
}

func (c *KubeletStrongCiphersCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletStrongCiphersCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	configMaps, err := kube.ListConfigMaps(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list configmaps: %w", err)
	}

	for _, cm := range configMaps.Items {
		if strings.Contains(cm.Name, "kubelet-config") {
			hasCiphers := false
			strong := false
			for _, data := range cm.Data {
				if strings.Contains(data, "TLSCipherSuites") || strings.Contains(data, "tls-cipher-suites") {
					hasCiphers = true
					if strings.Contains(data, "TLS_ECDHE") || strings.Contains(data, "TLS_AES") || strings.Contains(data, "TLS_CHACHA20") {
						strong = true
					}
				}
			}

			status := models.StatusFail
			msg := fmt.Sprintf("ConfigMap %s does not have strong cipher suites configured", cm.Name)
			if hasCiphers && strong {
				status = models.StatusPass
				msg = fmt.Sprintf("ConfigMap %s has strong cipher suites configured", cm.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "kubelet",
				ResourceID:     cm.Name,
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
			StatusExtended: "No kubelet-config ConfigMap found",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- KubeletTlsCertAndKeyCheck ----

type KubeletTlsCertAndKeyCheck struct {
	metadata models.CheckMetadata
}

func NewKubeletTlsCertAndKeyCheck() *KubeletTlsCertAndKeyCheck {
	return &KubeletTlsCertAndKeyCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "kubelet_tls_cert_and_key",
			CheckTitle:     "Kubelet should have TLS cert and key configured",
			Description:    "Kubelet should have tls-cert-file and tls-private-key-file configured",
			Severity:       "critical",
			ServiceName:    "kubelet",
			ResourceType:   "Configuration",
			RemediationText: "Configure tls-cert-file and tls-private-key-file on kubelet",
			Categories:     []string{"kubelet", "tls"},
		},
	}
}

func (c *KubeletTlsCertAndKeyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KubeletTlsCertAndKeyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	configMaps, err := kube.ListConfigMaps(ctx, "kube-system")
	if err != nil {
		return nil, fmt.Errorf("failed to list configmaps: %w", err)
	}

	for _, cm := range configMaps.Items {
		if strings.Contains(cm.Name, "kubelet-config") {
			hasCert := false
			hasKey := false
			for _, data := range cm.Data {
				if strings.Contains(data, "TLSCertFile") || strings.Contains(data, "tls-cert-file") {
					hasCert = true
				}
				if strings.Contains(data, "TLSPrivateKeyFile") || strings.Contains(data, "tls-private-key-file") {
					hasKey = true
				}
			}

			enabled := hasCert && hasKey
			status := models.StatusFail
			msg := fmt.Sprintf("ConfigMap %s does not have TLS cert and key configured", cm.Name)
			if enabled {
				status = models.StatusPass
				msg = fmt.Sprintf("ConfigMap %s has TLS cert and key configured", cm.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "kubelet",
				ResourceID:     cm.Name,
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
			StatusExtended: "No kubelet-config ConfigMap found",
			Provider:       "kubernetes",
			Service:        "kubelet",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}
