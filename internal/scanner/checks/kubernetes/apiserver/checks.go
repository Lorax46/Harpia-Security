package apiserver

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/kubernetes"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// helper to find arg value from container command/args
func argValue(container corev1.Container, flag string) string {
	fullArgs := append(container.Command, container.Args...)
	for _, arg := range fullArgs {
		if strings.HasPrefix(arg, "--"+flag+"=") {
			return strings.TrimPrefix(arg, "--"+flag+"=")
		}
		if strings.HasPrefix(arg, flag+"=") {
			return strings.TrimPrefix(arg, flag+"=")
		}
	}
	return ""
}

func argHas(container corev1.Container, flag, value string) bool {
	fullArgs := append(container.Command, container.Args...)
	for _, arg := range fullArgs {
		if strings.Contains(arg, "--"+flag) && strings.Contains(arg, value) {
			return true
		}
	}
	return false
}

func argExists(container corev1.Container, flag string) bool {
	fullArgs := append(container.Command, container.Args...)
	for _, arg := range fullArgs {
		if strings.HasPrefix(arg, "--"+flag+"=") || arg == "--"+flag {
			return true
		}
	}
	return false
}

func argValueOrFlag(container corev1.Container, flag string) (string, bool) {
	fullArgs := append(container.Command, container.Args...)
	for _, arg := range fullArgs {
		if strings.HasPrefix(arg, "--"+flag+"=") {
			return strings.TrimPrefix(arg, "--"+flag+"="), true
		}
	}
	return "", false
}

func findAPIServerPods(ctx context.Context, p *kubernetes.Provider) ([]corev1.Pod, error) {
	pods, err := p.CoreV1().CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-apiserver",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list API server pods: %w", err)
	}
	if len(pods.Items) == 0 {
		pods, err = p.CoreV1().CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=kube-apiserver",
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list API server pods: %w", err)
		}
	}
	return pods.Items, nil
}

func buildFinding(meta models.CheckMetadata, status models.Status, msg, resourceID string) models.Finding {
	return models.Finding{
		ID:             meta.CheckID,
		Title:          meta.CheckTitle,
		Description:    meta.Description,
		Severity:       meta.Severity,
		Status:         status,
		StatusExtended: msg,
		Provider:       "kubernetes",
		Service:        "apiserver",
		ResourceID:     resourceID,
		Remediation:    meta.RemediationText,
		Categories:     meta.Categories,
		FoundAt:        time.Now(),
	}
}

// ===================== 1. AlwaysPullImages =====================

type ApiserverAlwaysPullImagesCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverAlwaysPullImagesCheck() *ApiserverAlwaysPullImagesCheck {
	return &ApiserverAlwaysPullImagesCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_always_pull_images_plugin",
			CheckTitle:      "API server should have AlwaysPullImages admission controller enabled",
			Description:     "AlwaysPullImages admission controller ensures containers always pull latest image",
			Severity:        "medium",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Enable AlwaysPullImages admission controller on the API server",
			Categories:      []string{"apiserver", "admission"},
		},
	}
}

func (c *ApiserverAlwaysPullImagesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverAlwaysPullImagesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			found := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "enable-admission-plugins") && strings.Contains(arg, "AlwaysPullImages") {
					found = true
					break
				}
			}
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have AlwaysPullImages enabled", pod.Name)
			if found {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has AlwaysPullImages enabled", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 2. AnonymousRequestsCheck =====================

type ApiserverAnonymousRequestsCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverAnonymousRequestsCheck() *ApiserverAnonymousRequestsCheck {
	return &ApiserverAnonymousRequestsCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_anonymous_requests_disabled",
			CheckTitle:      "API server should not allow anonymous requests",
			Description:     "Anonymous requests to the API server should be disabled to prevent unauthenticated access",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --anonymous-auth=false on the API server",
			Categories:      []string{"apiserver", "authentication"},
		},
	}
}

func (c *ApiserverAnonymousRequestsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverAnonymousRequestsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "anonymous-auth")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s allows anonymous requests", pod.Name)
			if found && val == "false" {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has anonymous-auth=false", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 3. AuditLogMaxage =====================

type ApiserverAuditLogMaxageCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverAuditLogMaxageCheck() *ApiserverAuditLogMaxageCheck {
	return &ApiserverAuditLogMaxageCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_audit_log_maxage",
			CheckTitle:      "API server audit log retention should be at least 30 days",
			Description:     "The audit-log-maxage parameter should be set to at least 30 to retain audit logs for compliance",
			Severity:        "medium",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --audit-log-maxage=30 or higher on the API server",
			Categories:      []string{"apiserver", "audit"},
		},
	}
}

func (c *ApiserverAuditLogMaxageCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverAuditLogMaxageCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "audit-log-maxage")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s has insufficient audit log maxage", pod.Name)
			if found {
				if days, err := strconv.Atoi(val); err == nil && days >= 30 {
					status = models.StatusPass
					msg = fmt.Sprintf("API server %s has audit-log-maxage=%d (>=30)", pod.Name, days)
				}
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 4. AuditLogMaxbackup =====================

type ApiserverAuditLogMaxbackupCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverAuditLogMaxbackupCheck() *ApiserverAuditLogMaxbackupCheck {
	return &ApiserverAuditLogMaxbackupCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_audit_log_maxbackup",
			CheckTitle:      "API server audit log backup count should be at least 10",
			Description:     "The audit-log-maxbackup parameter should be set to at least 10 to retain sufficient backups",
			Severity:        "medium",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --audit-log-maxbackup=10 or higher on the API server",
			Categories:      []string{"apiserver", "audit"},
		},
	}
}

func (c *ApiserverAuditLogMaxbackupCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverAuditLogMaxbackupCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "audit-log-maxbackup")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s has insufficient audit log maxbackup", pod.Name)
			if found {
				if count, err := strconv.Atoi(val); err == nil && count >= 10 {
					status = models.StatusPass
					msg = fmt.Sprintf("API server %s has audit-log-maxbackup=%d (>=10)", pod.Name, count)
				}
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 5. AuditLogMaxsize =====================

type ApiserverAuditLogMaxsizeCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverAuditLogMaxsizeCheck() *ApiserverAuditLogMaxsizeCheck {
	return &ApiserverAuditLogMaxsizeCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_audit_log_maxsize",
			CheckTitle:      "API server audit log max size should be at least 100 MB",
			Description:     "The audit-log-maxsize parameter should be set to at least 100 to ensure sufficient audit log capacity",
			Severity:        "medium",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --audit-log-maxsize=100 or higher on the API server",
			Categories:      []string{"apiserver", "audit"},
		},
	}
}

func (c *ApiserverAuditLogMaxsizeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverAuditLogMaxsizeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "audit-log-maxsize")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s has insufficient audit log maxsize", pod.Name)
			if found {
				if size, err := strconv.Atoi(val); err == nil && size >= 100 {
					status = models.StatusPass
					msg = fmt.Sprintf("API server %s has audit-log-maxsize=%d (>=100)", pod.Name, size)
				}
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 6. AuditLogPath =====================

type ApiserverAuditLogPathCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverAuditLogPathCheck() *ApiserverAuditLogPathCheck {
	return &ApiserverAuditLogPathCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_audit_log_path",
			CheckTitle:      "API server should have an audit log path configured",
			Description:     "The audit-log-path parameter specifies where audit logs are written and should be configured",
			Severity:        "medium",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --audit-log-path to a proper audit log location on the API server",
			Categories:      []string{"apiserver", "audit"},
		},
	}
}

func (c *ApiserverAuditLogPathCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverAuditLogPathCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "audit-log-path")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have audit-log-path configured", pod.Name)
			if found && val != "" {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has audit-log-path=%s", pod.Name, val)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 7. AuthModeNode =====================

type ApiserverAuthModeNodeCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverAuthModeNodeCheck() *ApiserverAuthModeNodeCheck {
	return &ApiserverAuthModeNodeCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_auth_mode_node",
			CheckTitle:      "API server should have Node authorization mode enabled",
			Description:     "Node authorization mode restricts kubelet permissions to specific node resources",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Add Node to --authorization-mode on the API server",
			Categories:      []string{"apiserver", "authorization"},
		},
	}
}

func (c *ApiserverAuthModeNodeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverAuthModeNodeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			found := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "--authorization-mode") && strings.Contains(arg, "Node") {
					found = true
					break
				}
			}
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have Node authorization mode", pod.Name)
			if found {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has Node authorization mode enabled", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 8. AuthModeRbac =====================

type ApiserverAuthModeRbacCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverAuthModeRbacCheck() *ApiserverAuthModeRbacCheck {
	return &ApiserverAuthModeRbacCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_auth_mode_rbac",
			CheckTitle:      "API server should have RBAC authorization mode enabled",
			Description:     "RBAC authorization mode provides fine-grained access control to Kubernetes resources",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Add RBAC to --authorization-mode on the API server",
			Categories:      []string{"apiserver", "authorization"},
		},
	}
}

func (c *ApiserverAuthModeRbacCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverAuthModeRbacCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			found := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "--authorization-mode") && strings.Contains(arg, "RBAC") {
					found = true
					break
				}
			}
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have RBAC authorization mode", pod.Name)
			if found {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has RBAC authorization mode enabled", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 9. AuthModeNotAlwaysAllow =====================

type ApiserverAuthModeNotAlwaysAllowCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverAuthModeNotAlwaysAllowCheck() *ApiserverAuthModeNotAlwaysAllowCheck {
	return &ApiserverAuthModeNotAlwaysAllowCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_auth_mode_not_always_allow",
			CheckTitle:      "API server should not have AlwaysAllow authorization mode",
			Description:     "AlwaysAllow authorization mode bypasses all authorization checks and should not be used",
			Severity:        "critical",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Remove AlwaysAllow from --authorization-mode on the API server",
			Categories:      []string{"apiserver", "authorization"},
		},
	}
}

func (c *ApiserverAuthModeNotAlwaysAllowCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverAuthModeNotAlwaysAllowCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			foundAlwaysAllow := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "--authorization-mode") && strings.Contains(arg, "AlwaysAllow") {
					foundAlwaysAllow = true
					break
				}
			}
			status := models.StatusPass
			msg := fmt.Sprintf("API server %s does not have AlwaysAllow authorization mode", pod.Name)
			if foundAlwaysAllow {
				status = models.StatusFail
				msg = fmt.Sprintf("API server %s has AlwaysAllow authorization mode (dangerous)", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 10. ClientCaFile =====================

type ApiserverClientCaFileCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverClientCaFileCheck() *ApiserverClientCaFileCheck {
	return &ApiserverClientCaFileCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_client_ca_file",
			CheckTitle:      "API server should have a client CA file configured",
			Description:     "client-ca-file is used to verify client certificates presented to the API server",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --client-ca-file on the API server to a proper CA bundle",
			Categories:      []string{"apiserver", "tls"},
		},
	}
}

func (c *ApiserverClientCaFileCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverClientCaFileCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "client-ca-file")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have client-ca-file configured", pod.Name)
			if found && val != "" {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has client-ca-file configured", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 11. DenyServiceExternalIPs =====================

type ApiserverDenyServiceExternalIpsCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverDenyServiceExternalIpsCheck() *ApiserverDenyServiceExternalIpsCheck {
	return &ApiserverDenyServiceExternalIpsCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_deny_service_external_ips",
			CheckTitle:      "API server should have DenyExternalIPs or ServiceNodeExclusion enabled",
			Description:     "DenyServiceExternalIPs admission controller prevents services from using external IPs that could bypass network policies",
			Severity:        "medium",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Enable DenyServiceExternalIPs admission controller on the API server",
			Categories:      []string{"apiserver", "admission", "network"},
		},
	}
}

func (c *ApiserverDenyServiceExternalIpsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverDenyServiceExternalIpsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			found := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "enable-admission-plugins") && strings.Contains(arg, "DenyServiceExternalIPs") {
					found = true
					break
				}
			}
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have DenyServiceExternalIPs enabled", pod.Name)
			if found {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has DenyServiceExternalIPs enabled", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 12. DisableProfiling =====================

type ApiserverDisableProfilingCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverDisableProfilingCheck() *ApiserverDisableProfilingCheck {
	return &ApiserverDisableProfilingCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_disable_profiling",
			CheckTitle:      "API server profiling should be disabled",
			Description:     "Profiling exposes detailed program internals and should be disabled in production",
			Severity:        "low",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --profiling=false on the API server",
			Categories:      []string{"apiserver", "profiling"},
		},
	}
}

func (c *ApiserverDisableProfilingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverDisableProfilingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "profiling")
			status := models.StatusPass
			msg := fmt.Sprintf("API server %s has profiling disabled", pod.Name)
			if !found {
				msg = fmt.Sprintf("API server %s profiling not explicitly disabled", pod.Name)
			} else if val != "false" {
				status = models.StatusFail
				msg = fmt.Sprintf("API server %s has profiling enabled", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 13. EncryptionProviderConfig =====================

type ApiserverEncryptionProviderConfigCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverEncryptionProviderConfigCheck() *ApiserverEncryptionProviderConfigCheck {
	return &ApiserverEncryptionProviderConfigCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_encryption_provider_config",
			CheckTitle:      "API server should have encryption provider config configured",
			Description:     "encryption-provider-config encrypts secrets at rest in etcd",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --encryption-provider-config on the API server",
			Categories:      []string{"apiserver", "encryption"},
		},
	}
}

func (c *ApiserverEncryptionProviderConfigCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverEncryptionProviderConfigCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "encryption-provider-config")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have encryption-provider-config configured", pod.Name)
			if found && val != "" {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has encryption-provider-config configured", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 14. EtcdCafile =====================

type ApiserverEtcdCafileCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverEtcdCafileCheck() *ApiserverEtcdCafileCheck {
	return &ApiserverEtcdCafileCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_etcd_cafile",
			CheckTitle:      "API server should have etcd CA file configured",
			Description:     "etcd-cafile verifies etcd server certificate to prevent MITM attacks",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --etcd-cafile on the API server",
			Categories:      []string{"apiserver", "etcd", "tls"},
		},
	}
}

func (c *ApiserverEtcdCafileCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverEtcdCafileCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "etcd-cafile")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have etcd-cafile configured", pod.Name)
			if found && val != "" {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has etcd-cafile configured", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 15. EtcdTls =====================

type ApiserverEtcdTlsCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverEtcdTlsCheck() *ApiserverEtcdTlsCheck {
	return &ApiserverEtcdTlsCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_etcd_tls",
			CheckTitle:      "API server should use TLS for etcd communication",
			Description:     "etcd-certfile and etcd-keyfile enable mutual TLS between API server and etcd",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --etcd-certfile and --etcd-keyfile on the API server",
			Categories:      []string{"apiserver", "etcd", "tls"},
		},
	}
}

func (c *ApiserverEtcdTlsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverEtcdTlsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			certVal, certFound := argValueOrFlag(container, "etcd-certfile")
			keyVal, keyFound := argValueOrFlag(container, "etcd-keyfile")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have etcd TLS configured", pod.Name)
			if certFound && keyFound && certVal != "" && keyVal != "" {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has etcd TLS configured", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 16. EventRateLimit =====================

type ApiserverEventRateLimitCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverEventRateLimitCheck() *ApiserverEventRateLimitCheck {
	return &ApiserverEventRateLimitCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_event_rate_limit",
			CheckTitle:      "API server should have EventRateLimit admission controller enabled",
			Description:     "EventRateLimit prevents API server flooding with event requests",
			Severity:        "medium",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Enable EventRateLimit admission controller on the API server",
			Categories:      []string{"apiserver", "admission"},
		},
	}
}

func (c *ApiserverEventRateLimitCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverEventRateLimitCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			found := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "enable-admission-plugins") && strings.Contains(arg, "EventRateLimit") {
					found = true
					break
				}
			}
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have EventRateLimit enabled", pod.Name)
			if found {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has EventRateLimit enabled", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 17. KubeletCertAuth =====================

type ApiserverKubeletCertAuthCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverKubeletCertAuthCheck() *ApiserverKubeletCertAuthCheck {
	return &ApiserverKubeletCertAuthCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_kubelet_cert_auth",
			CheckTitle:      "API server should have kubelet certificate authority configured",
			Description:     "kubelet-certificate-authority validates kubelet server certificates",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --kubelet-certificate-authority on the API server",
			Categories:      []string{"apiserver", "kubelet", "tls"},
		},
	}
}

func (c *ApiserverKubeletCertAuthCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverKubeletCertAuthCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "kubelet-certificate-authority")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have kubelet-certificate-authority configured", pod.Name)
			if found && val != "" {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has kubelet-certificate-authority configured", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 18. KubeletTlsAuth =====================

type ApiserverKubeletTlsAuthCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverKubeletTlsAuthCheck() *ApiserverKubeletTlsAuthCheck {
	return &ApiserverKubeletTlsAuthCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_kubelet_tls_auth",
			CheckTitle:      "API server should use TLS for kubelet communication",
			Description:     "kubelet-client-certificate and kubelet-client-key enable mutual TLS with kubelets",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --kubelet-client-certificate and --kubelet-client-key on the API server",
			Categories:      []string{"apiserver", "kubelet", "tls"},
		},
	}
}

func (c *ApiserverKubeletTlsAuthCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverKubeletTlsAuthCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			certVal, certFound := argValueOrFlag(container, "kubelet-client-certificate")
			keyVal, keyFound := argValueOrFlag(container, "kubelet-client-key")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have kubelet TLS configured", pod.Name)
			if certFound && keyFound && certVal != "" && keyVal != "" {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has kubelet TLS configured", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 19. NamespaceLifecycle =====================

type ApiserverNamespaceLifecycleCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverNamespaceLifecycleCheck() *ApiserverNamespaceLifecycleCheck {
	return &ApiserverNamespaceLifecycleCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_namespace_lifecycle",
			CheckTitle:      "API server should have NamespaceLifecycle admission controller enabled",
			Description:     "NamespaceLifecycle ensures proper namespace cleanup and prevents operations in terminating namespaces",
			Severity:        "medium",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Enable NamespaceLifecycle admission controller on the API server",
			Categories:      []string{"apiserver", "admission"},
		},
	}
}

func (c *ApiserverNamespaceLifecycleCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverNamespaceLifecycleCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			found := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "enable-admission-plugins") && strings.Contains(arg, "NamespaceLifecycle") {
					found = true
					break
				}
			}
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have NamespaceLifecycle enabled", pod.Name)
			if found {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has NamespaceLifecycle enabled", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 20. NoAlwaysAdmit =====================

type ApiserverNoAlwaysAdmitCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverNoAlwaysAdmitCheck() *ApiserverNoAlwaysAdmitCheck {
	return &ApiserverNoAlwaysAdmitCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_no_always_admit",
			CheckTitle:      "API server should not have AlwaysAdmit admission controller enabled",
			Description:     "AlwaysAdmit bypasses all admission controllers and should be removed",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Remove AlwaysAdmit from --enable-admission-plugins on the API server",
			Categories:      []string{"apiserver", "admission"},
		},
	}
}

func (c *ApiserverNoAlwaysAdmitCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverNoAlwaysAdmitCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			foundAlwaysAdmit := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "enable-admission-plugins") && strings.Contains(arg, "AlwaysAdmit") {
					foundAlwaysAdmit = true
					break
				}
			}
			status := models.StatusPass
			msg := fmt.Sprintf("API server %s does not have AlwaysAdmit enabled", pod.Name)
			if foundAlwaysAdmit {
				status = models.StatusFail
				msg = fmt.Sprintf("API server %s has AlwaysAdmit enabled (dangerous)", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 21. NoTokenAuthFile =====================

type ApiserverNoTokenAuthFileCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverNoTokenAuthFileCheck() *ApiserverNoTokenAuthFileCheck {
	return &ApiserverNoTokenAuthFileCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_no_token_auth_file",
			CheckTitle:      "API server should not use token auth file",
			Description:     "token-auth-file provides static token authentication which is insecure and should be removed",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Remove --token-auth-file from the API server",
			Categories:      []string{"apiserver", "authentication"},
		},
	}
}

func (c *ApiserverNoTokenAuthFileCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverNoTokenAuthFileCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			_, found := argValueOrFlag(container, "token-auth-file")
			status := models.StatusPass
			msg := fmt.Sprintf("API server %s does not use token-auth-file", pod.Name)
			if found {
				status = models.StatusFail
				msg = fmt.Sprintf("API server %s uses token-auth-file (insecure)", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 22. NodeRestriction =====================

type ApiserverNodeRestrictionCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverNodeRestrictionCheck() *ApiserverNodeRestrictionCheck {
	return &ApiserverNodeRestrictionCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_node_restriction",
			CheckTitle:      "API server should have NodeRestriction admission controller enabled",
			Description:     "NodeRestriction restricts kubelet access to only its own node and pods",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Enable NodeRestriction admission controller on the API server",
			Categories:      []string{"apiserver", "admission"},
		},
	}
}

func (c *ApiserverNodeRestrictionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverNodeRestrictionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			found := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "enable-admission-plugins") && strings.Contains(arg, "NodeRestriction") {
					found = true
					break
				}
			}
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have NodeRestriction enabled", pod.Name)
			if found {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has NodeRestriction enabled", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 23. RequestTimeout =====================

type ApiserverRequestTimeoutCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverRequestTimeoutCheck() *ApiserverRequestTimeoutCheck {
	return &ApiserverRequestTimeoutCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_request_timeout",
			CheckTitle:      "API server should have request-timeout configured",
			Description:     "request-timeout limits how long a request can take, preventing resource exhaustion",
			Severity:        "low",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --request-timeout on the API server (e.g. 60s)",
			Categories:      []string{"apiserver", "performance"},
		},
	}
}

func (c *ApiserverRequestTimeoutCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverRequestTimeoutCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "request-timeout")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have request-timeout configured", pod.Name)
			if found && val != "" {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has request-timeout=%s", pod.Name, val)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 24. SecurityContextDeny =====================

type ApiserverSecurityContextDenyCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverSecurityContextDenyCheck() *ApiserverSecurityContextDenyCheck {
	return &ApiserverSecurityContextDenyCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_security_context_deny",
			CheckTitle:      "API server should have SecurityContextDeny or Seccomp admission controller enabled",
			Description:     "SecurityContextDeny/Seccomp admission enforces security context and seccomp profiles on pods",
			Severity:        "medium",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Enable SecurityContextDeny or PodSecurity admission controller on the API server",
			Categories:      []string{"apiserver", "admission", "security"},
		},
	}
}

func (c *ApiserverSecurityContextDenyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverSecurityContextDenyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			found := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "enable-admission-plugins") {
					if strings.Contains(arg, "SecurityContextDeny") || strings.Contains(arg, "PodSecurity") || strings.Contains(arg, "Seccomp") {
						found = true
						break
					}
				}
			}
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have SecurityContextDeny/Seccomp/PodSecurity enabled", pod.Name)
			if found {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has security-related admission controller enabled", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 25. ServiceAccountKeyFile =====================

type ApiserverServiceAccountKeyFileCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverServiceAccountKeyFileCheck() *ApiserverServiceAccountKeyFileCheck {
	return &ApiserverServiceAccountKeyFileCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_service_account_key_file",
			CheckTitle:      "API server should have service-account-key-file configured",
			Description:     "service-account-key-file signs service account tokens and should be configured",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --service-account-key-file on the API server",
			Categories:      []string{"apiserver", "serviceaccount"},
		},
	}
}

func (c *ApiserverServiceAccountKeyFileCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverServiceAccountKeyFileCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "service-account-key-file")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have service-account-key-file configured", pod.Name)
			if found && val != "" {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has service-account-key-file configured", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 26. ServiceAccountLookup =====================

type ApiserverServiceAccountLookupCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverServiceAccountLookupCheck() *ApiserverServiceAccountLookupCheck {
	return &ApiserverServiceAccountLookupCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_service_account_lookup",
			CheckTitle:      "API server should have service-account-lookup enabled",
			Description:     "service-account-lookup verifies service account tokens exist before accepting them",
			Severity:        "medium",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --service-account-lookup=true on the API server",
			Categories:      []string{"apiserver", "serviceaccount"},
		},
	}
}

func (c *ApiserverServiceAccountLookupCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverServiceAccountLookupCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "service-account-lookup")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s has service-account-lookup not enabled", pod.Name)
			if found && val == "true" {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has service-account-lookup=true", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 27. ServiceAccountPlugin =====================

type ApiserverServiceAccountPluginCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverServiceAccountPluginCheck() *ApiserverServiceAccountPluginCheck {
	return &ApiserverServiceAccountPluginCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_service_account_plugin",
			CheckTitle:      "API server should have ServiceAccount admission controller enabled",
			Description:     "ServiceAccount admission controller manages service account creation and defaults",
			Severity:        "medium",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Enable ServiceAccount admission controller on the API server",
			Categories:      []string{"apiserver", "admission", "serviceaccount"},
		},
	}
}

func (c *ApiserverServiceAccountPluginCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverServiceAccountPluginCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			found := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "enable-admission-plugins") && strings.Contains(arg, "ServiceAccount") {
					found = true
					break
				}
			}
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have ServiceAccount admission enabled", pod.Name)
			if found {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has ServiceAccount admission enabled", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 28. StrongCiphers =====================

type ApiserverStrongCiphersCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverStrongCiphersCheck() *ApiserverStrongCiphersCheck {
	return &ApiserverStrongCiphersCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_strong_ciphers",
			CheckTitle:      "API server should use strong TLS cipher suites",
			Description:     "tls-cipher-suites should only include strong cipher suites to prevent downgrade attacks",
			Severity:        "medium",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --tls-cipher-suites to only include strong cipher suites on the API server",
			Categories:      []string{"apiserver", "tls"},
		},
	}
}

func (c *ApiserverStrongCiphersCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverStrongCiphersCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	weakCiphers := []string{"TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "tls-cipher-suites")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not specify strong cipher suites", pod.Name)
			if found && val != "" {
				hasWeak := false
				for _, weak := range weakCiphers {
					if strings.Contains(val, weak) {
						hasWeak = true
						break
					}
				}
				if !hasWeak {
					status = models.StatusPass
					msg = fmt.Sprintf("API server %s uses strong cipher suites", pod.Name)
				} else {
					msg = fmt.Sprintf("API server %s has weak cipher suites", pod.Name)
				}
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 29. TlsCheck =====================

type ApiserverTlsCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverTlsCheck() *ApiserverTlsCheck {
	return &ApiserverTlsCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_tls",
			CheckTitle:      "API server should use TLS certificate and key",
			Description:     "tls-cert-file and tls-private-key-file provide TLS termination for the API server",
			Severity:        "high",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --tls-cert-file and --tls-private-key-file on the API server",
			Categories:      []string{"apiserver", "tls"},
		},
	}
}

func (c *ApiserverTlsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverTlsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			certVal, certFound := argValueOrFlag(container, "tls-cert-file")
			keyVal, keyFound := argValueOrFlag(container, "tls-private-key-file")
			status := models.StatusFail
			msg := fmt.Sprintf("API server %s does not have TLS configured", pod.Name)
			if certFound && keyFound && certVal != "" && keyVal != "" {
				status = models.StatusPass
				msg = fmt.Sprintf("API server %s has TLS configured", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// ===================== 30. EtcdAutoTlsCheck =====================

type ApiserverEtcdAutoTlsCheck struct {
	metadata models.CheckMetadata
}

func NewApiserverEtcdAutoTlsCheck() *ApiserverEtcdAutoTlsCheck {
	return &ApiserverEtcdAutoTlsCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "apiserver_etcd_auto_tls_disabled",
			CheckTitle:      "API server should not use etcd auto-tls",
			Description:     "auto-tls generates self-signed certificates which should not be used in production",
			Severity:        "medium",
			ServiceName:     "apiserver",
			ResourceType:    "Configuration",
			RemediationText: "Set --etcd-auto-tls=false on the API server or use proper CA",
			Categories:      []string{"apiserver", "etcd", "tls"},
		},
	}
}

func (c *ApiserverEtcdAutoTlsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiserverEtcdAutoTlsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findAPIServerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "etcd-auto-tls")
			status := models.StatusPass
			msg := fmt.Sprintf("API server %s does not use etcd-auto-tls", pod.Name)
			if found && val != "false" {
				status = models.StatusFail
				msg = fmt.Sprintf("API server %s uses etcd-auto-tls", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}
