package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/kubernetes"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Local helper functions (mirrors from common.go to avoid import cycle with registry.go).

func podContainers(p corev1.Pod) []corev1.Container {
	containers := append([]corev1.Container{}, p.Spec.Containers...)
	containers = append(containers, p.Spec.InitContainers...)
	return containers
}

func isLatestTag(image string) bool {
	if idx := strings.LastIndex(image, ":"); idx != -1 {
		return image[idx+1:] == "latest"
	}
	return true
}

func hasLiveness(c corev1.Container) bool { return c.LivenessProbe != nil }
func hasReadiness(c corev1.Container) bool { return c.ReadinessProbe != nil }

func hasCPULimit(c corev1.Container) bool {
	return c.Resources.Limits.Cpu() != nil && !c.Resources.Limits.Cpu().IsZero()
}

func hasMemoryLimit(c corev1.Container) bool {
	return c.Resources.Limits.Memory() != nil && !c.Resources.Limits.Memory().IsZero()
}

func hasCPURequest(c corev1.Container) bool {
	return c.Resources.Requests.Cpu() != nil && !c.Resources.Requests.Cpu().IsZero()
}

func hasMemoryRequest(c corev1.Container) bool {
	return c.Resources.Requests.Memory() != nil && !c.Resources.Requests.Memory().IsZero()
}

func allowsPrivilegeEscalation(c corev1.Container) bool {
	if c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil {
		return true
	}
	return *c.SecurityContext.AllowPrivilegeEscalation
}

func runsAsRoot(pod corev1.Pod, c corev1.Container) bool {
	if c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil {
		return !*c.SecurityContext.RunAsNonRoot
	}
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil {
		return !*pod.Spec.SecurityContext.RunAsNonRoot
	}
	return true
}

func isPrivileged(c corev1.Container) bool {
	return c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged
}

func hasReadOnlyRootFilesystem(c corev1.Container) bool {
	return c.SecurityContext != nil && c.SecurityContext.ReadOnlyRootFilesystem != nil &&
		*c.SecurityContext.ReadOnlyRootFilesystem
}

func hasSeccompProfile(pod corev1.Pod, c corev1.Container) bool {
	if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil &&
		c.SecurityContext.SeccompProfile.Type != "" {
		return true
	}
	return pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil &&
		pod.Spec.SecurityContext.SeccompProfile.Type != ""
}

func isRuntimeDefaultSeccomp(pod corev1.Pod, c corev1.Container) bool {
	if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil &&
		c.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeRuntimeDefault {
		return true
	}
	return pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil &&
		pod.Spec.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeRuntimeDefault
}

func hasSecurityContext(c corev1.Container) bool {
	return c.SecurityContext != nil
}

func usesHostPort(pod corev1.Pod) bool {
	for _, c := range podContainers(pod) {
		for _, port := range c.Ports {
			if port.HostPort > 0 {
				return true
			}
		}
	}
	return false
}

func usesHostPath(pod corev1.Pod) bool {
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			return true
		}
	}
	return false
}

func usesHostNetwork(pod corev1.Pod) bool  { return pod.Spec.HostNetwork }
func usesHostPID(pod corev1.Pod) bool      { return pod.Spec.HostPID }
func usesHostIPC(pod corev1.Pod) bool      { return pod.Spec.HostIPC }

func hasAddedCapabilities(c corev1.Container) bool {
	return c.SecurityContext != nil && c.SecurityContext.Capabilities != nil &&
		len(c.SecurityContext.Capabilities.Add) > 0
}

func hasDroppedAllCapabilities(c corev1.Container) bool {
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return false
	}
	for _, d := range c.SecurityContext.Capabilities.Drop {
		return string(d) == "ALL"
	}
	return false
}

func hasNETRawCapability(c corev1.Container) bool {
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return false
	}
	for _, cap := range c.SecurityContext.Capabilities.Add {
		if string(cap) == "NET_RAW" {
			return true
		}
	}
	return false
}

func usesHostProcess(_ corev1.Pod) bool {
	return false
}

func hasSecretInEnv(c corev1.Container) bool {
	for _, env := range c.Env {
		if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
			return true
		}
	}
	for _, envFrom := range c.EnvFrom {
		if envFrom.SecretRef != nil {
			return true
		}
	}
	return false
}

// buildCoreFinding creates a Finding with core service defaults.
func buildCoreFinding(meta models.CheckMetadata, status models.Status, msg, resourceID string) models.Finding {
	return models.Finding{
		ID:             meta.CheckID,
		Title:          meta.CheckTitle,
		Description:    meta.Description,
		Severity:       meta.Severity,
		Status:         status,
		StatusExtended: msg,
		Provider:       "kubernetes",
		Service:        "core",
		ResourceID:     resourceID,
		Remediation:    meta.RemediationText,
		Categories:     meta.Categories,
		FoundAt:        time.Now(),
	}
}

// listAllPodsAcrossNamespaces lists all pods in all namespaces.
func listAllPodsAcrossNamespaces(ctx context.Context, p *kubernetes.Provider) ([]corev1.Pod, error) {
	podList, err := p.CoreV1().CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}
	return podList.Items, nil
}

// ===================== 1. CoreCpuLimitsCheck =====================

type CoreCpuLimitsCheck struct {
	metadata models.CheckMetadata
}

func NewCoreCpuLimitsCheck() *CoreCpuLimitsCheck {
	return &CoreCpuLimitsCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_cpu_limits",
			CheckTitle:      "Containers should have CPU limits set",
			Description:     "Setting CPU limits prevents resource exhaustion and noisy neighbor issues",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Set CPU limits for all containers in your pod specifications",
			Categories:      []string{"core", "resources"},
		},
	}
}

func (c *CoreCpuLimitsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreCpuLimitsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s in pod %s/%s does not have CPU limits", container.Name, pod.Namespace, pod.Name)
			if hasCPULimit(container) {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s in pod %s/%s has CPU limits set", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 2. CoreCpuRequestsCheck =====================

type CoreCpuRequestsCheck struct {
	metadata models.CheckMetadata
}

func NewCoreCpuRequestsCheck() *CoreCpuRequestsCheck {
	return &CoreCpuRequestsCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_cpu_requests",
			CheckTitle:      "Containers should have CPU requests set",
			Description:     "Setting CPU requests ensures containers get guaranteed CPU allocation",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Set CPU requests for all containers in your pod specifications",
			Categories:      []string{"core", "resources"},
		},
	}
}

func (c *CoreCpuRequestsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreCpuRequestsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s in pod %s/%s does not have CPU requests", container.Name, pod.Namespace, pod.Name)
			if hasCPURequest(container) {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s in pod %s/%s has CPU requests set", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 3. CoreImageTagFixedCheck =====================

type CoreImageTagFixedCheck struct {
	metadata models.CheckMetadata
}

func NewCoreImageTagFixedCheck() *CoreImageTagFixedCheck {
	return &CoreImageTagFixedCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_image_tag_fixed",
			CheckTitle:      "Containers should not use :latest image tag",
			Description:     "Using :latest tag makes deployments non-reproducible and can pull unexpected versions",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Use specific version tags for container images instead of :latest",
			Categories:      []string{"core", "images"},
		},
	}
}

func (c *CoreImageTagFixedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreImageTagFixedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s in pod %s/%s uses :latest or no tag", container.Name, pod.Namespace, pod.Name)
			if !isLatestTag(container.Image) {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s in pod %s/%s uses fixed tag", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 4. CoreLivenessProbeCheck =====================

type CoreLivenessProbeCheck struct {
	metadata models.CheckMetadata
}

func NewCoreLivenessProbeCheck() *CoreLivenessProbeCheck {
	return &CoreLivenessProbeCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_liveness_probe",
			CheckTitle:      "Containers should have liveness probes configured",
			Description:     "Liveness probes help restart unhealthy containers automatically",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Add liveness probes to your container specifications",
			Categories:      []string{"core", "health"},
		},
	}
}

func (c *CoreLivenessProbeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreLivenessProbeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s in pod %s/%s does not have liveness probe", container.Name, pod.Namespace, pod.Name)
			if hasLiveness(container) {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s in pod %s/%s has liveness probe", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 5. CoreMemoryLimitsCheck =====================

type CoreMemoryLimitsCheck struct {
	metadata models.CheckMetadata
}

func NewCoreMemoryLimitsCheck() *CoreMemoryLimitsCheck {
	return &CoreMemoryLimitsCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_memory_limits",
			CheckTitle:      "Containers should have memory limits set",
			Description:     "Setting memory limits prevents OOM issues and resource exhaustion",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Set memory limits for all containers in your pod specifications",
			Categories:      []string{"core", "resources"},
		},
	}
}

func (c *CoreMemoryLimitsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreMemoryLimitsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s in pod %s/%s does not have memory limits", container.Name, pod.Namespace, pod.Name)
			if hasMemoryLimit(container) {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s in pod %s/%s has memory limits set", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 6. CoreMemoryRequestsCheck =====================

type CoreMemoryRequestsCheck struct {
	metadata models.CheckMetadata
}

func NewCoreMemoryRequestsCheck() *CoreMemoryRequestsCheck {
	return &CoreMemoryRequestsCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_memory_requests",
			CheckTitle:      "Containers should have memory requests set",
			Description:     "Setting memory requests ensures containers get guaranteed memory allocation",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Set memory requests for all containers in your pod specifications",
			Categories:      []string{"core", "resources"},
		},
	}
}

func (c *CoreMemoryRequestsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreMemoryRequestsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s in pod %s/%s does not have memory requests", container.Name, pod.Namespace, pod.Name)
			if hasMemoryRequest(container) {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s in pod %s/%s has memory requests set", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 7. CoreMinimizeHostPortCheck =====================

type CoreMinimizeHostPortCheck struct {
	metadata models.CheckMetadata
}

func NewCoreMinimizeHostPortCheck() *CoreMinimizeHostPortCheck {
	return &CoreMinimizeHostPortCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_minimize_host_port",
			CheckTitle:      "Pods should not use hostPort",
			Description:     "hostPort binds container ports directly to the node, creating security and scheduling issues",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Remove hostPort bindings and use NodePort or LoadBalancer services",
			Categories:      []string{"core", "networking", "security"},
		},
	}
}

func (c *CoreMinimizeHostPortCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreMinimizeHostPortCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		status := models.StatusPass
		msg := fmt.Sprintf("Pod %s/%s does not use hostPort", pod.Namespace, pod.Name)
		if usesHostPort(pod) {
			status = models.StatusFail
			msg = fmt.Sprintf("Pod %s/%s uses hostPort", pod.Namespace, pod.Name)
		}
		findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)))
	}
	return findings, nil
}

// ===================== 8. CoreMinimizeAllowPrivEscCheck =====================

type CoreMinimizeAllowPrivEscCheck struct {
	metadata models.CheckMetadata
}

func NewCoreMinimizeAllowPrivEscCheck() *CoreMinimizeAllowPrivEscCheck {
	return &CoreMinimizeAllowPrivEscCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_minimize_allow_privilege_escalation",
			CheckTitle:      "Containers should not allow privilege escalation",
			Description:     "Privilege escalation allows a process to gain more privileges than its parent",
			Severity:        "high",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Set allowPrivilegeEscalation=false in container securityContext",
			Categories:      []string{"core", "security"},
		},
	}
}

func (c *CoreMinimizeAllowPrivEscCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreMinimizeAllowPrivEscCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusPass
			msg := fmt.Sprintf("Container %s in pod %s/%s does not allow privilege escalation", container.Name, pod.Namespace, pod.Name)
			if allowsPrivilegeEscalation(container) {
				status = models.StatusFail
				msg = fmt.Sprintf("Container %s in pod %s/%s allows privilege escalation", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 9. CoreMinimizeAddedCapabilitiesCheck =====================

type CoreMinimizeAddedCapabilitiesCheck struct {
	metadata models.CheckMetadata
}

func NewCoreMinimizeAddedCapabilitiesCheck() *CoreMinimizeAddedCapabilitiesCheck {
	return &CoreMinimizeAddedCapabilitiesCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_minimize_added_capabilities",
			CheckTitle:      "Containers should not add Linux capabilities",
			Description:     "Adding capabilities increases the attack surface of the container",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Remove added capabilities from container securityContext",
			Categories:      []string{"core", "security", "capabilities"},
		},
	}
}

func (c *CoreMinimizeAddedCapabilitiesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreMinimizeAddedCapabilitiesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusPass
			msg := fmt.Sprintf("Container %s in pod %s/%s does not add capabilities", container.Name, pod.Namespace, pod.Name)
			if hasAddedCapabilities(container) {
				status = models.StatusFail
				msg = fmt.Sprintf("Container %s in pod %s/%s adds capabilities", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 10. CoreMinimizeHostIpcCheck =====================

type CoreMinimizeHostIpcCheck struct {
	metadata models.CheckMetadata
}

func NewCoreMinimizeHostIpcCheck() *CoreMinimizeHostIpcCheck {
	return &CoreMinimizeHostIpcCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_minimize_host_ipc",
			CheckTitle:      "Pods should not use hostIPC",
			Description:     "hostIPC shares the node's IPC namespace with containers",
			Severity:        "high",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Remove hostIPC from pod spec",
			Categories:      []string{"core", "security", "namespace"},
		},
	}
}

func (c *CoreMinimizeHostIpcCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreMinimizeHostIpcCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		status := models.StatusPass
		msg := fmt.Sprintf("Pod %s/%s does not use hostIPC", pod.Namespace, pod.Name)
		if usesHostIPC(pod) {
			status = models.StatusFail
			msg = fmt.Sprintf("Pod %s/%s uses hostIPC", pod.Namespace, pod.Name)
		}
		findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)))
	}
	return findings, nil
}

// ===================== 11. CoreMinimizeHostNetworkCheck =====================

type CoreMinimizeHostNetworkCheck struct {
	metadata models.CheckMetadata
}

func NewCoreMinimizeHostNetworkCheck() *CoreMinimizeHostNetworkCheck {
	return &CoreMinimizeHostNetworkCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_minimize_host_network",
			CheckTitle:      "Pods should not use hostNetwork",
			Description:     "hostNetwork shares the node's network namespace with containers",
			Severity:        "high",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Remove hostNetwork from pod spec",
			Categories:      []string{"core", "security", "networking"},
		},
	}
}

func (c *CoreMinimizeHostNetworkCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreMinimizeHostNetworkCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		status := models.StatusPass
		msg := fmt.Sprintf("Pod %s/%s does not use hostNetwork", pod.Namespace, pod.Name)
		if usesHostNetwork(pod) {
			status = models.StatusFail
			msg = fmt.Sprintf("Pod %s/%s uses hostNetwork", pod.Namespace, pod.Name)
		}
		findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)))
	}
	return findings, nil
}

// ===================== 12. CoreMinimizeHostPidCheck =====================

type CoreMinimizeHostPidCheck struct {
	metadata models.CheckMetadata
}

func NewCoreMinimizeHostPidCheck() *CoreMinimizeHostPidCheck {
	return &CoreMinimizeHostPidCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_minimize_host_pid",
			CheckTitle:      "Pods should not use hostPID",
			Description:     "hostPID shares the node's PID namespace with containers",
			Severity:        "high",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Remove hostPID from pod spec",
			Categories:      []string{"core", "security", "namespace"},
		},
	}
}

func (c *CoreMinimizeHostPidCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreMinimizeHostPidCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		status := models.StatusPass
		msg := fmt.Sprintf("Pod %s/%s does not use hostPID", pod.Namespace, pod.Name)
		if usesHostPID(pod) {
			status = models.StatusFail
			msg = fmt.Sprintf("Pod %s/%s uses hostPID", pod.Namespace, pod.Name)
		}
		findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)))
	}
	return findings, nil
}

// ===================== 13. CoreMinimizeHostpathCheck =====================

type CoreMinimizeHostpathCheck struct {
	metadata models.CheckMetadata
}

func NewCoreMinimizeHostpathCheck() *CoreMinimizeHostpathCheck {
	return &CoreMinimizeHostpathCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_minimize_hostpath",
			CheckTitle:      "Pods should not mount hostPath volumes",
			Description:     "hostPath volumes expose node filesystem paths to containers",
			Severity:        "high",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Replace hostPath volumes with persistentVolumeClaim or other volume types",
			Categories:      []string{"core", "security", "storage"},
		},
	}
}

func (c *CoreMinimizeHostpathCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreMinimizeHostpathCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		status := models.StatusPass
		msg := fmt.Sprintf("Pod %s/%s does not mount hostPath", pod.Namespace, pod.Name)
		if usesHostPath(pod) {
			status = models.StatusFail
			msg = fmt.Sprintf("Pod %s/%s mounts hostPath", pod.Namespace, pod.Name)
		}
		findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)))
	}
	return findings, nil
}

// ===================== 14. CoreMinimizeNetRawCheck =====================

type CoreMinimizeNetRawCheck struct {
	metadata models.CheckMetadata
}

func NewCoreMinimizeNetRawCheck() *CoreMinimizeNetRawCheck {
	return &CoreMinimizeNetRawCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_minimize_net_raw",
			CheckTitle:      "Containers should not have NET_RAW capability",
			Description:     "NET_RAW capability allows raw socket access which can be used for network attacks",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Remove NET_RAW from added capabilities",
			Categories:      []string{"core", "security", "capabilities"},
		},
	}
}

func (c *CoreMinimizeNetRawCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreMinimizeNetRawCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusPass
			msg := fmt.Sprintf("Container %s in pod %s/%s does not have NET_RAW", container.Name, pod.Namespace, pod.Name)
			if hasNETRawCapability(container) {
				status = models.StatusFail
				msg = fmt.Sprintf("Container %s in pod %s/%s has NET_RAW capability", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 15. CoreMinimizePrivilegedCheck =====================

type CoreMinimizePrivilegedCheck struct {
	metadata models.CheckMetadata
}

func NewCoreMinimizePrivilegedCheck() *CoreMinimizePrivilegedCheck {
	return &CoreMinimizePrivilegedCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_minimize_privileged",
			CheckTitle:      "Containers should not run in privileged mode",
			Description:     "Privileged containers have full access to the host and bypass most security mechanisms",
			Severity:        "critical",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Remove privileged=true from container securityContext",
			Categories:      []string{"core", "security"},
		},
	}
}

func (c *CoreMinimizePrivilegedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreMinimizePrivilegedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusPass
			msg := fmt.Sprintf("Container %s in pod %s/%s is not privileged", container.Name, pod.Namespace, pod.Name)
			if isPrivileged(container) {
				status = models.StatusFail
				msg = fmt.Sprintf("Container %s in pod %s/%s is privileged", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 16. CoreMinimizeRootCheck =====================

type CoreMinimizeRootCheck struct {
	metadata models.CheckMetadata
}

func NewCoreMinimizeRootCheck() *CoreMinimizeRootCheck {
	return &CoreMinimizeRootCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_minimize_root",
			CheckTitle:      "Containers should run as non-root user",
			Description:     "Running as root increases attack surface if container is compromised",
			Severity:        "high",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Set runAsNonRoot=true in pod or container securityContext",
			Categories:      []string{"core", "security"},
		},
	}
}

func (c *CoreMinimizeRootCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreMinimizeRootCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusPass
			msg := fmt.Sprintf("Container %s in pod %s/%s runs as non-root", container.Name, pod.Namespace, pod.Name)
			if runsAsRoot(pod, container) {
				status = models.StatusFail
				msg = fmt.Sprintf("Container %s in pod %s/%s runs as root", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 17. CoreNoSecretsEnvCheck =====================

type CoreNoSecretsEnvCheck struct {
	metadata models.CheckMetadata
}

func NewCoreNoSecretsEnvCheck() *CoreNoSecretsEnvCheck {
	return &CoreNoSecretsEnvCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_no_secrets_env",
			CheckTitle:      "Secrets should not be exposed as environment variables",
			Description:     "Secrets in environment variables can be leaked via logging or debugging",
			Severity:        "high",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Use volume mounts or secretKeyRef with restricted access instead",
			Categories:      []string{"core", "security", "secrets"},
		},
	}
}

func (c *CoreNoSecretsEnvCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreNoSecretsEnvCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusPass
			msg := fmt.Sprintf("Container %s in pod %s/%s does not expose secrets via env", container.Name, pod.Namespace, pod.Name)
			if hasSecretInEnv(container) {
				status = models.StatusFail
				msg = fmt.Sprintf("Container %s in pod %s/%s exposes secrets via environment variables", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 18. CoreReadinessProbeCheck =====================

type CoreReadinessProbeCheck struct {
	metadata models.CheckMetadata
}

func NewCoreReadinessProbeCheck() *CoreReadinessProbeCheck {
	return &CoreReadinessProbeCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_readiness_probe",
			CheckTitle:      "Containers should have readiness probes configured",
			Description:     "Readiness probes ensure traffic is only sent to healthy containers",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Add readiness probes to your container specifications",
			Categories:      []string{"core", "health"},
		},
	}
}

func (c *CoreReadinessProbeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreReadinessProbeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s in pod %s/%s does not have readiness probe", container.Name, pod.Namespace, pod.Name)
			if hasReadiness(container) {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s in pod %s/%s has readiness probe", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 19. CoreReadonlyRootFsCheck =====================

type CoreReadonlyRootFsCheck struct {
	metadata models.CheckMetadata
}

func NewCoreReadonlyRootFsCheck() *CoreReadonlyRootFsCheck {
	return &CoreReadonlyRootFsCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_readonly_root_filesystem",
			CheckTitle:      "Containers should use read-only root filesystem",
			Description:     "Read-only root filesystem prevents attackers from modifying container files",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Set readOnlyRootFilesystem=true in container securityContext",
			Categories:      []string{"core", "security"},
		},
	}
}

func (c *CoreReadonlyRootFsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreReadonlyRootFsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s in pod %s/%s does not have read-only root filesystem", container.Name, pod.Namespace, pod.Name)
			if hasReadOnlyRootFilesystem(container) {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s in pod %s/%s has read-only root filesystem", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 20. CoreSeccompProfileCheck =====================

type CoreSeccompProfileCheck struct {
	metadata models.CheckMetadata
}

func NewCoreSeccompProfileCheck() *CoreSeccompProfileCheck {
	return &CoreSeccompProfileCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_seccomp_profile",
			CheckTitle:      "Containers should have a seccomp profile set",
			Description:     "Seccomp profiles restrict system calls available to containers",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Set seccomp profile in pod or container securityContext",
			Categories:      []string{"core", "security", "seccomp"},
		},
	}
}

func (c *CoreSeccompProfileCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreSeccompProfileCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s in pod %s/%s does not have seccomp profile", container.Name, pod.Namespace, pod.Name)
			if hasSeccompProfile(pod, container) {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s in pod %s/%s has seccomp profile", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 21. CoreSecurityContextCheck =====================

type CoreSecurityContextCheck struct {
	metadata models.CheckMetadata
}

func NewCoreSecurityContextCheck() *CoreSecurityContextCheck {
	return &CoreSecurityContextCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_security_context",
			CheckTitle:      "Containers should have securityContext configured",
			Description:     "Security context defines privilege and access control settings for containers",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Add securityContext to your container specifications",
			Categories:      []string{"core", "security"},
		},
	}
}

func (c *CoreSecurityContextCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreSecurityContextCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s in pod %s/%s does not have securityContext", container.Name, pod.Namespace, pod.Name)
			if hasSecurityContext(container) {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s in pod %s/%s has securityContext", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 22. CoreSeccompRuntimeDefaultCheck =====================

type CoreSeccompRuntimeDefaultCheck struct {
	metadata models.CheckMetadata
}

func NewCoreSeccompRuntimeDefaultCheck() *CoreSeccompRuntimeDefaultCheck {
	return &CoreSeccompRuntimeDefaultCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_seccomp_runtime_default",
			CheckTitle:      "Containers should use RuntimeDefault seccomp profile",
			Description:     "RuntimeDefault provides a strong baseline seccomp profile",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Set seccomp profile type to RuntimeDefault",
			Categories:      []string{"core", "security", "seccomp"},
		},
	}
}

func (c *CoreSeccompRuntimeDefaultCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreSeccompRuntimeDefaultCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s in pod %s/%s does not use RuntimeDefault seccomp", container.Name, pod.Namespace, pod.Name)
			if isRuntimeDefaultSeccomp(pod, container) {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s in pod %s/%s uses RuntimeDefault seccomp", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}

// ===================== 23. CoreMinimizeHostProcessCheck =====================

type CoreMinimizeHostProcessCheck struct {
	metadata models.CheckMetadata
}

func NewCoreMinimizeHostProcessCheck() *CoreMinimizeHostProcessCheck {
	return &CoreMinimizeHostProcessCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_minimize_host_process",
			CheckTitle:      "Windows containers should not use hostProcess",
			Description:     "hostProcess allows Windows containers to access the host directly",
			Severity:        "high",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Remove hostProcess from Windows pod security context",
			Categories:      []string{"core", "security", "windows"},
		},
	}
}

func (c *CoreMinimizeHostProcessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreMinimizeHostProcessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		status := models.StatusPass
		msg := fmt.Sprintf("Pod %s/%s does not use hostProcess", pod.Namespace, pod.Name)
		if usesHostProcess(pod) {
			status = models.StatusFail
			msg = fmt.Sprintf("Pod %s/%s uses hostProcess", pod.Namespace, pod.Name)
		}
		findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)))
	}
	return findings, nil
}

// ===================== 24. CoreDropCapabilitiesCheck =====================

type CoreDropCapabilitiesCheck struct {
	metadata models.CheckMetadata
}

func NewCoreDropCapabilitiesCheck() *CoreDropCapabilitiesCheck {
	return &CoreDropCapabilitiesCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "core_drop_capabilities",
			CheckTitle:      "Containers should drop ALL capabilities",
			Description:     "Dropping ALL capabilities and only adding back needed ones follows least privilege",
			Severity:        "medium",
			ServiceName:     "core",
			ResourceType:    "Pod",
			RemediationText: "Add capabilities.drop: [\"ALL\"] in container securityContext",
			Categories:      []string{"core", "security", "capabilities"},
		},
	}
}

func (c *CoreDropCapabilitiesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CoreDropCapabilitiesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := listAllPodsAcrossNamespaces(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range podContainers(pod) {
			status := models.StatusFail
			msg := fmt.Sprintf("Container %s in pod %s/%s does not drop ALL capabilities", container.Name, pod.Namespace, pod.Name)
			if hasDroppedAllCapabilities(container) {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s in pod %s/%s drops ALL capabilities", container.Name, pod.Namespace, pod.Name)
			}
			findings = append(findings, buildCoreFinding(c.metadata, status, msg, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)))
		}
	}
	return findings, nil
}
