package controllermanager

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

func argValue(container corev1.Container, flag string) string {
	fullArgs := append(container.Command, container.Args...)
	for _, arg := range fullArgs {
		if strings.HasPrefix(arg, "--"+flag+"=") {
			return strings.TrimPrefix(arg, "--"+flag+"=")
		}
	}
	return ""
}

func argExists(container corev1.Container, flag string) bool {
	fullArgs := append(container.Command, container.Args...)
	for _, arg := range fullArgs {
		if strings.HasPrefix(arg, "--"+flag+"=") {
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

func findControllerManagerPods(ctx context.Context, p *kubernetes.Provider) ([]corev1.Pod, error) {
	pods, err := p.CoreV1().CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-controller-manager",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list controller manager pods: %w", err)
	}
	if len(pods.Items) == 0 {
		pods, err = p.CoreV1().CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=kube-controller-manager",
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list controller manager pods: %w", err)
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
		Service:        "controllermanager",
		ResourceID:     resourceID,
		Remediation:    meta.RemediationText,
		Categories:     meta.Categories,
		FoundAt:        time.Now(),
	}
}

// 1. BindAddress = 127.0.0.1

type ControllermanagerBindAddressCheck struct {
	metadata models.CheckMetadata
}

func NewControllermanagerBindAddressCheck() *ControllermanagerBindAddressCheck {
	return &ControllermanagerBindAddressCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "controllermanager_bind_address",
			CheckTitle:      "Controller Manager bind address should be 127.0.0.1",
			Description:     "The controller manager should bind only to localhost to limit network exposure",
			Severity:        "high",
			ServiceName:     "controllermanager",
			ResourceType:    "Configuration",
			RemediationText: "Set --bind-address=127.0.0.1 on the Controller Manager",
			Categories:      []string{"controllermanager", "network"},
		},
	}
}

func (c *ControllermanagerBindAddressCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ControllermanagerBindAddressCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findControllerManagerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "bind-address")
			status := models.StatusFail
			msg := fmt.Sprintf("Controller Manager %s has bind-address not set to 127.0.0.1", pod.Name)
			if found && val == "127.0.0.1" {
				status = models.StatusPass
				msg = fmt.Sprintf("Controller Manager %s binds to 127.0.0.1", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// 2. DisableProfiling

type ControllermanagerDisableProfilingCheck struct {
	metadata models.CheckMetadata
}

func NewControllermanagerDisableProfilingCheck() *ControllermanagerDisableProfilingCheck {
	return &ControllermanagerDisableProfilingCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "controllermanager_disable_profiling",
			CheckTitle:      "Controller Manager profiling should be disabled",
			Description:     "Profiling exposes detailed program internals and should be disabled in production",
			Severity:        "low",
			ServiceName:     "controllermanager",
			ResourceType:    "Configuration",
			RemediationText: "Set --profiling=false on the Controller Manager",
			Categories:      []string{"controllermanager", "profiling"},
		},
	}
}

func (c *ControllermanagerDisableProfilingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ControllermanagerDisableProfilingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findControllerManagerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "profiling")
			status := models.StatusPass
			msg := fmt.Sprintf("Controller Manager %s has profiling disabled", pod.Name)
			if !found {
				msg = fmt.Sprintf("Controller Manager %s profiling not explicitly disabled", pod.Name)
			} else if val != "false" {
				status = models.StatusFail
				msg = fmt.Sprintf("Controller Manager %s has profiling enabled", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// 3. GarbageCollection

type ControllermanagerGarbageCollectionCheck struct {
	metadata models.CheckMetadata
}

func NewControllermanagerGarbageCollectionCheck() *ControllermanagerGarbageCollectionCheck {
	return &ControllermanagerGarbageCollectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "controllermanager_garbage_collection",
			CheckTitle:      "Controller Manager should have garbage collection configured",
			Description:     "terminated-pod-gc-threshold controls when terminated pods are garbage collected",
			Severity:        "low",
			ServiceName:     "controllermanager",
			ResourceType:    "Configuration",
			RemediationText: "Set --terminated-pod-gc-threshold on the Controller Manager",
			Categories:      []string{"controllermanager", "gc"},
		},
	}
}

func (c *ControllermanagerGarbageCollectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ControllermanagerGarbageCollectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findControllerManagerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "terminated-pod-gc-threshold")
			status := models.StatusFail
			msg := fmt.Sprintf("Controller Manager %s does not have terminated-pod-gc-threshold set", pod.Name)
			if found && val != "" {
				status = models.StatusPass
				msg = fmt.Sprintf("Controller Manager %s has terminated-pod-gc-threshold=%s", pod.Name, val)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// 4. RootCaFile

type ControllermanagerRootCaFileCheck struct {
	metadata models.CheckMetadata
}

func NewControllermanagerRootCaFileCheck() *ControllermanagerRootCaFileCheck {
	return &ControllermanagerRootCaFileCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "controllermanager_root_ca_file",
			CheckTitle:      "Controller Manager should have root CA file configured",
			Description:     "root-ca-file is used to verify service account token requests",
			Severity:        "high",
			ServiceName:     "controllermanager",
			ResourceType:    "Configuration",
			RemediationText: "Set --root-ca-file on the Controller Manager",
			Categories:      []string{"controllermanager", "tls"},
		},
	}
}

func (c *ControllermanagerRootCaFileCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ControllermanagerRootCaFileCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findControllerManagerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "root-ca-file")
			status := models.StatusFail
			msg := fmt.Sprintf("Controller Manager %s does not have root-ca-file configured", pod.Name)
			if found && val != "" {
				status = models.StatusPass
				msg = fmt.Sprintf("Controller Manager %s has root-ca-file configured", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// 5. RotateKubeletServerCert

type ControllermanagerRotateKubeletServerCertCheck struct {
	metadata models.CheckMetadata
}

func NewControllermanagerRotateKubeletServerCertCheck() *ControllermanagerRotateKubeletServerCertCheck {
	return &ControllermanagerRotateKubeletServerCertCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "controllermanager_rotate_kubelet_server_cert",
			CheckTitle:      "Controller Manager should enable RotateKubeletServerCertificate",
			Description:     "RotateKubeletServerCertificate ensures kubelet server certificates are rotated automatically",
			Severity:        "high",
			ServiceName:     "controllermanager",
			ResourceType:    "Configuration",
			RemediationText: "Set --feature-gates=RotateKubeletServerCertificate=true on the Controller Manager",
			Categories:      []string{"controllermanager", "tls"},
		},
	}
}

func (c *ControllermanagerRotateKubeletServerCertCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ControllermanagerRotateKubeletServerCertCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findControllerManagerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			found := false
			fullArgs := append(container.Command, container.Args...)
			for _, arg := range fullArgs {
				if strings.Contains(arg, "RotateKubeletServerCertificate") && strings.Contains(arg, "true") {
					found = true
					break
				}
			}
			status := models.StatusFail
			msg := fmt.Sprintf("Controller Manager %s does not enable RotateKubeletServerCertificate", pod.Name)
			if found {
				status = models.StatusPass
				msg = fmt.Sprintf("Controller Manager %s enables RotateKubeletServerCertificate", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// 6. ServiceAccountCredentials

type ControllermanagerServiceAccountCredentialsCheck struct {
	metadata models.CheckMetadata
}

func NewControllermanagerServiceAccountCredentialsCheck() *ControllermanagerServiceAccountCredentialsCheck {
	return &ControllermanagerServiceAccountCredentialsCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "controllermanager_service_account_credentials",
			CheckTitle:      "Controller Manager should use service account credentials",
			Description:     "use-service-account-credentials allows each controller to use its own service account",
			Severity:        "high",
			ServiceName:     "controllermanager",
			ResourceType:    "Configuration",
			RemediationText: "Set --use-service-account-credentials=true on the Controller Manager",
			Categories:      []string{"controllermanager", "serviceaccount"},
		},
	}
}

func (c *ControllermanagerServiceAccountCredentialsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ControllermanagerServiceAccountCredentialsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findControllerManagerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "use-service-account-credentials")
			status := models.StatusFail
			msg := fmt.Sprintf("Controller Manager %s does not use service account credentials", pod.Name)
			if found && val == "true" {
				status = models.StatusPass
				msg = fmt.Sprintf("Controller Manager %s uses service account credentials", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}

// 7. ServiceAccountPrivateKey

type ControllermanagerServiceAccountPrivateKeyCheck struct {
	metadata models.CheckMetadata
}

func NewControllermanagerServiceAccountPrivateKeyCheck() *ControllermanagerServiceAccountPrivateKeyCheck {
	return &ControllermanagerServiceAccountPrivateKeyCheck{
		metadata: models.CheckMetadata{
			Provider:        "kubernetes",
			CheckID:         "controllermanager_service_account_private_key",
			CheckTitle:      "Controller Manager should have service account private key configured",
			Description:     "service-account-private-key-file signs service account tokens",
			Severity:        "high",
			ServiceName:     "controllermanager",
			ResourceType:    "Configuration",
			RemediationText: "Set --service-account-private-key-file on the Controller Manager",
			Categories:      []string{"controllermanager", "serviceaccount"},
		},
	}
}

func (c *ControllermanagerServiceAccountPrivateKeyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ControllermanagerServiceAccountPrivateKeyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not *kubernetes.Provider")
	}

	pods, err := findControllerManagerPods(ctx, p)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			val, found := argValueOrFlag(container, "service-account-private-key-file")
			status := models.StatusFail
			msg := fmt.Sprintf("Controller Manager %s does not have service-account-private-key-file configured", pod.Name)
			if found && val != "" {
				status = models.StatusPass
				msg = fmt.Sprintf("Controller Manager %s has service-account-private-key-file configured", pod.Name)
			}
			findings = append(findings, buildFinding(c.metadata, status, msg, pod.Name))
		}
	}
	return findings, nil
}
