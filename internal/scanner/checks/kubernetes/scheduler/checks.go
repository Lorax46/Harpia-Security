package scheduler

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/kubernetes"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// ---- SchedulerBindAddressCheck ----

type SchedulerBindAddressCheck struct {
	metadata models.CheckMetadata
}

func NewSchedulerBindAddressCheck() *SchedulerBindAddressCheck {
	return &SchedulerBindAddressCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "scheduler_bind_address",
			CheckTitle:     "Scheduler should bind to localhost",
			Description:    "Scheduler should have bind-address set to 127.0.0.1",
			Severity:       "high",
			ServiceName:    "scheduler",
			ResourceType:   "Configuration",
			RemediationText: "Set --bind-address=127.0.0.1 on scheduler",
			Categories:     []string{"scheduler", "network"},
		},
	}
}

func (c *SchedulerBindAddressCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SchedulerBindAddressCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		if !strings.Contains(pod.Name, "scheduler") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			hasLocalhost := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "--bind-address=127.0.0.1") {
					hasLocalhost = true
					break
				}
			}

			status := models.StatusFail
			msg := fmt.Sprintf("Container %s/%s does not bind to 127.0.0.1", pod.Name, container.Name)
			if hasLocalhost {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s/%s binds to 127.0.0.1", pod.Name, container.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "scheduler",
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
			StatusExtended: "No scheduler pods found",
			Provider:       "kubernetes",
			Service:        "scheduler",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- SchedulerProfilingCheck ----

type SchedulerProfilingCheck struct {
	metadata models.CheckMetadata
}

func NewSchedulerProfilingCheck() *SchedulerProfilingCheck {
	return &SchedulerProfilingCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "scheduler_profiling",
			CheckTitle:     "Scheduler should disable profiling",
			Description:    "Scheduler should have profiling disabled",
			Severity:       "medium",
			ServiceName:    "scheduler",
			ResourceType:   "Configuration",
			RemediationText: "Disable profiling on scheduler",
			Categories:     []string{"scheduler", "security"},
		},
	}
}

func (c *SchedulerProfilingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SchedulerProfilingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		if !strings.Contains(pod.Name, "scheduler") {
			continue
		}

		for _, container := range pod.Spec.Containers {
			disabled := false
			for _, arg := range container.Command {
				if strings.Contains(arg, "--profiling=false") {
					disabled = true
					break
				}
			}

			status := models.StatusFail
			msg := fmt.Sprintf("Container %s/%s has profiling enabled", pod.Name, container.Name)
			if disabled {
				status = models.StatusPass
				msg = fmt.Sprintf("Container %s/%s has profiling disabled", pod.Name, container.Name)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: msg,
				Provider:       "kubernetes",
				Service:        "scheduler",
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
			StatusExtended: "No scheduler pods found",
			Provider:       "kubernetes",
			Service:        "scheduler",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}
