// Package containers provides container security checks for Docker images,
// containers, and registries.
package containers

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// NewContainerChecks returns all container security checks.
func NewContainerChecks() []CheckFactory {
	return []CheckFactory{
		{ID: "dockerfile_user_check", New: func() Checker { return NewDockerfileUserCheck() }},
		{ID: "dockerfile_root_check", New: func() Checker { return NewDockerfileRootCheck() }},
		{ID: "dockerfile_healthcheck_check", New: func() Checker { return NewDockerfileHealthcheckCheck() }},
		{ID: "dockerfile_no_secrets", New: func() Checker { return NewDockerfileNoSecretsCheck() }},
		{ID: "image_vulnerability_scan", New: func() Checker { return NewImageVulnerabilityScanCheck() }},
		{ID: "image_base_official", New: func() Checker { return NewImageBaseOfficialCheck() }},
		{ID: "image_tag_pinned", New: func() Checker { return NewImageTagPinnedCheck() }},
		{ID: "container_privileged", New: func() Checker { return NewContainerPrivilegedCheck() }},
		{ID: "container_readonly_rootfs", New: func() Checker { return NewContainerReadonlyRootFSCheck() }},
		{ID: "container_security_context", New: func() Checker { return NewContainerSecurityContextCheck() }},
		{ID: "registry_immutable", New: func() Checker { return NewRegistryImmutableCheck() }},
		{ID: "registry_scan_on_push", New: func() Checker { return NewRegistryScanOnPushCheck() }},
	}
}

// CheckFactory creates new check instances.
type CheckFactory struct {
	ID  string
	New func() Checker
}

// Checker is the interface for container security checks.
type Checker interface {
	Metadata() models.CheckMetadata
	Execute(ctx context.Context, provider interface{}) ([]models.Finding, error)
}

// DockerfileUserCheck ensures Dockerfile uses non-root user.
type DockerfileUserCheck struct {
	metadata models.CheckMetadata
}

func NewDockerfileUserCheck() *DockerfileUserCheck {
	return &DockerfileUserCheck{
		metadata: models.CheckMetadata{
			Provider: "containers", CheckID: "dockerfile_user_check",
			CheckTitle: "Ensure Dockerfile uses non-root user",
			Description: "Dockerfile should specify a non-root USER instruction",
			ServiceName: "dockerfile", Severity: "high", ResourceType: "Dockerfile",
			Categories: []string{"dockerfile", "security"},
		},
	}
}

func (c *DockerfileUserCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DockerfileUserCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ContainerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ContainerProvider")
	}
	findings := []models.Finding{}
	dockerfiles, err := p.ListDockerfiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, df := range dockerfiles {
		if !df.HasUserInstruction {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Dockerfile %s does not have USER instruction", df.Path),
				ResourceID: df.Path, Provider: "containers", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Dockerfile %s has USER instruction", df.Path),
				ResourceID: df.Path, Provider: "containers", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// DockerfileRootCheck ensures Dockerfile does not use root.
type DockerfileRootCheck struct {
	metadata models.CheckMetadata
}

func NewDockerfileRootCheck() *DockerfileRootCheck {
	return &DockerfileRootCheck{
		metadata: models.CheckMetadata{
			Provider: "containers", CheckID: "dockerfile_root_check",
			CheckTitle: "Ensure Dockerfile does not run as root",
			Description: "Dockerfile USER instruction should not be root",
			ServiceName: "dockerfile", Severity: "high", ResourceType: "Dockerfile",
			Categories: []string{"dockerfile", "security"},
		},
	}
}

func (c *DockerfileRootCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DockerfileRootCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ContainerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ContainerProvider")
	}
	findings := []models.Finding{}
	dockerfiles, err := p.ListDockerfiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, df := range dockerfiles {
		if df.User == "root" || df.User == "0" {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Dockerfile %s runs as root", df.Path),
				ResourceID: df.Path, Provider: "containers", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Dockerfile %s does not run as root", df.Path),
				ResourceID: df.Path, Provider: "containers", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// DockerfileHealthcheckCheck ensures Dockerfile has HEALTHCHECK.
type DockerfileHealthcheckCheck struct {
	metadata models.CheckMetadata
}

func NewDockerfileHealthcheckCheck() *DockerfileHealthcheckCheck {
	return &DockerfileHealthcheckCheck{
		metadata: models.CheckMetadata{
			Provider: "containers", CheckID: "dockerfile_healthcheck_check",
			CheckTitle: "Ensure Dockerfile has HEALTHCHECK instruction",
			Description: "Dockerfile should include HEALTHCHECK for container health monitoring",
			ServiceName: "dockerfile", Severity: "medium", ResourceType: "Dockerfile",
			Categories: []string{"dockerfile", "reliability"},
		},
	}
}

func (c *DockerfileHealthcheckCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DockerfileHealthcheckCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ContainerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ContainerProvider")
	}
	findings := []models.Finding{}
	dockerfiles, err := p.ListDockerfiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, df := range dockerfiles {
		if !df.HasHealthcheck {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Dockerfile %s does not have HEALTHCHECK", df.Path),
				ResourceID: df.Path, Provider: "containers", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Dockerfile %s has HEALTHCHECK", df.Path),
				ResourceID: df.Path, Provider: "containers", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// DockerfileNoSecretsCheck ensures Dockerfile does not contain secrets.
type DockerfileNoSecretsCheck struct {
	metadata models.CheckMetadata
}

func NewDockerfileNoSecretsCheck() *DockerfileNoSecretsCheck {
	return &DockerfileNoSecretsCheck{
		metadata: models.CheckMetadata{
			Provider: "containers", CheckID: "dockerfile_no_secrets",
			CheckTitle: "Ensure Dockerfile does not contain secrets",
			Description: "Dockerfile should not contain hardcoded secrets or credentials",
			ServiceName: "dockerfile", Severity: "critical", ResourceType: "Dockerfile",
			Categories: []string{"dockerfile", "secrets"},
		},
	}
}

func (c *DockerfileNoSecretsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DockerfileNoSecretsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ContainerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ContainerProvider")
	}
	findings := []models.Finding{}
	dockerfiles, err := p.ListDockerfiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, df := range dockerfiles {
		if df.HasSecrets {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Dockerfile %s contains hardcoded secrets", df.Path),
				ResourceID: df.Path, Provider: "containers", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Dockerfile %s does not contain hardcoded secrets", df.Path),
				ResourceID: df.Path, Provider: "containers", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// ImageVulnerabilityScanCheck ensures images are scanned for vulnerabilities.
type ImageVulnerabilityScanCheck struct {
	metadata models.CheckMetadata
}

func NewImageVulnerabilityScanCheck() *ImageVulnerabilityScanCheck {
	return &ImageVulnerabilityScanCheck{
		metadata: models.CheckMetadata{
			Provider: "containers", CheckID: "image_vulnerability_scan",
			CheckTitle: "Ensure container images are scanned for vulnerabilities",
			Description: "Container images should be scanned for known vulnerabilities",
			ServiceName: "image", Severity: "high", ResourceType: "Image",
			Categories: []string{"image", "vulnerabilities"},
		},
	}
}

func (c *ImageVulnerabilityScanCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ImageVulnerabilityScanCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ContainerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ContainerProvider")
	}
	findings := []models.Finding{}
	images, err := p.ListImages(ctx)
	if err != nil {
		return nil, err
	}
	for _, img := range images {
		if !img.Scanned {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Image %s has not been scanned for vulnerabilities", img.Name),
				ResourceID: img.Name, Provider: "containers", Service: "image",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else if img.CriticalVulns > 0 {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Image %s has %d critical vulnerabilities", img.Name, img.CriticalVulns),
				ResourceID: img.Name, Provider: "containers", Service: "image",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Image %s has been scanned and has no critical vulnerabilities", img.Name),
				ResourceID: img.Name, Provider: "containers", Service: "image",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// ImageBaseOfficialCheck ensures images use official base images.
type ImageBaseOfficialCheck struct {
	metadata models.CheckMetadata
}

func NewImageBaseOfficialCheck() *ImageBaseOfficialCheck {
	return &ImageBaseOfficialCheck{
		metadata: models.CheckMetadata{
			Provider: "containers", CheckID: "image_base_official",
			CheckTitle: "Ensure container images use official base images",
			Description: "Container images should use official/trusted base images",
			ServiceName: "image", Severity: "medium", ResourceType: "Image",
			Categories: []string{"image", "supply-chain"},
		},
	}
}

func (c *ImageBaseOfficialCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ImageBaseOfficialCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ContainerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ContainerProvider")
	}
	findings := []models.Finding{}
	images, err := p.ListImages(ctx)
	if err != nil {
		return nil, err
	}
	for _, img := range images {
		if !img.IsOfficialBase {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Image %s does not use an official base image", img.Name),
				ResourceID: img.Name, Provider: "containers", Service: "image",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Image %s uses an official base image", img.Name),
				ResourceID: img.Name, Provider: "containers", Service: "image",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// ImageTagPinnedCheck ensures images use pinned tags.
type ImageTagPinnedCheck struct {
	metadata models.CheckMetadata
}

func NewImageTagPinnedCheck() *ImageTagPinnedCheck {
	return &ImageTagPinnedCheck{
		metadata: models.CheckMetadata{
			Provider: "containers", CheckID: "image_tag_pinned",
			CheckTitle: "Ensure container images use pinned tags",
			Description: "Container images should use specific tags, not 'latest'",
			ServiceName: "image", Severity: "medium", ResourceType: "Image",
			Categories: []string{"image", "supply-chain"},
		},
	}
}

func (c *ImageTagPinnedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ImageTagPinnedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ContainerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ContainerProvider")
	}
	findings := []models.Finding{}
	images, err := p.ListImages(ctx)
	if err != nil {
		return nil, err
	}
	for _, img := range images {
		if img.Tag == "latest" || img.Tag == "" {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Image %s uses 'latest' tag instead of a specific version", img.Name),
				ResourceID: img.Name, Provider: "containers", Service: "image",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Image %s uses specific tag: %s", img.Name, img.Tag),
				ResourceID: img.Name, Provider: "containers", Service: "image",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// ContainerPrivilegedCheck ensures containers are not running in privileged mode.
type ContainerPrivilegedCheck struct {
	metadata models.CheckMetadata
}

func NewContainerPrivilegedCheck() *ContainerPrivilegedCheck {
	return &ContainerPrivilegedCheck{
		metadata: models.CheckMetadata{
			Provider: "containers", CheckID: "container_privileged",
			CheckTitle: "Ensure containers are not running in privileged mode",
			Description: "Containers should not run in privileged mode",
			ServiceName: "container", Severity: "critical", ResourceType: "Container",
			Categories: []string{"container", "runtime"},
		},
	}
}

func (c *ContainerPrivilegedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerPrivilegedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ContainerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ContainerProvider")
	}
	findings := []models.Finding{}
	containers, err := p.ListContainers(ctx)
	if err != nil {
		return nil, err
	}
	for _, cont := range containers {
		if cont.Privileged {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Container %s is running in privileged mode", cont.Name),
				ResourceID: cont.ID, Provider: "containers", Service: "container",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Container %s is not running in privileged mode", cont.Name),
				ResourceID: cont.ID, Provider: "containers", Service: "container",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// ContainerReadonlyRootFSCheck ensures containers use read-only root filesystem.
type ContainerReadonlyRootFSCheck struct {
	metadata models.CheckMetadata
}

func NewContainerReadonlyRootFSCheck() *ContainerReadonlyRootFSCheck {
	return &ContainerReadonlyRootFSCheck{
		metadata: models.CheckMetadata{
			Provider: "containers", CheckID: "container_readonly_rootfs",
			CheckTitle: "Ensure containers use read-only root filesystem",
			Description: "Containers should use read-only root filesystem when possible",
			ServiceName: "container", Severity: "medium", ResourceType: "Container",
			Categories: []string{"container", "runtime"},
		},
	}
}

func (c *ContainerReadonlyRootFSCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerReadonlyRootFSCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ContainerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ContainerProvider")
	}
	findings := []models.Finding{}
	containers, err := p.ListContainers(ctx)
	if err != nil {
		return nil, err
	}
	for _, cont := range containers {
		if !cont.ReadonlyRootFS {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Container %s does not use read-only root filesystem", cont.Name),
				ResourceID: cont.ID, Provider: "containers", Service: "container",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Container %s uses read-only root filesystem", cont.Name),
				ResourceID: cont.ID, Provider: "containers", Service: "container",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// ContainerSecurityContextCheck ensures containers have security context.
type ContainerSecurityContextCheck struct {
	metadata models.CheckMetadata
}

func NewContainerSecurityContextCheck() *ContainerSecurityContextCheck {
	return &ContainerSecurityContextCheck{
		metadata: models.CheckMetadata{
			Provider: "containers", CheckID: "container_security_context",
			CheckTitle: "Ensure containers have security context defined",
			Description: "Containers should have security context with proper settings",
			ServiceName: "container", Severity: "high", ResourceType: "Container",
			Categories: []string{"container", "runtime"},
		},
	}
}

func (c *ContainerSecurityContextCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerSecurityContextCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ContainerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ContainerProvider")
	}
	findings := []models.Finding{}
	containers, err := p.ListContainers(ctx)
	if err != nil {
		return nil, err
	}
	for _, cont := range containers {
		if !cont.HasSecurityContext {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Container %s does not have security context defined", cont.Name),
				ResourceID: cont.ID, Provider: "containers", Service: "container",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Container %s has security context defined", cont.Name),
				ResourceID: cont.ID, Provider: "containers", Service: "container",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// RegistryImmutableCheck ensures container registry uses immutable images.
type RegistryImmutableCheck struct {
	metadata models.CheckMetadata
}

func NewRegistryImmutableCheck() *RegistryImmutableCheck {
	return &RegistryImmutableCheck{
		metadata: models.CheckMetadata{
			Provider: "containers", CheckID: "registry_immutable",
			CheckTitle: "Ensure container registry uses immutable images",
			Description: "Container registry should use immutable images to prevent tag overwriting",
			ServiceName: "registry", Severity: "medium", ResourceType: "Registry",
			Categories: []string{"registry", "supply-chain"},
		},
	}
}

func (c *RegistryImmutableCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RegistryImmutableCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ContainerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ContainerProvider")
	}
	findings := []models.Finding{}
	registries, err := p.ListRegistries(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range registries {
		if !r.Immutable {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Registry %s does not use immutable images", r.Name),
				ResourceID: r.Name, Provider: "containers", Service: "registry",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Registry %s uses immutable images", r.Name),
				ResourceID: r.Name, Provider: "containers", Service: "registry",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// RegistryScanOnPushCheck ensures registry scans images on push.
type RegistryScanOnPushCheck struct {
	metadata models.CheckMetadata
}

func NewRegistryScanOnPushCheck() *RegistryScanOnPushCheck {
	return &RegistryScanOnPushCheck{
		metadata: models.CheckMetadata{
			Provider: "containers", CheckID: "registry_scan_on_push",
			CheckTitle: "Ensure container registry scans images on push",
			Description: "Container registry should scan images on push for vulnerabilities",
			ServiceName: "registry", Severity: "high", ResourceType: "Registry",
			Categories: []string{"registry", "vulnerabilities"},
		},
	}
}

func (c *RegistryScanOnPushCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RegistryScanOnPushCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ContainerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ContainerProvider")
	}
	findings := []models.Finding{}
	registries, err := p.ListRegistries(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range registries {
		if !r.ScanOnPush {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Registry %s does not scan images on push", r.Name),
				ResourceID: r.Name, Provider: "containers", Service: "registry",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Registry %s scans images on push", r.Name),
				ResourceID: r.Name, Provider: "containers", Service: "registry",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// ContainerProvider is the interface for container access.
type ContainerProvider interface {
	ListDockerfiles(ctx context.Context) ([]Dockerfile, error)
	ListImages(ctx context.Context) ([]Image, error)
	ListContainers(ctx context.Context) ([]Container, error)
	ListRegistries(ctx context.Context) ([]Registry, error)
}

// Dockerfile represents a Dockerfile.
type Dockerfile struct {
	Path               string
	User               string
	HasUserInstruction bool
	HasHealthcheck     bool
	HasSecrets         bool
}

// Image represents a container image.
type Image struct {
	Name           string
	Tag            string
	Scanned        bool
	CriticalVulns  int
	IsOfficialBase bool
}

// Container represents a running container.
type Container struct {
	ID                 string
	Name               string
	Privileged         bool
	ReadonlyRootFS     bool
	HasSecurityContext bool
}

// Registry represents a container registry.
type Registry struct {
	Name       string
	Immutable  bool
	ScanOnPush bool
}
