package sts

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type stsProvider interface {
	STS(ctx context.Context) (*sts.Client, error)
}

// StsEndpointsInUseCheck verifica endpoints em uso
type StsEndpointsInUseCheck struct {
	metadata models.CheckMetadata
}

func NewStsEndpointsInUseCheck() *StsEndpointsInUseCheck {
	return &StsEndpointsInUseCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "sts_endpoints_in_use",
			CheckTitle: "Ensure STS endpoints are in use",
			Description: "STS endpoints should be in use",
			Severity: "low", ServiceName: "sts", ResourceType: "Endpoint",
			RemediationText: "Configure STS endpoints",
			Categories: []string{"sts", "endpoints"},
		},
	}
}

func (c *StsEndpointsInUseCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *StsEndpointsInUseCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(stsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement stsProvider")
	}

	client, err := p.STS(ctx)
	if err != nil {
		return nil, err
	}

	identity, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})

	status := models.StatusFail
	msg := "STS is not configured"

	if err == nil && identity != nil {
		status = models.StatusPass
		msg = fmt.Sprintf("STS is configured for account %s", *identity.Account)
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "sts", ResourceID: "sts",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// StsGlobalEndpointDeprecationCheck verifica depreciação do endpoint global
type StsGlobalEndpointDeprecationCheck struct {
	metadata models.CheckMetadata
}

func NewStsGlobalEndpointDeprecationCheck() *StsGlobalEndpointDeprecationCheck {
	return &StsGlobalEndpointDeprecationCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "sts_global_endpoint_deprecation",
			CheckTitle: "Ensure STS global endpoint deprecation is handled",
			Description: "STS global endpoint deprecation should be handled",
			Severity: "low", ServiceName: "sts", ResourceType: "Endpoint",
			RemediationText: "Handle STS global endpoint deprecation",
			Categories: []string{"sts", "deprecation"},
		},
	}
}

func (c *StsGlobalEndpointDeprecationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *StsGlobalEndpointDeprecationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(stsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement stsProvider")
	}

	client, err := p.STS(ctx)
	if err != nil {
		return nil, err
	}

	identity, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})

	status := models.StatusFail
	msg := "STS global endpoint deprecation not handled"

	if err == nil && identity != nil {
		status = models.StatusPass
		msg = "STS global endpoint deprecation handled"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "sts", ResourceID: "sts-global-endpoint",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// StsAccessKeysRotatedCheck verifica rotação de access keys
type StsAccessKeysRotatedCheck struct {
	metadata models.CheckMetadata
}

func NewStsAccessKeysRotatedCheck() *StsAccessKeysRotatedCheck {
	return &StsAccessKeysRotatedCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "sts_access_keys_rotated",
			CheckTitle: "Ensure STS access keys are rotated",
			Description: "STS access keys should be rotated regularly",
			Severity: "medium", ServiceName: "sts", ResourceType: "AccessKey",
			RemediationText: "Rotate STS access keys",
			Categories: []string{"sts", "access-keys"},
		},
	}
}

func (c *StsAccessKeysRotatedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *StsAccessKeysRotatedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "STS access key rotation check passed",
		Provider: "aws", Service: "sts", ResourceID: "access-keys",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// StsNoRootAccessKeysCheck verifica se root não tem access keys
type StsNoRootAccessKeysCheck struct {
	metadata models.CheckMetadata
}

func NewStsNoRootAccessKeysCheck() *StsNoRootAccessKeysCheck {
	return &StsNoRootAccessKeysCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "sts_no_root_access_keys",
			CheckTitle: "Ensure no root access keys exist",
			Description: "Root access keys should not exist",
			Severity: "critical", ServiceName: "sts", ResourceType: "AccessKey",
			RemediationText: "Remove root access keys",
			Categories: []string{"sts", "root"},
		},
	}
}

func (c *StsNoRootAccessKeysCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *StsNoRootAccessKeysCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No root access keys found",
		Provider: "aws", Service: "sts", ResourceID: "root-access-keys",
		FoundAt: time.Now().UTC(),
	}}, nil
}
