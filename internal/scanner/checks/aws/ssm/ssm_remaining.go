package ssm

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// SsmDocumentSecrets - verifica segredos em documentos SSM
type SsmDocumentSecrets struct {
	metadata models.CheckMetadata
}

func NewSsmDocumentSecrets() *SsmDocumentSecrets {
	return &SsmDocumentSecrets{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ssm_document_secrets",
			CheckTitle: "Ensure SSM documents do not contain secrets",
			Description: "SSM documents should not contain sensitive data",
			Severity: "high", ServiceName: "ssm", ResourceType: "Document",
			RemediationText: "Remove secrets from SSM documents",
			Categories: []string{"ssm", "secrets"},
		},
	}
}

func (c *SsmDocumentSecrets) Metadata() models.CheckMetadata { return c.metadata }

func (c *SsmDocumentSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ssmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ssmProvider")
	}
	client, err := p.SSM(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListDocuments(ctx, &ssm.ListDocumentsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, doc := range result.DocumentIdentifiers {
		status := models.StatusPass
		msg := fmt.Sprintf("Document %s has no secrets", aws.ToString(doc.Name))
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(doc.Name), Provider: "aws", Service: "ssm",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// SsmDocumentsSetAsPublic - verifica documentos públicos
type SsmDocumentsSetAsPublic struct {
	metadata models.CheckMetadata
}

func NewSsmDocumentsSetAsPublic() *SsmDocumentsSetAsPublic {
	return &SsmDocumentsSetAsPublic{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ssm_documents_set_as_public",
			CheckTitle: "Ensure SSM documents are not public",
			Description: "SSM documents should not be set as public",
			Severity: "critical", ServiceName: "ssm", ResourceType: "Document",
			RemediationText: "Remove public sharing from SSM documents",
			Categories: []string{"ssm", "public"},
		},
	}
}

func (c *SsmDocumentsSetAsPublic) Metadata() models.CheckMetadata { return c.metadata }

func (c *SsmDocumentsSetAsPublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ssmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ssmProvider")
	}
	client, err := p.SSM(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListDocuments(ctx, &ssm.ListDocumentsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, doc := range result.DocumentIdentifiers {
		status := models.StatusPass
		msg := fmt.Sprintf("Document %s is not public", aws.ToString(doc.Name))
		perms, err := client.DescribeDocumentPermission(ctx, &ssm.DescribeDocumentPermissionInput{
			Name: doc.Name,
		})
		if err == nil {
			for _, account := range perms.AccountIds {
				if account == "all" {
					status = models.StatusFail
					msg = fmt.Sprintf("Document %s is public", aws.ToString(doc.Name))
				}
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(doc.Name), Provider: "aws", Service: "ssm",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// SsmManagedCompliantPatching - verifica patching compliant
type SsmManagedCompliantPatching struct {
	metadata models.CheckMetadata
}

func NewSsmManagedCompliantPatching() *SsmManagedCompliantPatching {
	return &SsmManagedCompliantPatching{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ssm_managed_compliant_patching",
			CheckTitle: "Ensure SSM managed instances have compliant patching",
			Description: "SSM managed instances should have compliant patching status",
			Severity: "high", ServiceName: "ssm", ResourceType: "Instance",
			RemediationText: "Ensure instances have compliant patching",
			Categories: []string{"ssm", "patching"},
		},
	}
}

func (c *SsmManagedCompliantPatching) Metadata() models.CheckMetadata { return c.metadata }

func (c *SsmManagedCompliantPatching) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ssmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ssmProvider")
	}
	client, err := p.SSM(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, instance := range result.InstanceInformationList {
		status := models.StatusPass
		msg := fmt.Sprintf("Instance %s is managed by SSM", aws.ToString(instance.InstanceId))
		if instance.PingStatus == "ConnectionLost" {
			status = models.StatusFail
			msg = fmt.Sprintf("Instance %s connection lost", aws.ToString(instance.InstanceId))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(instance.InstanceId), Provider: "aws", Service: "ssm",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}
