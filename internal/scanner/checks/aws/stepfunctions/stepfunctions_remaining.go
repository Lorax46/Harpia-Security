package stepfunctions

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
)

// StepfunctionsStateMachineEncryptedWithCmk - verifica criptografia CMK
type StepfunctionsStateMachineEncryptedWithCmk struct {
	metadata models.CheckMetadata
}

func NewStepfunctionsStateMachineEncryptedWithCmk() *StepfunctionsStateMachineEncryptedWithCmk {
	return &StepfunctionsStateMachineEncryptedWithCmk{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "stepfunctions_statemachine_encrypted_with_cmk",
			CheckTitle: "Ensure Step Functions state machine is encrypted with CMK",
			Description: "Step Functions state machines should be encrypted with a customer-managed KMS key",
			Severity: "medium", ServiceName: "stepfunctions", ResourceType: "StateMachine",
			RemediationText: "Enable CMK encryption for Step Functions",
			Categories: []string{"stepfunctions", "encryption"},
		},
	}
}

func (c *StepfunctionsStateMachineEncryptedWithCmk) Metadata() models.CheckMetadata { return c.metadata }

func (c *StepfunctionsStateMachineEncryptedWithCmk) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(stepfunctionsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement stepfunctionsProvider")
	}
	client, err := p.StepFunctions(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListStateMachines(ctx, &sfn.ListStateMachinesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, sm := range result.StateMachines {
		status := models.StatusPass
		msg := fmt.Sprintf("State machine %s is encrypted with CMK", aws.ToString(sm.Name))
		// Descrever para obter configuração de criptografia
		desc, err := client.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
			StateMachineArn: sm.StateMachineArn,
		})
		if err == nil && desc.EncryptionConfiguration != nil && aws.ToString(desc.EncryptionConfiguration.KmsKeyId) != "" {
			status = models.StatusPass
		} else if desc.EncryptionConfiguration == nil {
			status = models.StatusFail
			msg = fmt.Sprintf("State machine %s is not encrypted with CMK", aws.ToString(sm.Name))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(sm.Name), Provider: "aws", Service: "stepfunctions",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// StepfunctionsStateMachineNoSecretsInDefinition - verifica segredos na definição
type StepfunctionsStateMachineNoSecretsInDefinition struct {
	metadata models.CheckMetadata
}

func NewStepfunctionsStateMachineNoSecretsInDefinition() *StepfunctionsStateMachineNoSecretsInDefinition {
	return &StepfunctionsStateMachineNoSecretsInDefinition{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "stepfunctions_statemachine_no_secrets_in_definition",
			CheckTitle: "Ensure Step Functions state machine definition has no secrets",
			Description: "Step Functions state machine definitions should not contain secrets",
			Severity: "high", ServiceName: "stepfunctions", ResourceType: "StateMachine",
			RemediationText: "Remove secrets from Step Functions state machine definitions",
			Categories: []string{"stepfunctions", "secrets"},
		},
	}
}

func (c *StepfunctionsStateMachineNoSecretsInDefinition) Metadata() models.CheckMetadata { return c.metadata }

func (c *StepfunctionsStateMachineNoSecretsInDefinition) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(stepfunctionsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement stepfunctionsProvider")
	}
	client, err := p.StepFunctions(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListStateMachines(ctx, &sfn.ListStateMachinesInput{})
	if err != nil {
		return nil, err
	}

	secretPatterns := []string{"password", "secret", "api_key", "apikey", "token", "access_key", "private_key"}
	findings := []models.Finding{}
	for _, sm := range result.StateMachines {
		status := models.StatusPass
		msg := fmt.Sprintf("State machine %s has no secrets", aws.ToString(sm.Name))
		desc, err := client.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
			StateMachineArn: sm.StateMachineArn,
		})
		if err == nil && desc.Definition != nil {
			def := aws.ToString(desc.Definition)
			for _, pattern := range secretPatterns {
				if strings.Contains(strings.ToLower(def), pattern) {
					status = models.StatusFail
					msg = fmt.Sprintf("State machine %s contains secrets", aws.ToString(sm.Name))
					break
				}
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(sm.Name), Provider: "aws", Service: "stepfunctions",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}
