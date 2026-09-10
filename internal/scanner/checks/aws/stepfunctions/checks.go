package stepfunctions

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfnTypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type stepfunctionsProvider interface {
	StepFunctions(ctx context.Context) (*sfn.Client, error)
}

// StepfunctionsStateMachineLoggingEnabled - Step Functions logging enabled
type StepfunctionsStateMachineLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewStepfunctionsStateMachineLoggingEnabled() *StepfunctionsStateMachineLoggingEnabled {
	return &StepfunctionsStateMachineLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "stepfunctions_state_machine_logging_enabled",
			CheckTitle: "Step Functions logging enabled",
			ServiceName: "stepfunctions", Severity: "medium", ResourceType: "StateMachine",
			Description: "Step Functions should have logging enabled",
			RemediationText: "Enable logging on Step Functions",
			Categories: []string{"compute", "logging"},
		},
	}
}

func (c *StepfunctionsStateMachineLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *StepfunctionsStateMachineLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(stepfunctionsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement stepfunctionsProvider")
	}
	sfnClient, err := p.StepFunctions(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	machines, err := sfnClient.ListStateMachines(ctx, &sfn.ListStateMachinesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list state machines: %w", err)
	}

	for _, machine := range machines.StateMachines {
		machineARN := aws.ToString(machine.StateMachineArn)
		machineName := aws.ToString(machine.Name)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("State machine %s does not have logging enabled.", machineName)

		details, err := sfnClient.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
			StateMachineArn: machine.StateMachineArn,
		})
		if err == nil && details.LoggingConfiguration != nil {
			level := details.LoggingConfiguration.Level
			if level != sfnTypes.LogLevelOff {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("State machine %s has logging enabled (level: %s).", machineName, string(level))
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "stepfunctions", ResourceID: machineName,
			ResourceARN: machineARN,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// StepfunctionsStateMachineTracingEnabled - Step Functions tracing enabled
type StepfunctionsStateMachineTracingEnabled struct {
	metadata models.CheckMetadata
}

func NewStepfunctionsStateMachineTracingEnabled() *StepfunctionsStateMachineTracingEnabled {
	return &StepfunctionsStateMachineTracingEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "stepfunctions_state_machine_tracing_enabled",
			CheckTitle: "Step Functions tracing enabled",
			ServiceName: "stepfunctions", Severity: "low", ResourceType: "StateMachine",
			Description: "Step Functions should have tracing enabled",
			RemediationText: "Enable tracing on Step Functions",
			Categories: []string{"compute"},
		},
	}
}

func (c *StepfunctionsStateMachineTracingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *StepfunctionsStateMachineTracingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(stepfunctionsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement stepfunctionsProvider")
	}
	sfnClient, err := p.StepFunctions(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	machines, err := sfnClient.ListStateMachines(ctx, &sfn.ListStateMachinesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list state machines: %w", err)
	}

	for _, machine := range machines.StateMachines {
		machineARN := aws.ToString(machine.StateMachineArn)
		machineName := aws.ToString(machine.Name)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("State machine %s does not have tracing enabled.", machineName)

		details, err := sfnClient.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
			StateMachineArn: machine.StateMachineArn,
		})
		if err == nil && details.TracingConfiguration != nil {
			if details.TracingConfiguration.Enabled {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("State machine %s has tracing enabled.", machineName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "stepfunctions", ResourceID: machineName,
			ResourceARN: machineARN,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// StepfunctionsStateMachineEncrypted - Step Functions encrypted
type StepfunctionsStateMachineEncrypted struct {
	metadata models.CheckMetadata
}

func NewStepfunctionsStateMachineEncrypted() *StepfunctionsStateMachineEncrypted {
	return &StepfunctionsStateMachineEncrypted{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "stepfunctions_state_machine_encrypted",
			CheckTitle: "Step Functions encrypted",
			ServiceName: "stepfunctions", Severity: "medium", ResourceType: "StateMachine",
			Description: "Step Functions should be encrypted",
			RemediationText: "Enable encryption on Step Functions",
			Categories: []string{"compute", "encryption"},
		},
	}
}

func (c *StepfunctionsStateMachineEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *StepfunctionsStateMachineEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(stepfunctionsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement stepfunctionsProvider")
	}
	sfnClient, err := p.StepFunctions(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	machines, err := sfnClient.ListStateMachines(ctx, &sfn.ListStateMachinesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list state machines: %w", err)
	}

	for _, machine := range machines.StateMachines {
		machineARN := aws.ToString(machine.StateMachineArn)
		machineName := aws.ToString(machine.Name)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("State machine %s does not have encryption enabled.", machineName)

		details, err := sfnClient.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
			StateMachineArn: machine.StateMachineArn,
		})
		if err == nil && details.EncryptionConfiguration != nil {
			if details.EncryptionConfiguration.Type != "" {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("State machine %s has encryption enabled (type: %s).", machineName, string(details.EncryptionConfiguration.Type))
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "stepfunctions", ResourceID: machineName,
			ResourceARN: machineARN,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}