package eventbridge

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
)

// EventbridgeBusCrossAccountAccess - verifica acesso cross-account
type EventbridgeBusCrossAccountAccess struct {
	metadata models.CheckMetadata
}

func NewEventbridgeBusCrossAccountAccess() *EventbridgeBusCrossAccountAccess {
	return &EventbridgeBusCrossAccountAccess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "eventbridge_bus_cross_account_access",
			CheckTitle: "Ensure EventBridge bus does not allow cross-account access",
			Description: "EventBridge buses should not allow cross-account access",
			Severity: "medium", ServiceName: "eventbridge", ResourceType: "EventBus",
			RemediationText: "Restrict cross-account access for EventBridge buses",
			Categories: []string{"eventbridge", "cross-account"},
		},
	}
}

func (c *EventbridgeBusCrossAccountAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *EventbridgeBusCrossAccountAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(eventbridgeProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement eventbridgeProvider")
	}
	client, err := p.EventBridge(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, bus := range result.EventBuses {
		status := models.StatusPass
		msg := fmt.Sprintf("EventBridge bus %s has no cross-account access", aws.ToString(bus.Name))
		policy, err := client.DescribeEventBus(ctx, &eventbridge.DescribeEventBusInput{
			Name: bus.Name,
		})
		if err == nil && policy.Policy != nil {
			policyStr := aws.ToString(policy.Policy)
			if policyStr == "*" {
				status = models.StatusFail
				msg = fmt.Sprintf("EventBridge bus %s allows cross-account access", aws.ToString(bus.Name))
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(bus.Name), Provider: "aws", Service: "eventbridge",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// EventbridgeBusExposed - verifica barramentos expostos
type EventbridgeBusExposed struct {
	metadata models.CheckMetadata
}

func NewEventbridgeBusExposed() *EventbridgeBusExposed {
	return &EventbridgeBusExposed{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "eventbridge_bus_exposed",
			CheckTitle: "Ensure EventBridge bus is not publicly exposed",
			Description: "EventBridge buses should not be publicly exposed",
			Severity: "high", ServiceName: "eventbridge", ResourceType: "EventBus",
			RemediationText: "Remove public exposure from EventBridge buses",
			Categories: []string{"eventbridge", "public"},
		},
	}
}

func (c *EventbridgeBusExposed) Metadata() models.CheckMetadata { return c.metadata }

func (c *EventbridgeBusExposed) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(eventbridgeProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement eventbridgeProvider")
	}
	client, err := p.EventBridge(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, bus := range result.EventBuses {
		status := models.StatusPass
		msg := fmt.Sprintf("EventBridge bus %s is not publicly exposed", aws.ToString(bus.Name))
		policy, err := client.DescribeEventBus(ctx, &eventbridge.DescribeEventBusInput{
			Name: bus.Name,
		})
		if err == nil && policy.Policy != nil {
			policyStr := aws.ToString(policy.Policy)
			if policyStr == "*" || policyStr == "{}" {
				status = models.StatusFail
				msg = fmt.Sprintf("EventBridge bus %s is publicly exposed", aws.ToString(bus.Name))
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(bus.Name), Provider: "aws", Service: "eventbridge",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}
