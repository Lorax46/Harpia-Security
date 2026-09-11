package config

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

type configProvider interface {
	Config(ctx context.Context) (*configservice.Client, error)
}

// ConfigConfigurationRecorderEnabled - Config configuration recorder enabled
type ConfigConfigurationRecorderEnabled struct {
	metadata models.CheckMetadata
}

func NewConfigConfigurationRecorderEnabled() *ConfigConfigurationRecorderEnabled {
	return &ConfigConfigurationRecorderEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "config_configuration_recorder_enabled",
			CheckTitle: "Config configuration recorder enabled",
			ServiceName: "config", Severity: "medium", ResourceType: "ConfigurationRecorder",
			Description: "Config configuration recorder should be enabled",
			RemediationText: "Enable Config configuration recorder",
			Categories: []string{"governance"},
		},
	}
}

func (c *ConfigConfigurationRecorderEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ConfigConfigurationRecorderEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(configProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement configProvider")
	}
	client, err := p.Config(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return nil, err
	}

	status := models.StatusFail
	msg := "Config configuration recorder is not enabled"
	if len(result.ConfigurationRecorders) > 0 {
		recorder := result.ConfigurationRecorders[0]
		if recorder.RecordingGroup != nil && recorder.RecordingGroup.AllSupported {
			status = models.StatusPass
			msg = "Config configuration recorder is enabled with all resource types"
		} else if recorder.Name != nil {
			status = models.StatusPass
			msg = "Config configuration recorder is enabled"
		}
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "config",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
		FoundAt: time.Now().UTC(),
	}}, nil
}

// ConfigConfigurationRecorderAllResourceTypes - Config all resource types
type ConfigConfigurationRecorderAllResourceTypes struct {
	metadata models.CheckMetadata
}

func NewConfigConfigurationRecorderAllResourceTypes() *ConfigConfigurationRecorderAllResourceTypes {
	return &ConfigConfigurationRecorderAllResourceTypes{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "config_configuration_recorder_all_resource_types",
			CheckTitle: "Config configuration recorder all resource types",
			ServiceName: "config", Severity: "medium", ResourceType: "ConfigurationRecorder",
			Description: "Config should record all resource types",
			RemediationText: "Enable all resource types for Config",
			Categories: []string{"governance"},
		},
	}
}

func (c *ConfigConfigurationRecorderAllResourceTypes) Metadata() models.CheckMetadata { return c.metadata }

func (c *ConfigConfigurationRecorderAllResourceTypes) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Config all resource types check requires detailed analysis",
			Provider: "aws", Service: "config",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// ConfigDeliveryChannelEnabled - Config delivery channel enabled
type ConfigDeliveryChannelEnabled struct {
	metadata models.CheckMetadata
}

func NewConfigDeliveryChannelEnabled() *ConfigDeliveryChannelEnabled {
	return &ConfigDeliveryChannelEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "config_delivery_channel_enabled",
			CheckTitle: "Config delivery channel enabled",
			ServiceName: "config", Severity: "medium", ResourceType: "DeliveryChannel",
			Description: "Config delivery channel should be enabled",
			RemediationText: "Enable Config delivery channel",
			Categories: []string{"governance"},
		},
	}
}

func (c *ConfigDeliveryChannelEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ConfigDeliveryChannelEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Config delivery channel check requires detailed analysis",
			Provider: "aws", Service: "config",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// ConfigRecorderAllRegionsEnabled - verifica gravador em todas as regiões
type ConfigRecorderAllRegionsEnabled struct {
	metadata models.CheckMetadata
}

func NewConfigRecorderAllRegionsEnabled() *ConfigRecorderAllRegionsEnabled {
	return &ConfigRecorderAllRegionsEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "config_recorder_all_regions_enabled",
			CheckTitle: "Ensure AWS Config is enabled in all regions",
			Description: "AWS Config should be enabled in all regions",
			Severity: "high", ServiceName: "config", ResourceType: "ConfigurationRecorder",
			RemediationText: "Enable AWS Config in all regions",
			Categories: []string{"config", "regions"},
		},
	}
}

func (c *ConfigRecorderAllRegionsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ConfigRecorderAllRegionsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(configProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement configProvider")
	}
	client, err := p.Config(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return nil, err
	}

	status := models.StatusFail
	msg := "AWS Config is not enabled"
	if len(result.ConfigurationRecorders) > 0 {
		status = models.StatusPass
		msg = "AWS Config is enabled"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "config-recorder", Provider: "aws", Service: "config",
		FoundAt: time.Now().UTC(),
	}}, nil
}
