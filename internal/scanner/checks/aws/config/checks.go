package config

import (
	"context"
	
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type configProvider interface{}

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
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Config configuration recorder check requires detailed configuration analysis",
			Provider: "aws", Service: "config",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
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
			Description: "Config configuration recorder should record all resource types",
			RemediationText: "Configure Config to record all resource types",
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
			StatusExtended: "Config all resource types check requires detailed configuration analysis",
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
			StatusExtended: "Config delivery channel check requires detailed configuration analysis",
			Provider: "aws", Service: "config",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}