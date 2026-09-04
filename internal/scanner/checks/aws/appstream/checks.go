package appstream

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// AppstreamFleetDefaultInternetAccessDisabled - AppStream fleet has default internet access disabled
type AppstreamFleetDefaultInternetAccessDisabled struct {
    metadata models.CheckMetadata
}

func NewAppstreamFleetDefaultInternetAccessDisabled() *AppstreamFleetDefaultInternetAccessDisabled {
    return &AppstreamFleetDefaultInternetAccessDisabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "appstream_fleet_default_internet_access_disabled",
            CheckTitle: "AppStream fleet has default internet access disabled",
            ServiceName: "appstream",
            Severity: "medium",
            Description: "**Amazon AppStream fleets** are assessed for the `EnableDefaultInternetAccess` setting, identifying fleets where streaming instances have default Internet connectivity.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"appstream"},
        },
    }
}

func (c *AppstreamFleetDefaultInternetAccessDisabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AppstreamFleetDefaultInternetAccessDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "appstream",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AppstreamFleetSessionDisconnectTimeout - AppStream fleet session disconnect timeout is 5 minutes or less
type AppstreamFleetSessionDisconnectTimeout struct {
    metadata models.CheckMetadata
}

func NewAppstreamFleetSessionDisconnectTimeout() *AppstreamFleetSessionDisconnectTimeout {
    return &AppstreamFleetSessionDisconnectTimeout{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "appstream_fleet_session_disconnect_timeout",
            CheckTitle: "AppStream fleet session disconnect timeout is 5 minutes or less",
            ServiceName: "appstream",
            Severity: "medium",
            Description: "**AppStream fleets** are evaluated for `DisconnectTimeoutInSeconds` being at or below `300` seconds (5 minutes), which defines how long a streaming session remains active after a user disconnects.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"appstream"},
        },
    }
}

func (c *AppstreamFleetSessionDisconnectTimeout) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AppstreamFleetSessionDisconnectTimeout) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "appstream",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AppstreamFleetMaximumSessionDuration - AppStream fleet maximum user session duration is less than 10 hours
type AppstreamFleetMaximumSessionDuration struct {
    metadata models.CheckMetadata
}

func NewAppstreamFleetMaximumSessionDuration() *AppstreamFleetMaximumSessionDuration {
    return &AppstreamFleetMaximumSessionDuration{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "appstream_fleet_maximum_session_duration",
            CheckTitle: "AppStream fleet maximum user session duration is less than 10 hours",
            ServiceName: "appstream",
            Severity: "medium",
            Description: "**AppStream fleets** enforce a **maximum user session duration**. This finding evaluates each fleet's configured limit against a threshold-default `10 hours` (`36000` seconds)-and identifies fleets whose session duration exceeds that limit.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"appstream"},
        },
    }
}

func (c *AppstreamFleetMaximumSessionDuration) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AppstreamFleetMaximumSessionDuration) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "appstream",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AppstreamFleetSessionIdleDisconnectTimeout - AppStream fleet session idle disconnect timeout is 10 minutes or less
type AppstreamFleetSessionIdleDisconnectTimeout struct {
    metadata models.CheckMetadata
}

func NewAppstreamFleetSessionIdleDisconnectTimeout() *AppstreamFleetSessionIdleDisconnectTimeout {
    return &AppstreamFleetSessionIdleDisconnectTimeout{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "appstream_fleet_session_idle_disconnect_timeout",
            CheckTitle: "AppStream fleet session idle disconnect timeout is 10 minutes or less",
            ServiceName: "appstream",
            Severity: "medium",
            Description: "**Amazon AppStream fleets** are evaluated for the **idle disconnect timeout** setting, confirming it is configured to `10 minutes` (`<=600s`) or less before inactive users are dropped and the session's `disconnect_timeout` window begins.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"appstream"},
        },
    }
}

func (c *AppstreamFleetSessionIdleDisconnectTimeout) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AppstreamFleetSessionIdleDisconnectTimeout) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "appstream",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

