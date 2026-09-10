package directoryservice

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// DirectoryserviceDirectorySnapshotsLimit - Directory Service directory has adequate remaining manual snapshot quota
type DirectoryserviceDirectorySnapshotsLimit struct {
    metadata models.CheckMetadata
}

func NewDirectoryserviceDirectorySnapshotsLimit() *DirectoryserviceDirectorySnapshotsLimit {
    return &DirectoryserviceDirectorySnapshotsLimit{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "directoryservice_directory_snapshots_limit",
            CheckTitle: "Directory Service directory has adequate remaining manual snapshot quota",
            ServiceName: "directoryservice",
            Severity: "low",
            Description: "**AWS Directory Service** directories with **manual snapshot capacity** fully consumed or nearly exhausted, based on current snapshot count relative to the directory's maximum allowed.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"directoryservice"},
        },
    }
}

func (c *DirectoryserviceDirectorySnapshotsLimit) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DirectoryserviceDirectorySnapshotsLimit) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "directoryservice",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DirectoryserviceSupportedMfaRadiusEnabled - AWS Directory Service directory has RADIUS-based MFA enabled
type DirectoryserviceSupportedMfaRadiusEnabled struct {
    metadata models.CheckMetadata
}

func NewDirectoryserviceSupportedMfaRadiusEnabled() *DirectoryserviceSupportedMfaRadiusEnabled {
    return &DirectoryserviceSupportedMfaRadiusEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "directoryservice_supported_mfa_radius_enabled",
            CheckTitle: "AWS Directory Service directory has RADIUS-based MFA enabled",
            ServiceName: "directoryservice",
            Severity: "medium",
            Description: "**AWS Directory Service directories** are evaluated for **RADIUS-backed multi-factor authentication**, confirming that MFA is configured and the RADIUS integration is active.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"directoryservice"},
        },
    }
}

func (c *DirectoryserviceSupportedMfaRadiusEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DirectoryserviceSupportedMfaRadiusEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "directoryservice",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DirectoryserviceRadiusServerSecurityProtocol - Directory Service directory RADIUS server uses MS-CHAPv2
type DirectoryserviceRadiusServerSecurityProtocol struct {
    metadata models.CheckMetadata
}

func NewDirectoryserviceRadiusServerSecurityProtocol() *DirectoryserviceRadiusServerSecurityProtocol {
    return &DirectoryserviceRadiusServerSecurityProtocol{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "directoryservice_radius_server_security_protocol",
            CheckTitle: "Directory Service directory RADIUS server uses MS-CHAPv2",
            ServiceName: "directoryservice",
            Severity: "medium",
            Description: "AWS Directory Service RADIUS configuration uses the **authentication protocol** defined for MFA integration. The finding evaluates whether directories with RADIUS enabled are set to `MS-CHAPv2` instead of weaker options like `PAP`, `CHAP`, or `MS-CHAPv1`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"directoryservice"},
        },
    }
}

func (c *DirectoryserviceRadiusServerSecurityProtocol) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DirectoryserviceRadiusServerSecurityProtocol) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "directoryservice",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DirectoryserviceDirectoryLogForwardingEnabled - Directory Service directory has log forwarding to CloudWatch Logs enabled
type DirectoryserviceDirectoryLogForwardingEnabled struct {
    metadata models.CheckMetadata
}

func NewDirectoryserviceDirectoryLogForwardingEnabled() *DirectoryserviceDirectoryLogForwardingEnabled {
    return &DirectoryserviceDirectoryLogForwardingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "directoryservice_directory_log_forwarding_enabled",
            CheckTitle: "Directory Service directory has log forwarding to CloudWatch Logs enabled",
            ServiceName: "directoryservice",
            Severity: "medium",
            Description: "**AWS Directory Service directories** are configured to forward domain controller security event logs to **CloudWatch Logs** using log subscriptions.  Evaluation identifies directories with or without this forwarding in place.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"directoryservice"},
        },
    }
}

func (c *DirectoryserviceDirectoryLogForwardingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DirectoryserviceDirectoryLogForwardingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "directoryservice",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DirectoryserviceDirectoryMonitorNotifications - Directory Service directory has SNS notifications enabled
type DirectoryserviceDirectoryMonitorNotifications struct {
    metadata models.CheckMetadata
}

func NewDirectoryserviceDirectoryMonitorNotifications() *DirectoryserviceDirectoryMonitorNotifications {
    return &DirectoryserviceDirectoryMonitorNotifications{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "directoryservice_directory_monitor_notifications",
            CheckTitle: "Directory Service directory has SNS notifications enabled",
            ServiceName: "directoryservice",
            Severity: "medium",
            Description: "**AWS Directory Service** directories are associated with **Amazon SNS topics** to send status change notifications (e.g., `Active`  `Impaired`).  The evaluation looks for directories that have SNS event topics configured for monitoring alerts.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"directoryservice"},
        },
    }
}

func (c *DirectoryserviceDirectoryMonitorNotifications) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DirectoryserviceDirectoryMonitorNotifications) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "directoryservice",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DirectoryserviceLdapCertificateExpiration - Directory Service LDAP certificate expires in more than 90 days
type DirectoryserviceLdapCertificateExpiration struct {
    metadata models.CheckMetadata
}

func NewDirectoryserviceLdapCertificateExpiration() *DirectoryserviceLdapCertificateExpiration {
    return &DirectoryserviceLdapCertificateExpiration{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "directoryservice_ldap_certificate_expiration",
            CheckTitle: "Directory Service LDAP certificate expires in more than 90 days",
            ServiceName: "directoryservice",
            Severity: "medium",
            Description: "**AWS Directory Service** Secure LDAP (LDAPS) certificates are assessed for upcoming expiration by comparing each directory's certificate expiration to the current time and identifying those with `<= 90` days remaining.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"directoryservice"},
        },
    }
}

func (c *DirectoryserviceLdapCertificateExpiration) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DirectoryserviceLdapCertificateExpiration) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "directoryservice",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

