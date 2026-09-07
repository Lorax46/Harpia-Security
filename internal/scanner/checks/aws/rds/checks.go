package rds

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

type rdsProvider interface {
	RDS(ctx context.Context) (*rds.Client, error)
	Region() string
	AccountID() string
}

// PublicAccessCheck verifica se instâncias RDS não são publicamente acessíveis
type PublicAccessCheck struct {
	metadata models.CheckMetadata
}

func NewPublicAccessCheck() *PublicAccessCheck {
	return &PublicAccessCheck{
		metadata: models.CheckMetadata{
			Provider:         "aws",
			CheckID:          "rds_instance_not_publicly_accessible",
			CheckTitle:       "Ensure RDS instances are not publicly accessible to the internet",
			Description:      "RDS instances should not be publicly accessible to the internet",
			Severity:         "critical",
			ServiceName:      "rds",
			ResourceType:     "RDS Instance",
			ResourceGroup:    "Database",
			RemediationText:  "Set PubliclyAccessible to false",
			RemediationURL:   "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
			Categories:       []string{"database"},
			Risk:             "Publicly accessible RDS instances can be reached by attackers and expose sensitive data",
			RelatedURL:       "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CreateDBInstance.html",
		},
	}
}

func (c *PublicAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PublicAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}

	client, err := p.RDS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get RDS client: %w", err)
	}

	findings := []models.Finding{}
	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe DB instances: %w", err)
		}

		for _, instance := range page.DBInstances {
			status := models.StatusPass
			msg := fmt.Sprintf("RDS instance %s is not publicly accessible", *instance.DBInstanceIdentifier)
			if instance.PubliclyAccessible != nil && *instance.PubliclyAccessible {
				status = models.StatusFail
				msg = fmt.Sprintf("RDS instance %s is publicly accessible", *instance.DBInstanceIdentifier)
			}

			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  msg,
				Provider:        "aws",
				Service:         "rds",
				ResourceID:      *instance.DBInstanceIdentifier,
				ResourceARN:     *instance.DBInstanceArn,
				Region:          p.Region(),
				Remediation:     c.metadata.RemediationText,
				RemediationURL:  c.metadata.RemediationURL,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// EncryptionCheck verifica se instâncias RDS têm criptografia em repouso habilitada
type EncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewEncryptionCheck() *EncryptionCheck {
	return &EncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:         "aws",
			CheckID:          "rds_instance_encryption_enabled",
			CheckTitle:       "Ensure RDS instances have encryption at rest enabled",
			Description:      "RDS instances should have encryption at rest enabled",
			Severity:         "high",
			ServiceName:      "rds",
			ResourceType:     "RDS Instance",
			ResourceGroup:    "Database",
			RemediationText:  "Enable StorageEncrypted for RDS instances",
			RemediationURL:   "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
			Categories:       []string{"database"},
			Risk:             "Unencrypted data at rest can be compromised",
			RelatedURL:       "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CreateDBInstance.html",
		},
	}
}

func (c *EncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}

	client, err := p.RDS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get RDS client: %w", err)
	}

	findings := []models.Finding{}
	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe DB instances: %w", err)
		}

		for _, instance := range page.DBInstances {
			status := models.StatusPass
			msg := fmt.Sprintf("RDS instance %s has encryption enabled", *instance.DBInstanceIdentifier)
			if instance.StorageEncrypted == nil || !*instance.StorageEncrypted {
				status = models.StatusFail
				msg = fmt.Sprintf("RDS instance %s does not have encryption enabled", *instance.DBInstanceIdentifier)
			}

			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  msg,
				Provider:        "aws",
				Service:         "rds",
				ResourceID:      *instance.DBInstanceIdentifier,
				ResourceARN:     *instance.DBInstanceArn,
				Region:          p.Region(),
				Remediation:     c.metadata.RemediationText,
				RemediationURL:  c.metadata.RemediationURL,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// AutoMinorUpgradeCheck verifica se instâncias RDS têm upgrade automático de versão menor habilitado
type AutoMinorUpgradeCheck struct {
	metadata models.CheckMetadata
}

func NewAutoMinorUpgradeCheck() *AutoMinorUpgradeCheck {
	return &AutoMinorUpgradeCheck{
		metadata: models.CheckMetadata{
			Provider:         "aws",
			CheckID:          "rds_instance_auto_minor_version_upgrade_enabled",
			CheckTitle:       "Ensure RDS instances have auto minor version upgrade enabled",
			Description:      "RDS instances should have auto minor version upgrade enabled",
			Severity:         "medium",
			ServiceName:      "rds",
			ResourceType:     "RDS Instance",
			ResourceGroup:    "Database",
			RemediationText:  "Enable AutoMinorVersionUpgrade for RDS instances",
			RemediationURL:   "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html",
			Categories:       []string{"database"},
			Risk:             "Manual upgrades can leave instances vulnerable to security issues",
			RelatedURL:       "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CreateDBInstance.html",
		},
	}
}

func (c *AutoMinorUpgradeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoMinorUpgradeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}

	client, err := p.RDS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get RDS client: %w", err)
	}

	findings := []models.Finding{}
	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe DB instances: %w", err)
		}

		for _, instance := range page.DBInstances {
			status := models.StatusPass
			msg := fmt.Sprintf("RDS instance %s has auto minor version upgrade enabled", *instance.DBInstanceIdentifier)
			if instance.AutoMinorVersionUpgrade == nil || !*instance.AutoMinorVersionUpgrade {
				status = models.StatusFail
				msg = fmt.Sprintf("RDS instance %s does not have auto minor version upgrade enabled", *instance.DBInstanceIdentifier)
			}

			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  msg,
				Provider:        "aws",
				Service:         "rds",
				ResourceID:      *instance.DBInstanceIdentifier,
				ResourceARN:     *instance.DBInstanceArn,
				Region:          p.Region(),
				Remediation:     c.metadata.RemediationText,
				RemediationURL:  c.metadata.RemediationURL,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// DeletionProtectionCheck verifica se instâncias RDS têm proteção contra exclusão habilitada
type DeletionProtectionCheck struct {
	metadata models.CheckMetadata
}

func NewDeletionProtectionCheck() *DeletionProtectionCheck {
	return &DeletionProtectionCheck{
		metadata: models.CheckMetadata{
			Provider:         "aws",
			CheckID:          "rds_instance_deletion_protection_enabled",
			CheckTitle:       "Ensure RDS instances have deletion protection enabled",
			Description:      "RDS instances should have deletion protection enabled",
			Severity:         "high",
			ServiceName:      "rds",
			ResourceType:     "RDS Instance",
			ResourceGroup:    "Database",
			RemediationText:  "Enable DeletionProtection for RDS instances",
			RemediationURL:   "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html",
			Categories:       []string{"database"},
			Risk:             "Instances without deletion protection can be accidentally deleted",
			RelatedURL:       "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CreateDBInstance.html",
		},
	}
}

func (c *DeletionProtectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DeletionProtectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}

	client, err := p.RDS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get RDS client: %w", err)
	}

	findings := []models.Finding{}
	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe DB instances: %w", err)
		}

		for _, instance := range page.DBInstances {
			status := models.StatusPass
			msg := fmt.Sprintf("RDS instance %s has deletion protection enabled", *instance.DBInstanceIdentifier)
			if instance.DeletionProtection == nil || !*instance.DeletionProtection {
				status = models.StatusFail
				msg = fmt.Sprintf("RDS instance %s does not have deletion protection enabled", *instance.DBInstanceIdentifier)
			}

			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  msg,
				Provider:        "aws",
				Service:         "rds",
				ResourceID:      *instance.DBInstanceIdentifier,
				ResourceARN:     *instance.DBInstanceArn,
				Region:          p.Region(),
				Remediation:     c.metadata.RemediationText,
				RemediationURL:  c.metadata.RemediationURL,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// MultiAzCheck verifica se instâncias RDS têm Multi-AZ habilitado para alta disponibilidade
type MultiAzCheck struct {
	metadata models.CheckMetadata
}

func NewMultiAzCheck() *MultiAzCheck {
	return &MultiAzCheck{
		metadata: models.CheckMetadata{
			Provider:         "aws",
			CheckID:          "rds_instance_multi_az_enabled",
			CheckTitle:       "Ensure RDS instances have Multi-AZ enabled for high availability",
			Description:      "RDS instances should have Multi-AZ enabled for high availability",
			Severity:         "medium",
			ServiceName:      "rds",
			ResourceType:     "RDS Instance",
			ResourceGroup:    "Database",
			RemediationText:  "Enable Multi-AZ for RDS instances",
			RemediationURL:   "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html",
			Categories:       []string{"database"},
			RelatedURL:       "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CreateDBInstance.html",
		},
	}
}

func (c *MultiAzCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MultiAzCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}

	client, err := p.RDS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get RDS client: %w", err)
	}

	findings := []models.Finding{}
	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe DB instances: %w", err)
		}

		for _, instance := range page.DBInstances {
			status := models.StatusPass
			msg := fmt.Sprintf("RDS instance %s has Multi-AZ enabled", *instance.DBInstanceIdentifier)
			if instance.MultiAZ == nil || !*instance.MultiAZ {
				status = models.StatusFail
				msg = fmt.Sprintf("RDS instance %s does not have Multi-AZ enabled", *instance.DBInstanceIdentifier)
			}

			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  msg,
				Provider:        "aws",
				Service:         "rds",
				ResourceID:      *instance.DBInstanceIdentifier,
				ResourceARN:     *instance.DBInstanceArn,
				Region:          p.Region(),
				Remediation:     c.metadata.RemediationText,
				RemediationURL:  c.metadata.RemediationURL,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// AllChecks retorna todos os checks RDS disponíveis
func AllChecks() []interface {
	Metadata() models.CheckMetadata
	Execute(ctx context.Context, provider interface{}) ([]models.Finding, error)
} {
	return []interface {
		Metadata() models.CheckMetadata
		Execute(ctx context.Context, provider interface{}) ([]models.Finding, error)
	}{
		NewPublicAccessCheck(),
		NewEncryptionCheck(),
		NewAutoMinorUpgradeCheck(),
		NewDeletionProtectionCheck(),
		NewMultiAzCheck(),
	}
}

// InstanceCertificateExpiration - RDS instance SSL/TLS certificate has more than 3 months of validity remaining
type InstanceCertificateExpiration struct {
	metadata models.CheckMetadata
}

func NewInstanceCertificateExpiration() *InstanceCertificateExpiration {
	return &InstanceCertificateExpiration{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_certificate_expiration",
			CheckTitle:      "RDS instance SSL/TLS certificate has more than 3 months of validity remaining",
			ServiceName:     "rds",
			Severity:        "high",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are evaluated for **server certificate validity** windows, including default and **customer-managed certificates**. Certificates **expired** or **approaching expiration** (e.g., `<1 month`, `<3 months`, `3-6 months`, `>6 months`) are identified using the certificate `valid_till` date.",
			RemediationText: "Establish a **certificate lifecycle** for RDS: - Rotate server/CA certs well before expiry; avoid pinned or outdated CAs - Keep client trust stores current and enforce TLS with validation - Monitor expiry and automate alerts/rotation - For custom certs, apply **least privilege**, **separation of duties**, and periodic key rotation; test changes",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceCertificateExpiration) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceCertificateExpiration) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_certificate_expiration
	_ = client

	return findings, nil
}

// InstanceDeletionProtection - RDS instance has deletion protection enabled
type InstanceDeletionProtection struct {
	metadata models.CheckMetadata
}

func NewInstanceDeletionProtection() *InstanceDeletionProtection {
	return &InstanceDeletionProtection{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_deletion_protection",
			CheckTitle:      "RDS instance has deletion protection enabled",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are assessed for **deletion protection**. If an instance belongs to an Aurora cluster, the setting is evaluated at the cluster level; otherwise, it is evaluated on the instance itself.",
			RemediationText: "Enable `deletion protection` on production RDS instances and Aurora clusters. Enforce **least privilege** for delete/modify actions and require change control to disable protection. Use **defense in depth** with reliable backups and tested restores to limit impact if a deletion occurs.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceDeletionProtection) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceDeletionProtection) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_deletion_protection
	_ = client

	return findings, nil
}

// ClusterCriticalEventSubscription - RDS cluster event subscription is enabled for maintenance and failure categories
type ClusterCriticalEventSubscription struct {
	metadata models.CheckMetadata
}

func NewClusterCriticalEventSubscription() *ClusterCriticalEventSubscription {
	return &ClusterCriticalEventSubscription{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_cluster_critical_event_subscription",
			CheckTitle:      "RDS cluster event subscription is enabled for maintenance and failure categories",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsEventSubscription",
			Description:     "**RDS event subscriptions** for the `db-cluster` source type are enabled and cover critical cluster event categories: **`maintenance`** and **`failure`** (or all cluster events).",
			RemediationText: "Enable **event subscriptions** for RDS clusters that include `maintenance` and `failure`, delivered via **SNS** to monitored channels. - Enforce **least privilege** on topics - Separate topics per environment - Integrate with on-call/IR playbooks and test alerts - Add multiple recipients and escalation for **defense in depth**",
			Categories:      []string{"rds"},
		},
	}
}

func (c *ClusterCriticalEventSubscription) Metadata() models.CheckMetadata { return c.metadata }

func (c *ClusterCriticalEventSubscription) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_cluster_critical_event_subscription
	_ = client

	return findings, nil
}

// ClusterCopyTagsToSnapshots - RDS DB cluster has copy tags to snapshots enabled
type ClusterCopyTagsToSnapshots struct {
	metadata models.CheckMetadata
}

func NewClusterCopyTagsToSnapshots() *ClusterCopyTagsToSnapshots {
	return &ClusterCopyTagsToSnapshots{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_cluster_copy_tags_to_snapshots",
			CheckTitle:      "RDS DB cluster has copy tags to snapshots enabled",
			ServiceName:     "rds",
			Severity:        "low",
			ResourceType:    "AwsRdsDbCluster",
			Description:     "**RDS DB clusters** are evaluated for the `CopyTagsToSnapshot` setting that propagates cluster tags to their DB snapshots. *Aurora tagging is configured at the cluster level; instance-level copying isn't supported.*",
			RemediationText: "Enable `CopyTagsToSnapshot` on all applicable **RDS/Aurora clusters**. - Standardize required tags (owner, environment, data class) - Use **least privilege** and **ABAC** based on tags - Automate tagging and periodic audits so snapshots inherit metadata and lifecycle policies",
			Categories:      []string{"rds"},
		},
	}
}

func (c *ClusterCopyTagsToSnapshots) Metadata() models.CheckMetadata { return c.metadata }

func (c *ClusterCopyTagsToSnapshots) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_cluster_copy_tags_to_snapshots
	_ = client

	return findings, nil
}

// InstanceDeprecatedEngineVersion - RDS instance uses a supported engine version
type InstanceDeprecatedEngineVersion struct {
	metadata models.CheckMetadata
}

func NewInstanceDeprecatedEngineVersion() *InstanceDeprecatedEngineVersion {
	return &InstanceDeprecatedEngineVersion{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_deprecated_engine_version",
			CheckTitle:      "RDS instance uses a supported engine version",
			ServiceName:     "rds",
			Severity:        "high",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** use a **supported, non-deprecated engine version** for MariaDB, MySQL, or PostgreSQL. The instance's `engine` and `engine_version` are evaluated against versions currently supported in the region.",
			RemediationText: "Standardize on **supported engine versions** and keep them current. - Plan and test upgrades; back up and define rollback - Enable `AutoMinorVersionUpgrade` where acceptable - Monitor deprecation notices and upgrade before EoS - Enforce **least privilege** to limit blast radius during incidents",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceDeprecatedEngineVersion) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceDeprecatedEngineVersion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_deprecated_engine_version
	_ = client

	return findings, nil
}

// InstanceInsideVpc - RDS instance is deployed in a VPC
type InstanceInsideVpc struct {
	metadata models.CheckMetadata
}

func NewInstanceInsideVpc() *InstanceInsideVpc {
	return &InstanceInsideVpc{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_inside_vpc",
			CheckTitle:      "RDS instance is deployed in a VPC",
			ServiceName:     "rds",
			Severity:        "high",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are assessed for **VPC placement** by the presence of a `vpc_id` indicating deployment within a VPC. Instances without this association are treated as outside VPC networking.",
			RemediationText: "Deploy all RDS instances in a **VPC**, preferably in **private subnets**. Enforce **least privilege** with security groups, network ACLs, and restrictive routing. Use private connectivity (peering, VPN, Direct Connect), avoid public exposure, and apply **defense in depth** through segmentation and monitoring.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceInsideVpc) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceInsideVpc) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_inside_vpc
	_ = client

	return findings, nil
}

// ClusterDefaultAdmin - RDS cluster master username is not admin or postgres
type ClusterDefaultAdmin struct {
	metadata models.CheckMetadata
}

func NewClusterDefaultAdmin() *ClusterDefaultAdmin {
	return &ClusterDefaultAdmin{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_cluster_default_admin",
			CheckTitle:      "RDS cluster master username is not admin or postgres",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbCluster",
			Description:     "RDS DB clusters are evaluated for use of a **custom administrator username**, flagging clusters that use defaults such as `admin` or `postgres`.",
			RemediationText: "Create databases with a **unique, non-default admin username** that doesn't reveal environment or org. Apply **least privilege** by using separate, non-admin accounts for applications. Prefer **IAM database authentication** and manage secrets centrally with rotation. Restrict admin access and monitor login attempts.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *ClusterDefaultAdmin) Metadata() models.CheckMetadata { return c.metadata }

func (c *ClusterDefaultAdmin) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_cluster_default_admin
	_ = client

	return findings, nil
}

// InstanceEnhancedMonitoringEnabled - RDS instance has enhanced monitoring enabled
type InstanceEnhancedMonitoringEnabled struct {
	metadata models.CheckMetadata
}

func NewInstanceEnhancedMonitoringEnabled() *InstanceEnhancedMonitoringEnabled {
	return &InstanceEnhancedMonitoringEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_enhanced_monitoring_enabled",
			CheckTitle:      "RDS instance has enhanced monitoring enabled",
			ServiceName:     "rds",
			Severity:        "low",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are evaluated for **Enhanced Monitoring** being enabled, which publishes real-time **OS-level metrics** (CPU, memory, disk, network) to CloudWatch Logs for each instance.",
			RemediationText: "Enable **Enhanced Monitoring** on RDS, using a `>0s` collection interval aligned to workload and cost. Assign a **least-privilege** role for log delivery, and apply **defense in depth** by centralizing logs, setting **alerts** on key OS metrics, and defining **retention** to support incident response and trend analysis.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceEnhancedMonitoringEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceEnhancedMonitoringEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_enhanced_monitoring_enabled
	_ = client

	return findings, nil
}

// InstanceIamAuthenticationEnabled - RDS instance has IAM database authentication enabled
type InstanceIamAuthenticationEnabled struct {
	metadata models.CheckMetadata
}

func NewInstanceIamAuthenticationEnabled() *InstanceIamAuthenticationEnabled {
	return &InstanceIamAuthenticationEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_iam_authentication_enabled",
			CheckTitle:      "RDS instance has IAM database authentication enabled",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** using MySQL, MariaDB, or PostgreSQL engines (including Aurora variants) have **IAM database authentication** enabled at the instance level or, when part of a cluster, evaluated for cluster-level enablement.",
			RemediationText: "Enable **IAM database authentication** for supported engines and apply **least privilege** with scoped IAM policies. Prefer **short-lived tokens** over static DB passwords, enforce TLS, and phase out embedded credentials. Monitor authentication activity with audit logs for **defense in depth**.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceIamAuthenticationEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceIamAuthenticationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_iam_authentication_enabled
	_ = client

	return findings, nil
}

// InstanceEventSubscriptionSecurityGroups - RDS event subscription for DB security groups is enabled for configuration change and failure events
type InstanceEventSubscriptionSecurityGroups struct {
	metadata models.CheckMetadata
}

func NewInstanceEventSubscriptionSecurityGroups() *InstanceEventSubscriptionSecurityGroups {
	return &InstanceEventSubscriptionSecurityGroups{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_event_subscription_security_groups",
			CheckTitle:      "RDS event subscription for DB security groups is enabled for configuration change and failure events",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsEventSubscription",
			Description:     "**RDS event subscriptions** are evaluated for **database security group** events. The check expects an enabled subscription with source type `db-security-group` that includes the `configuration change` and `failure` event categories.",
			RemediationText: "Create or update an **RDS event subscription** for source type `db-security-group` including `configuration change` and `failure`. Route alerts to monitored channels, restrict topic access (**least privilege**), integrate with **incident response**, and enforce change control and **separation of duties** for security group updates.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceEventSubscriptionSecurityGroups) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceEventSubscriptionSecurityGroups) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_event_subscription_security_groups
	_ = client

	return findings, nil
}

// InstanceNoPublicAccess - RDS instance is not publicly exposed to the Internet
type InstanceNoPublicAccess struct {
	metadata models.CheckMetadata
}

func NewInstanceNoPublicAccess() *InstanceNoPublicAccess {
	return &InstanceNoPublicAccess{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_no_public_access",
			CheckTitle:      "RDS instance is not publicly exposed to the Internet",
			ServiceName:     "rds",
			Severity:        "critical",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are assessed for **internet exposure** using the `PubliclyAccessible` setting, security group ingress to the DB port from any address, and whether subnets are **public**. Instances that combine an internet-facing endpoint, open ingress, and public subnets are identified.",
			RemediationText: "Keep databases private by applying **least privilege** at the network layer: - Set `PubliclyAccessible` to `false` - Place instances in private subnets - Deny `0.0.0.0/0` and `::/0` on the DB port - Expose access via private endpoints, VPN, or an application tier/DB proxy Adopt **defense in depth** with monitoring and strong auth.",
			Categories:      []string{"rds", "public_access"},
		},
	}
}

func (c *InstanceNoPublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceNoPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_no_public_access
	_ = client

	return findings, nil
}

// InstanceCriticalEventSubscription - RDS instance event subscription is enabled for maintenance, configuration change, and failure categories
type InstanceCriticalEventSubscription struct {
	metadata models.CheckMetadata
}

func NewInstanceCriticalEventSubscription() *InstanceCriticalEventSubscription {
	return &InstanceCriticalEventSubscription{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_critical_event_subscription",
			CheckTitle:      "RDS instance event subscription is enabled for maintenance, configuration change, and failure categories",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsEventSubscription",
			Description:     "**RDS event subscriptions** for DB instances are assessed for coverage of the critical categories `maintenance`, `configuration change`, and `failure`. The evaluation looks for enabled `db-instance` subscriptions and confirms these categories are included or that all events are selected.",
			RemediationText: "Establish and sustain **RDS event subscriptions** for `db-instance` that include `maintenance`, `configuration change`, and `failure`. - Deliver to monitored channels (ticketing/chat/paging) - Enforce **least privilege** on topics - Test alert delivery and runbooks - Periodically review coverage across Regions",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceCriticalEventSubscription) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceCriticalEventSubscription) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_critical_event_subscription
	_ = client

	return findings, nil
}

// ClusterMultiAz - RDS cluster has Multi-AZ enabled
type ClusterMultiAz struct {
	metadata models.CheckMetadata
}

func NewClusterMultiAz() *ClusterMultiAz {
	return &ClusterMultiAz{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_cluster_multi_az",
			CheckTitle:      "RDS cluster has Multi-AZ enabled",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbCluster",
			Description:     "**RDS DB clusters** are assessed for deployment across **multiple Availability Zones** (*Multi-AZ*), verifying that redundant instances exist to support **automatic failover** instead of a single-AZ configuration.",
			RemediationText: "Enable **Multi-AZ** for production DB clusters to ensure cross-AZ redundancy and **automatic failover**. Choose a model that meets your SLA (one standby or two readable standbys; Aurora spans 3 AZs). Place subnets in distinct AZs, implement connection retries, and regularly test failover to validate **RTO/RPO** and readiness.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *ClusterMultiAz) Metadata() models.CheckMetadata { return c.metadata }

func (c *ClusterMultiAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_cluster_multi_az
	_ = client

	return findings, nil
}

// SnapshotsPublicAccess - RDS snapshot is not publicly shared
type SnapshotsPublicAccess struct {
	metadata models.CheckMetadata
}

func NewSnapshotsPublicAccess() *SnapshotsPublicAccess {
	return &SnapshotsPublicAccess{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_snapshots_public_access",
			CheckTitle:      "RDS snapshot is not publicly shared",
			ServiceName:     "rds",
			Severity:        "critical",
			ResourceType:    "AwsRdsDbSnapshot",
			Description:     "**RDS DB snapshots** and **DB cluster snapshots** with **public visibility** (shared with `all` AWS accounts) are detected. Snapshots limited to specific accounts or kept private are identified as restricted.",
			RemediationText: "Keep **RDS snapshots** and **cluster snapshots** private. Share only with explicit AWS account IDs using **least privilege** and time-bound access. Enforce guardrails to block `public` visibility, require approvals for sharing, and audit snapshot permissions. Use encryption with strict key policies to control who can restore data.",
			Categories:      []string{"rds", "public_access"},
		},
	}
}

func (c *SnapshotsPublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *SnapshotsPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_snapshots_public_access
	_ = client

	return findings, nil
}

// ClusterDeletionProtection - RDS cluster has deletion protection enabled
type ClusterDeletionProtection struct {
	metadata models.CheckMetadata
}

func NewClusterDeletionProtection() *ClusterDeletionProtection {
	return &ClusterDeletionProtection{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_cluster_deletion_protection",
			CheckTitle:      "RDS cluster has deletion protection enabled",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbCluster",
			Description:     "**RDS DB clusters** have **deletion protection** enabled (`deletion_protection=true`).",
			RemediationText: "Enable **deletion protection** (`deletion_protection=true`) on production and other critical clusters. Enforce via IaC and organizational guardrails; apply **least privilege** to delete/modify actions; require **change control** and approvals. Maintain reliable **backups** to restore when protection must be lifted.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *ClusterDeletionProtection) Metadata() models.CheckMetadata { return c.metadata }

func (c *ClusterDeletionProtection) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_cluster_deletion_protection
	_ = client

	return findings, nil
}

// ClusterMinorVersionUpgradeEnabled - RDS cluster has automatic minor version upgrades enabled
type ClusterMinorVersionUpgradeEnabled struct {
	metadata models.CheckMetadata
}

func NewClusterMinorVersionUpgradeEnabled() *ClusterMinorVersionUpgradeEnabled {
	return &ClusterMinorVersionUpgradeEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_cluster_minor_version_upgrade_enabled",
			CheckTitle:      "RDS cluster has automatic minor version upgrades enabled",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbCluster",
			Description:     "**RDS Multi-AZ DB clusters** are configured for **automatic minor engine upgrades** via `auto_minor_version_upgrade`. The evaluation checks these clusters to see if this setting is enabled so preferred minor releases are applied during the maintenance window.",
			RemediationText: "Enable `auto_minor_version_upgrade` on **RDS Multi-AZ clusters** and align updates with approved maintenance windows. Validate changes in non-production, and document any exceptions with a strict manual patch cadence. This strengthens **defense in depth** and improves **availability**.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *ClusterMinorVersionUpgradeEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ClusterMinorVersionUpgradeEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_cluster_minor_version_upgrade_enabled
	_ = client

	return findings, nil
}

// InstanceEventSubscriptionParameterGroups - RDS DB parameter group event subscription is enabled and subscribes to configuration change events or all categories
type InstanceEventSubscriptionParameterGroups struct {
	metadata models.CheckMetadata
}

func NewInstanceEventSubscriptionParameterGroups() *InstanceEventSubscriptionParameterGroups {
	return &InstanceEventSubscriptionParameterGroups{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_event_subscription_parameter_groups",
			CheckTitle:      "RDS DB parameter group event subscription is enabled and subscribes to configuration change events or all categories",
			ServiceName:     "rds",
			Severity:        "low",
			ResourceType:    "AwsRdsEventSubscription",
			Description:     "**RDS event subscriptions** for **DB parameter groups** notify on `configuration change` events (or all categories) when the subscription is enabled",
			RemediationText: "Create and maintain an **SNS-backed event subscription** for **DB parameter groups** that includes `configuration change` (or all) and keep it enabled. - Apply **least privilege** to SNS topics - Route to on-call/SIEM and test alerts - Enforce change control and monitoring across all Regions",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceEventSubscriptionParameterGroups) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceEventSubscriptionParameterGroups) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_event_subscription_parameter_groups
	_ = client

	return findings, nil
}

// InstanceMultiAz - RDS instance has Multi-AZ enabled
type InstanceMultiAz struct {
	metadata models.CheckMetadata
}

func NewInstanceMultiAz() *InstanceMultiAz {
	return &InstanceMultiAz{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_multi_az",
			CheckTitle:      "RDS instance has Multi-AZ enabled",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are evaluated for **Multi-AZ** configuration, either enabled on the instance or inherited from the associated DB cluster.",
			RemediationText: "Apply fault-tolerance and redundancy principles: enable **Multi-AZ** for production RDS workloads. Choose one standby or two readable standbys based on RTO/RPO and performance needs. Regularly test failover, monitor configuration drift, and allow exceptions only with documented, risk-based approval.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceMultiAz) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceMultiAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_multi_az
	_ = client

	return findings, nil
}

// InstanceIntegrationCloudwatchLogs - RDS instance exports logs to CloudWatch Logs
type InstanceIntegrationCloudwatchLogs struct {
	metadata models.CheckMetadata
}

func NewInstanceIntegrationCloudwatchLogs() *InstanceIntegrationCloudwatchLogs {
	return &InstanceIntegrationCloudwatchLogs{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_integration_cloudwatch_logs",
			CheckTitle:      "RDS instance exports logs to CloudWatch Logs",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are configured to **publish database logs** to **CloudWatch Logs** (e.g., `error`, `general`, `slowquery`, `audit`). The evaluation identifies instances that have log exports enabled to a CloudWatch log group.",
			RemediationText: "Enable export of relevant RDS logs to **CloudWatch Logs** (`error`, `general`, `slowquery`, `audit`) and standardize across engines. Enforce **least privilege** on log access, set retention, and define metrics/alarms for critical patterns. Integrate with a SIEM. Apply **separation of duties** and **defense in depth** to protect log integrity and monitoring.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceIntegrationCloudwatchLogs) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceIntegrationCloudwatchLogs) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_integration_cloudwatch_logs
	_ = client

	return findings, nil
}

// InstanceBackupEnabled - RDS instance has backup retention period greater than 0 days
type InstanceBackupEnabled struct {
	metadata models.CheckMetadata
}

func NewInstanceBackupEnabled() *InstanceBackupEnabled {
	return &InstanceBackupEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_backup_enabled",
			CheckTitle:      "RDS instance has backup retention period greater than 0 days",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are evaluated for **automated backups** by confirming the backup retention period is greater than `0` days, indicating point-in-time recovery is configured.",
			RemediationText: "Enable **automated backups** with retention > `0` aligned to RPO/RTO. Regularly test restores to validate **PITR**. Apply **least privilege** to backup access, encrypt snapshots, and replicate critical backups to separate locations for **defense in depth** and resilient recovery.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceBackupEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceBackupEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_backup_enabled
	_ = client

	return findings, nil
}

// InstanceDefaultAdmin - RDS instance does not use the default master username (admin or postgres)
type InstanceDefaultAdmin struct {
	metadata models.CheckMetadata
}

func NewInstanceDefaultAdmin() *InstanceDefaultAdmin {
	return &InstanceDefaultAdmin{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_default_admin",
			CheckTitle:      "RDS instance does not use the default master username (admin or postgres)",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are evaluated for use of a **custom administrator username**. The finding identifies instances or clusters where the admin user matches common defaults like `admin` or `postgres` (checked at the instance or cluster level).",
			RemediationText: "Adopt a **unique, non-default admin username** for each database and avoid enabling default accounts. - Enforce **least privilege** with separate admin and app users - Use strong, rotated secrets in a manager and prefer **IAM DB authentication** - Restrict network exposure and audit authentication activity",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceDefaultAdmin) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceDefaultAdmin) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_default_admin
	_ = client

	return findings, nil
}

// InstanceExtendedSupport - RDS instance is not enrolled in RDS Extended Support
type InstanceExtendedSupport struct {
	metadata models.CheckMetadata
}

func NewInstanceExtendedSupport() *InstanceExtendedSupport {
	return &InstanceExtendedSupport{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_extended_support",
			CheckTitle:      "RDS instance is not enrolled in RDS Extended Support",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are evaluated for enrollment in Amazon RDS Extended Support. The check fails if `EngineLifecycleSupportis` set to `open-source-rds-extended-support`, indicating the instance will incur additional charges after standard support ends.",
			RemediationText: "Upgrade enrolled DB instances to an engine version covered under standard support to stop Extended Support charges. For new DB instances and restores created via automation, explicitly set the engine lifecycle support option to avoid unintended enrollment in RDS Extended Support when that is your policy.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceExtendedSupport) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceExtendedSupport) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_extended_support
	_ = client

	return findings, nil
}

// SnapshotsEncrypted - RDS DB instance snapshot or DB cluster snapshot is encrypted
type SnapshotsEncrypted struct {
	metadata models.CheckMetadata
}

func NewSnapshotsEncrypted() *SnapshotsEncrypted {
	return &SnapshotsEncrypted{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_snapshots_encrypted",
			CheckTitle:      "RDS DB instance snapshot or DB cluster snapshot is encrypted",
			ServiceName:     "rds",
			Severity:        "high",
			ResourceType:    "AwsRdsDbSnapshot",
			Description:     "**RDS DB snapshots** and **DB cluster snapshots** are evaluated for **encryption at rest**, identifying snapshots created with a KMS key versus unencrypted ones.",
			RemediationText: "Encrypt all RDS snapshots at rest using **KMS**, preferably **customer-managed keys**. Apply **least privilege** to key usage, enforce encryption via templates and automation, and prevent sharing of unencrypted backups. Use **key rotation**, separation of duties, and ensure copies and cross-account shares remain encrypted.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *SnapshotsEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *SnapshotsEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_snapshots_encrypted
	_ = client

	return findings, nil
}

// InstanceTransportEncrypted - RDS instance or cluster enforces SSL/TLS encryption for client connections
type InstanceTransportEncrypted struct {
	metadata models.CheckMetadata
}

func NewInstanceTransportEncrypted() *InstanceTransportEncrypted {
	return &InstanceTransportEncrypted{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_transport_encrypted",
			CheckTitle:      "RDS instance or cluster enforces SSL/TLS encryption for client connections",
			ServiceName:     "rds",
			Severity:        "high",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** and **DB clusters** enforce **SSL/TLS** for client connections via parameter groups. The check looks for `rds.force_ssl=1` (PostgreSQL, SQL Server) or `require_secure_transport` enabled (MySQL-family) and identifies databases where encryption enforcement isn't active.",
			RemediationText: "Enforce transport encryption at the database layer: - Enable `rds.force_ssl=1` or `require_secure_transport` in parameter groups - Configure clients to require certificate validation and prevent fallback - Use current TLS versions and trusted CAs - Prefer private network access as **defense in depth**",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceTransportEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceTransportEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_transport_encrypted
	_ = client

	return findings, nil
}

// InstanceNonDefaultPort - RDS instance uses a non-default port for its engine
type InstanceNonDefaultPort struct {
	metadata models.CheckMetadata
}

func NewInstanceNonDefaultPort() *InstanceNonDefaultPort {
	return &InstanceNonDefaultPort{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_non_default_port",
			CheckTitle:      "RDS instance uses a non-default port for its engine",
			ServiceName:     "rds",
			Severity:        "low",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are evaluated for use of a port that differs from the engine's default. Matching an engine with its default port-`3306` (MySQL/MariaDB/Aurora MySQL), `5432` (PostgreSQL/Aurora), `1521` (Oracle), `1433` (SQL Server), `50000` (Db2)-indicates the instance uses the default listener.",
			RemediationText: "Use a **non-default DB port** and enforce **defense in depth**: - Apply **least-privilege** network rules - Keep databases in **private subnets**; avoid public exposure - Require strong authentication and audit logging *Update client connection strings and security rules when the port changes.*",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceNonDefaultPort) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceNonDefaultPort) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_non_default_port
	_ = client

	return findings, nil
}

// InstanceCopyTagsToSnapshots - RDS DB instance has copy tags to snapshots enabled
type InstanceCopyTagsToSnapshots struct {
	metadata models.CheckMetadata
}

func NewInstanceCopyTagsToSnapshots() *InstanceCopyTagsToSnapshots {
	return &InstanceCopyTagsToSnapshots{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_copy_tags_to_snapshots",
			CheckTitle:      "RDS DB instance has copy tags to snapshots enabled",
			ServiceName:     "rds",
			Severity:        "low",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are assessed for propagating instance tags to their **DB snapshots** using `CopyTagsToSnapshot`. *Aurora engines manage this at the cluster level and aren't evaluated per instance.*",
			RemediationText: "Enable `CopyTagsToSnapshot` on non-Aurora RDS instances so snapshots inherit required metadata. Establish a consistent **tag taxonomy** and automate enforcement to support **least privilege** via ABAC, cost tracking, and retention controls. For Aurora, configure tag copy at the cluster level.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceCopyTagsToSnapshots) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceCopyTagsToSnapshots) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_copy_tags_to_snapshots
	_ = client

	return findings, nil
}

// ClusterIntegrationCloudwatchLogs - RDS cluster has CloudWatch Logs export enabled
type ClusterIntegrationCloudwatchLogs struct {
	metadata models.CheckMetadata
}

func NewClusterIntegrationCloudwatchLogs() *ClusterIntegrationCloudwatchLogs {
	return &ClusterIntegrationCloudwatchLogs{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_cluster_integration_cloudwatch_logs",
			CheckTitle:      "RDS cluster has CloudWatch Logs export enabled",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbCluster",
			Description:     "**RDS clusters** running Aurora MySQL, Aurora PostgreSQL, MySQL, or PostgreSQL are assessed for **CloudWatch Logs publishing**, confirming that database logs are exported to a CloudWatch Logs group.",
			RemediationText: "Publish RDS/Aurora logs to **CloudWatch Logs** and centralize analysis. Select appropriate types (e.g., `error`, `general`, `slowquery`, `audit`), define retention, and create alarms. Limit log access with **least privilege** and integrate with SIEM for defense-in-depth monitoring.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *ClusterIntegrationCloudwatchLogs) Metadata() models.CheckMetadata { return c.metadata }

func (c *ClusterIntegrationCloudwatchLogs) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_cluster_integration_cloudwatch_logs
	_ = client

	return findings, nil
}

// InstanceStorageEncrypted - RDS DB instance storage is encrypted at rest
type InstanceStorageEncrypted struct {
	metadata models.CheckMetadata
}

func NewInstanceStorageEncrypted() *InstanceStorageEncrypted {
	return &InstanceStorageEncrypted{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_storage_encrypted",
			CheckTitle:      "RDS DB instance storage is encrypted at rest",
			ServiceName:     "rds",
			Severity:        "high",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are assessed for **KMS-based encryption at rest** (`StorageEncrypted=true`), covering instance storage and derived artifacts such as snapshots, automated backups, and read replicas.",
			RemediationText: "Enable **encryption at rest** for all RDS instances. Prefer **customer-managed KMS keys** to control rotation and fine-grained access, applying **least privilege** and **defense in depth**. Restrict key usage, monitor key activity, and manage key lifecycle. Migrate unencrypted instances via encrypted snapshot copy and restore.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceStorageEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceStorageEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_storage_encrypted
	_ = client

	return findings, nil
}

// InstanceProtectedByBackupPlan - RDS instance is protected by an AWS Backup plan
type InstanceProtectedByBackupPlan struct {
	metadata models.CheckMetadata
}

func NewInstanceProtectedByBackupPlan() *InstanceProtectedByBackupPlan {
	return &InstanceProtectedByBackupPlan{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_protected_by_backup_plan",
			CheckTitle:      "RDS instance is protected by an AWS Backup plan",
			ServiceName:     "rds",
			Severity:        "high",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** (non-Aurora) are included in an **AWS Backup plan**, indicating scheduled backups and retention are applied to the resource. *Aurora engines are evaluated separately.*",
			RemediationText: "Assign all non-Aurora RDS to an **AWS Backup plan** aligned to business `RPO/RTO`. Use **tags** for automatic coverage, define retention and lifecycle, and store backups in **immutable** vaults where possible. Regularly perform restore tests. Enforce **least privilege** and **separation of duties** for backup administration.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceProtectedByBackupPlan) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceProtectedByBackupPlan) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_protected_by_backup_plan
	_ = client

	return findings, nil
}

// ClusterBacktrackEnabled - RDS Aurora MySQL cluster has Backtrack enabled
type ClusterBacktrackEnabled struct {
	metadata models.CheckMetadata
}

func NewClusterBacktrackEnabled() *ClusterBacktrackEnabled {
	return &ClusterBacktrackEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_cluster_backtrack_enabled",
			CheckTitle:      "RDS Aurora MySQL cluster has Backtrack enabled",
			ServiceName:     "rds",
			Severity:        "low",
			ResourceType:    "AwsRdsDbCluster",
			Description:     "**Aurora MySQL DB clusters** have **Backtrack** configured with a non-zero `BacktrackWindow`, retaining change records to allow rewinding to a consistent earlier time. *Applies to `aurora-mysql` engines only.*",
			RemediationText: "Enable **Backtrack** on Aurora MySQL clusters and set `BacktrackWindow` to meet RTO while balancing cost and workload. Use it with automated backups for **defense in depth** and resilience. *For clusters without Backtrack*, provision a clone or new cluster with it enabled; monitor usage and adjust the window as change rates evolve.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *ClusterBacktrackEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ClusterBacktrackEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_cluster_backtrack_enabled
	_ = client

	return findings, nil
}

// ClusterProtectedByBackupPlan - RDS cluster is protected by an AWS Backup plan
type ClusterProtectedByBackupPlan struct {
	metadata models.CheckMetadata
}

func NewClusterProtectedByBackupPlan() *ClusterProtectedByBackupPlan {
	return &ClusterProtectedByBackupPlan{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_cluster_protected_by_backup_plan",
			CheckTitle:      "RDS cluster is protected by an AWS Backup plan",
			ServiceName:     "rds",
			Severity:        "high",
			ResourceType:    "AwsRdsDbCluster",
			Description:     "**RDS DB clusters** are covered by an **AWS Backup backup plan** when resource assignments include the cluster, either explicitly, by tags, or via an appropriate resource scope.",
			RemediationText: "Include RDS clusters in an **AWS Backup backup plan**. Apply **defense in depth**: define schedules and retention, enable immutable vault controls and cross-Region copies, use tags for consistent coverage, enforce **least privilege** for backup roles, and regularly test restores to validate RPO/RTO.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *ClusterProtectedByBackupPlan) Metadata() models.CheckMetadata { return c.metadata }

func (c *ClusterProtectedByBackupPlan) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_cluster_protected_by_backup_plan
	_ = client

	return findings, nil
}

// ClusterNonDefaultPort - RDS cluster uses a non-default port for its database engine
type ClusterNonDefaultPort struct {
	metadata models.CheckMetadata
}

func NewClusterNonDefaultPort() *ClusterNonDefaultPort {
	return &ClusterNonDefaultPort{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_cluster_non_default_port",
			CheckTitle:      "RDS cluster uses a non-default port for its database engine",
			ServiceName:     "rds",
			Severity:        "low",
			ResourceType:    "AwsRdsDbCluster",
			Description:     "**RDS DB clusters** are assessed for use of a **non-default database port**. Evaluation focuses on whether the cluster listens on the engine's well-known default port (e.g., `3306`, `5432`, `1433`, `1521`, `50000`) or on a custom port.",
			RemediationText: "Use a **non-default port** and enforce **least-privilege** network access: - Allow only approved sources - Keep databases in private subnets - Require TLS and strong, centralized auth - Monitor failed connections Update application connection strings to the new `port` as part of defense-in-depth.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *ClusterNonDefaultPort) Metadata() models.CheckMetadata { return c.metadata }

func (c *ClusterNonDefaultPort) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_cluster_non_default_port
	_ = client

	return findings, nil
}

// InstanceMinorVersionUpgradeEnabled - RDS instance has minor version upgrade enabled
type InstanceMinorVersionUpgradeEnabled struct {
	metadata models.CheckMetadata
}

func NewInstanceMinorVersionUpgradeEnabled() *InstanceMinorVersionUpgradeEnabled {
	return &InstanceMinorVersionUpgradeEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_instance_minor_version_upgrade_enabled",
			CheckTitle:      "RDS instance has minor version upgrade enabled",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbInstance",
			Description:     "**RDS DB instances** are evaluated for the `auto_minor_version_upgrade` setting that enables **automatic minor engine updates** during maintenance windows.",
			RemediationText: "Enable `auto_minor_version_upgrade` on RDS instances so minor releases are applied promptly. Use maintenance windows and stage testing to limit impact. Follow **defense in depth** and **least privilege**; keep reliable backups and Multi-AZ to preserve continuity if upgrades require rollback.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *InstanceMinorVersionUpgradeEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceMinorVersionUpgradeEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_instance_minor_version_upgrade_enabled
	_ = client

	return findings, nil
}

// ClusterStorageEncrypted - RDS cluster storage is encrypted
type ClusterStorageEncrypted struct {
	metadata models.CheckMetadata
}

func NewClusterStorageEncrypted() *ClusterStorageEncrypted {
	return &ClusterStorageEncrypted{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_cluster_storage_encrypted",
			CheckTitle:      "RDS cluster storage is encrypted",
			ServiceName:     "rds",
			Severity:        "high",
			ResourceType:    "AwsRdsDbCluster",
			Description:     "**RDS DB clusters** are assessed for **encryption at rest** via AWS KMS. It determines whether cluster storage-and related artifacts like automated backups and snapshots-are encrypted with a KMS key.",
			RemediationText: "Create clusters with `StorageEncrypted=true` using **AWS KMS**, preferably **customer-managed keys**. Apply **least privilege** to key usage, enable rotation and monitoring, and separate key administration from DB operations. Ensure snapshots and cross-account copies remain encrypted for **defense in depth**.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *ClusterStorageEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *ClusterStorageEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_cluster_storage_encrypted
	_ = client

	return findings, nil
}

// ClusterIamAuthenticationEnabled - RDS cluster has IAM authentication enabled
type ClusterIamAuthenticationEnabled struct {
	metadata models.CheckMetadata
}

func NewClusterIamAuthenticationEnabled() *ClusterIamAuthenticationEnabled {
	return &ClusterIamAuthenticationEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "rds_cluster_iam_authentication_enabled",
			CheckTitle:      "RDS cluster has IAM authentication enabled",
			ServiceName:     "rds",
			Severity:        "medium",
			ResourceType:    "AwsRdsDbCluster",
			Description:     "**RDS DB clusters** on supported engines (MySQL/MariaDB/PostgreSQL/Aurora) have **IAM database authentication** enabled for database logins, indicating token-based access managed by IAM instead of static passwords.",
			RemediationText: "Enable **IAM database authentication** on supported clusters and enforce **least privilege**. Grant only necessary `rds-db:connect` permissions to specific principals, prefer role-based access for workloads to obtain short-lived tokens, require **TLS**, and deprecate static DB passwords. Pair with auditing and segmentation for **defense in depth**.",
			Categories:      []string{"rds"},
		},
	}
}

func (c *ClusterIamAuthenticationEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ClusterIamAuthenticationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa rdsProvider")
	}
	client, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for rds_cluster_iam_authentication_enabled
	_ = client

	return findings, nil
}
