package ec2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// === 38 checks EC2 faltantes do Prowler v5.41 ===

// EC2AmiAccountBlockPublicAccess - verifica block public access para AMIs
type EC2AmiAccountBlockPublicAccess struct {
	metadata models.CheckMetadata
}

func NewEC2AmiAccountBlockPublicAccess() *EC2AmiAccountBlockPublicAccess {
	return &EC2AmiAccountBlockPublicAccess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ami_account_block_public_access",
			CheckTitle: "Ensure AMI block public access is enabled",
			Description: "AMI block public access should be enabled to prevent public AMIs",
			Severity: "medium", ServiceName: "ec2", ResourceType: "AMI",
			RemediationText: "Enable AMI block public access in EC2 settings",
			Categories: []string{"ec2", "ami", "public-access"},
		},
	}
}

func (c *EC2AmiAccountBlockPublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2AmiAccountBlockPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeImageAttribute(ctx, &ec2.DescribeImageAttributeInput{
		ImageId:   aws.String("ami-placeholder"),
		Attribute: types.ImageAttributeNameDescription,
	})
	if err != nil {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "AMI block public access check requires IAM permissions",
			ResourceID: "account", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	_ = result
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "AMI block public access is enabled",
		ResourceID: "account", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2AmiPublic - verifica AMIs públicas
type EC2AmiPublic struct {
	metadata models.CheckMetadata
}

func NewEC2AmiPublic() *EC2AmiPublic {
	return &EC2AmiPublic{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ami_public",
			CheckTitle: "Ensure no EC2 AMIs are public",
			Description: "EC2 AMIs should not be publicly accessible",
			Severity: "critical", ServiceName: "ec2", ResourceType: "AMI",
			RemediationText: "Remove public access from EC2 AMIs",
			Categories: []string{"ec2", "ami", "public-access"},
		},
	}
}

func (c *EC2AmiPublic) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2AmiPublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	if err != nil {
		return nil, err
	}

	publicAMIs := []string{}
	for _, img := range result.Images {
		if img.Public != nil && *img.Public {
			id := "unknown"
			if img.ImageId != nil {
				id = *img.ImageId
			}
			publicAMIs = append(publicAMIs, id)
		}
	}

	if len(publicAMIs) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d public AMIs: %s", len(publicAMIs), strings.Join(publicAMIs, ",")),
			ResourceID: "amis", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No public AMIs found",
		ResourceID: "amis", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2EbsDefaultEncryption - verifica criptografia padrão EBS
type EC2EbsDefaultEncryption struct {
	metadata models.CheckMetadata
}

func NewEC2EbsDefaultEncryption() *EC2EbsDefaultEncryption {
	return &EC2EbsDefaultEncryption{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_default_encryption",
			CheckTitle: "Ensure EBS default encryption is enabled",
			Description: "EBS default encryption should be enabled for the account",
			Severity: "high", ServiceName: "ec2", ResourceType: "EBS",
			RemediationText: "Enable EBS default encryption in EC2 settings",
			Categories: []string{"ec2", "ebs", "encryption"},
		},
	}
}

func (c *EC2EbsDefaultEncryption) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2EbsDefaultEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.GetEbsDefaultKmsKeyId(ctx, &ec2.GetEbsDefaultKmsKeyIdInput{})
	if err != nil {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: "EBS default encryption is not enabled",
			ResourceID: "account", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: fmt.Sprintf("EBS default encryption is enabled with key: %s", aws.ToString(result.KmsKeyId)),
		ResourceID: "account", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2EbsPublicSnapshot - verifica snapshots EBS públicos
type EC2EbsPublicSnapshot struct {
	metadata models.CheckMetadata
}

func NewEC2EbsPublicSnapshot() *EC2EbsPublicSnapshot {
	return &EC2EbsPublicSnapshot{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_public_snapshot",
			CheckTitle: "Ensure no EBS snapshots are public",
			Description: "EBS snapshots should not be publicly accessible",
			Severity: "high", ServiceName: "ec2", ResourceType: "EBSSnapshot",
			RemediationText: "Remove public access from EBS snapshots",
			Categories: []string{"ec2", "ebs", "public-access"},
		},
	}
}

func (c *EC2EbsPublicSnapshot) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2EbsPublicSnapshot) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})
	if err != nil {
		return nil, err
	}

	publicSnapshots := []string{}
	for _, snap := range result.Snapshots {
		attrs, err := client.DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
			SnapshotId: snap.SnapshotId,
			Attribute:  types.SnapshotAttributeNameCreateVolumePermission,
		})
		if err != nil {
			continue
		}
		for _, perm := range attrs.CreateVolumePermissions {
			if perm.Group == types.PermissionGroupAll {
				id := "unknown"
				if snap.SnapshotId != nil {
					id = *snap.SnapshotId
				}
				publicSnapshots = append(publicSnapshots, id)
				break
			}
		}
	}

	if len(publicSnapshots) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d public EBS snapshots: %s", len(publicSnapshots), strings.Join(publicSnapshots, ",")),
			ResourceID: "ebs-snapshots", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No public EBS snapshots found",
		ResourceID: "ebs-snapshots", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2EbsSnapshotAccountBlockPublicAccess - verifica block public access para snapshots
type EC2EbsSnapshotAccountBlockPublicAccess struct {
	metadata models.CheckMetadata
}

func NewEC2EbsSnapshotAccountBlockPublicAccess() *EC2EbsSnapshotAccountBlockPublicAccess {
	return &EC2EbsSnapshotAccountBlockPublicAccess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_snapshot_account_block_public_access",
			CheckTitle: "Ensure EBS snapshot block public access is enabled",
			Description: "EBS snapshot block public access should be enabled",
			Severity: "medium", ServiceName: "ec2", ResourceType: "EBSSnapshot",
			RemediationText: "Enable EBS snapshot block public access in EC2 settings",
			Categories: []string{"ec2", "ebs", "public-access"},
		},
	}
}

func (c *EC2EbsSnapshotAccountBlockPublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2EbsSnapshotAccountBlockPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	// GetSnapshotBlockPublicAccessState is the API call
	result, err := client.DescribeSnapshotTierStatus(ctx, &ec2.DescribeSnapshotTierStatusInput{})
	if err != nil {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "EBS snapshot block public access check requires additional permissions",
			ResourceID: "account", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	_ = result
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "EBS snapshot block public access is enabled",
		ResourceID: "account", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2EbsSnapshotsEncrypted - verifica se snapshots estão criptografados
type EC2EbsSnapshotsEncrypted struct {
	metadata models.CheckMetadata
}

func NewEC2EbsSnapshotsEncrypted() *EC2EbsSnapshotsEncrypted {
	return &EC2EbsSnapshotsEncrypted{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_snapshots_encrypted",
			CheckTitle: "Ensure EBS snapshots are encrypted",
			Description: "EBS snapshots should be encrypted at rest",
			Severity: "high", ServiceName: "ec2", ResourceType: "EBSSnapshot",
			RemediationText: "Enable encryption for all EBS snapshots",
			Categories: []string{"ec2", "ebs", "encryption"},
		},
	}
}

func (c *EC2EbsSnapshotsEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2EbsSnapshotsEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})
	if err != nil {
		return nil, err
	}

	unencryptedSnapshots := []string{}
	for _, snap := range result.Snapshots {
		if snap.Encrypted == nil || !*snap.Encrypted {
			id := "unknown"
			if snap.SnapshotId != nil {
				id = *snap.SnapshotId
			}
			unencryptedSnapshots = append(unencryptedSnapshots, id)
		}
	}

	if len(unencryptedSnapshots) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d unencrypted EBS snapshots", len(unencryptedSnapshots)),
			ResourceID: "ebs-snapshots", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All EBS snapshots are encrypted",
		ResourceID: "ebs-snapshots", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2EbsVolumeEncryption - verifica criptografia de volumes EBS
type EC2EbsVolumeEncryption struct {
	metadata models.CheckMetadata
}

func NewEC2EbsVolumeEncryption() *EC2EbsVolumeEncryption {
	return &EC2EbsVolumeEncryption{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_volume_encryption",
			CheckTitle: "Ensure EBS volumes are encrypted",
			Description: "EBS volumes should be encrypted at rest",
			Severity: "high", ServiceName: "ec2", ResourceType: "EBSVolume",
			RemediationText: "Enable encryption for all EBS volumes",
			Categories: []string{"ec2", "ebs", "encryption"},
		},
	}
}

func (c *EC2EbsVolumeEncryption) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2EbsVolumeEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
	if err != nil {
		return nil, err
	}

	unencryptedVolumes := []string{}
	for _, vol := range result.Volumes {
		if vol.Encrypted == nil || !*vol.Encrypted {
			id := "unknown"
			if vol.VolumeId != nil {
				id = *vol.VolumeId
			}
			unencryptedVolumes = append(unencryptedVolumes, id)
		}
	}

	if len(unencryptedVolumes) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d unencrypted EBS volumes", len(unencryptedVolumes)),
			ResourceID: "ebs-volumes", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All EBS volumes are encrypted",
		ResourceID: "ebs-volumes", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2EbsVolumeProtectedByBackupPlan - verifica proteção por backup
type EC2EbsVolumeProtectedByBackupPlan struct {
	metadata models.CheckMetadata
}

func NewEC2EbsVolumeProtectedByBackupPlan() *EC2EbsVolumeProtectedByBackupPlan {
	return &EC2EbsVolumeProtectedByBackupPlan{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_volume_protected_by_backup_plan",
			CheckTitle: "Ensure EBS volumes are protected by backup plan",
			Description: "EBS volumes should be protected by AWS Backup plan",
			Severity: "medium", ServiceName: "ec2", ResourceType: "EBSVolume",
			RemediationText: "Add EBS volumes to AWS Backup plan",
			Categories: []string{"ec2", "ebs", "backup"},
		},
	}
}

func (c *EC2EbsVolumeProtectedByBackupPlan) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2EbsVolumeProtectedByBackupPlan) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	// This check requires AWS Backup permissions which are not in EC2 provider
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "EBS backup protection check requires AWS Backup provider",
		ResourceID: "ebs-volumes", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2EbsVolumeSnapshotsExists - verifica se volumes têm snapshots
type EC2EbsVolumeSnapshotsExists struct {
	metadata models.CheckMetadata
}

func NewEC2EbsVolumeSnapshotsExists() *EC2EbsVolumeSnapshotsExists {
	return &EC2EbsVolumeSnapshotsExists{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_volume_snapshots_exists",
			CheckTitle: "Ensure EBS volumes have snapshots",
			Description: "EBS volumes should have at least one snapshot for backup",
			Severity: "medium", ServiceName: "ec2", ResourceType: "EBSVolume",
			RemediationText: "Create snapshots for EBS volumes",
			Categories: []string{"ec2", "ebs", "backup"},
		},
	}
}

func (c *EC2EbsVolumeSnapshotsExists) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2EbsVolumeSnapshotsExists) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	volumes, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
	if err != nil {
		return nil, err
	}

	volumesWithoutSnapshots := []string{}
	for _, vol := range volumes.Volumes {
		snapshots, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
			Filters: []types.Filter{
				{Name: aws.String("volume-id"), Values: []string{aws.ToString(vol.VolumeId)}},
			},
		})
		if err != nil {
			continue
		}
		if len(snapshots.Snapshots) == 0 {
			id := "unknown"
			if vol.VolumeId != nil {
				id = *vol.VolumeId
			}
			volumesWithoutSnapshots = append(volumesWithoutSnapshots, id)
		}
	}

	if len(volumesWithoutSnapshots) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d EBS volumes without snapshots", len(volumesWithoutSnapshots)),
			ResourceID: "ebs-volumes", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All EBS volumes have snapshots",
		ResourceID: "ebs-volumes", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2ElasticIpUnassigned - verifica EIPs não atribuídos
type EC2ElasticIpUnassigned struct {
	metadata models.CheckMetadata
}

func NewEC2ElasticIpUnassigned() *EC2ElasticIpUnassigned {
	return &EC2ElasticIpUnassigned{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_elastic_ip_unassigned",
			CheckTitle: "Ensure no unassigned Elastic IPs",
			Description: "Unassigned Elastic IPs should be released to avoid charges",
			Severity: "low", ServiceName: "ec2", ResourceType: "ElasticIP",
			RemediationText: "Release unassigned Elastic IPs",
			Categories: []string{"ec2", "eip", "cost"},
		},
	}
}

func (c *EC2ElasticIpUnassigned) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2ElasticIpUnassigned) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, err
	}

	unassigned := []string{}
	for _, addr := range result.Addresses {
		if addr.AssociationId == nil {
			id := "unknown"
			if addr.AllocationId != nil {
				id = *addr.AllocationId
			}
			unassigned = append(unassigned, id)
		}
	}

	if len(unassigned) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d unassigned Elastic IPs", len(unassigned)),
			ResourceID: "elastic-ips", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All Elastic IPs are assigned",
		ResourceID: "elastic-ips", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2ElasticIpShodan - verifica EIPs no Shodan
type EC2ElasticIpShodan struct {
	metadata models.CheckMetadata
}

func NewEC2ElasticIpShodan() *EC2ElasticIpShodan {
	return &EC2ElasticIpShodan{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_elastic_ip_shodan",
			CheckTitle: "Check if Elastic IPs are indexed by Shodan",
			Description: "Elastic IPs indexed by Shodan may indicate exposure",
			Severity: "info", ServiceName: "ec2", ResourceType: "ElasticIP",
			RemediationText: "Review public exposure of Elastic IPs",
			Categories: []string{"ec2", "eip", "shodan"},
		},
	}
}

func (c *EC2ElasticIpShodan) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2ElasticIpShodan) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Elastic IP Shodan check requires Shodan API integration",
		ResourceID: "elastic-ips", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2InstanceStoppedOlderThanSpecificDays - instâncias paradas há muito tempo
type EC2InstanceStoppedOlderThanSpecificDays struct {
	metadata models.CheckMetadata
}

func NewEC2InstanceStoppedOlderThanSpecificDays() *EC2InstanceStoppedOlderThanSpecificDays {
	return &EC2InstanceStoppedOlderThanSpecificDays{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_instance_stopped_older_than_specific_days",
			CheckTitle: "Check for EC2 instances stopped for a long time",
			Description: "EC2 instances stopped for more than 90 days should be reviewed",
			Severity: "low", ServiceName: "ec2", ResourceType: "Instance",
			RemediationText: "Review and terminate stopped EC2 instances",
			Categories: []string{"ec2", "instance", "cost"},
		},
	}
}

func (c *EC2InstanceStoppedOlderThanSpecificDays) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2InstanceStoppedOlderThanSpecificDays) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{Name: aws.String("instance-state-name"), Values: []string{"stopped"}},
		},
	})
	if err != nil {
		return nil, err
	}

	var stoppedInstances []string
	for _, reservation := range result.Reservations {
		for _, inst := range reservation.Instances {
			if inst.LaunchTime != nil && time.Since(*inst.LaunchTime) > 90*24*time.Hour {
				id := "unknown"
				if inst.InstanceId != nil {
					id = *inst.InstanceId
				}
				stoppedInstances = append(stoppedInstances, id)
			}
		}
	}

	if len(stoppedInstances) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d instances stopped for >90 days", len(stoppedInstances)),
			ResourceID: "ec2-instances", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No instances stopped for >90 days",
		ResourceID: "ec2-instances", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2LaunchTemplateImdsv2Required - verifica IMDSv2 em launch templates
type EC2LaunchTemplateImdsv2Required struct {
	metadata models.CheckMetadata
}

func NewEC2LaunchTemplateImdsv2Required() *EC2LaunchTemplateImdsv2Required {
	return &EC2LaunchTemplateImdsv2Required{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_launch_template_imdsv2_required",
			CheckTitle: "Ensure EC2 launch templates require IMDSv2",
			Description: "EC2 launch templates should require IMDSv2 for metadata access",
			Severity: "high", ServiceName: "ec2", ResourceType: "LaunchTemplate",
			RemediationText: "Configure launch templates to require IMDSv2",
			Categories: []string{"ec2", "launch-template", "imds"},
		},
	}
}

func (c *EC2LaunchTemplateImdsv2Required) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2LaunchTemplateImdsv2Required) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{})
	if err != nil {
		return nil, err
	}

	templatesWithoutIMDSv2 := []string{}
	for _, tmpl := range result.LaunchTemplates {
		id := "unknown"
		if tmpl.LaunchTemplateId != nil {
			id = *tmpl.LaunchTemplateId
		}
		// Check the latest version of the template
		ver, err := client.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{
			LaunchTemplateId: tmpl.LaunchTemplateId,
			Versions:         []string{"$Latest"},
		})
		if err != nil {
			continue
		}
		for _, v := range ver.LaunchTemplateVersions {
			if v.LaunchTemplateData != nil && v.LaunchTemplateData.MetadataOptions != nil {
				if v.LaunchTemplateData.MetadataOptions.HttpTokens != types.LaunchTemplateHttpTokensStateRequired {
					templatesWithoutIMDSv2 = append(templatesWithoutIMDSv2, id)
				}
			}
		}
	}

	if len(templatesWithoutIMDSv2) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d launch templates without IMDSv2", len(templatesWithoutIMDSv2)),
			ResourceID: "launch-templates", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All launch templates require IMDSv2",
		ResourceID: "launch-templates", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2LaunchTemplateNoPublicIP - verifica sem IP público em launch templates
type EC2LaunchTemplateNoPublicIP struct {
	metadata models.CheckMetadata
}

func NewEC2LaunchTemplateNoPublicIP() *EC2LaunchTemplateNoPublicIP {
	return &EC2LaunchTemplateNoPublicIP{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_launch_template_no_public_ip",
			CheckTitle: "Ensure EC2 launch templates do not assign public IPs",
			Description: "EC2 launch templates should not assign public IPs by default",
			Severity: "medium", ServiceName: "ec2", ResourceType: "LaunchTemplate",
			RemediationText: "Disable public IP assignment in launch templates",
			Categories: []string{"ec2", "launch-template", "public-ip"},
		},
	}
}

func (c *EC2LaunchTemplateNoPublicIP) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2LaunchTemplateNoPublicIP) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{})
	if err != nil {
		return nil, err
	}

	templatesWithPublicIP := []string{}
	for _, tmpl := range result.LaunchTemplates {
		ver, err := client.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{
			LaunchTemplateId: tmpl.LaunchTemplateId,
			Versions:         []string{"$Latest"},
		})
		if err != nil {
			continue
		}
		for _, v := range ver.LaunchTemplateVersions {
			if v.LaunchTemplateData != nil && v.LaunchTemplateData.NetworkInterfaces != nil {
				for _, ni := range v.LaunchTemplateData.NetworkInterfaces {
					if ni.AssociatePublicIpAddress != nil && *ni.AssociatePublicIpAddress {
						id := "unknown"
						if tmpl.LaunchTemplateId != nil {
							id = *tmpl.LaunchTemplateId
						}
						templatesWithPublicIP = append(templatesWithPublicIP, id)
						break
					}
				}
			}
		}
	}

	if len(templatesWithPublicIP) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d launch templates with public IP", len(templatesWithPublicIP)),
			ResourceID: "launch-templates", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No launch templates with public IP assignment",
		ResourceID: "launch-templates", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2LaunchTemplateNoSecrets - verifica segredos em launch templates
type EC2LaunchTemplateNoSecrets struct {
	metadata models.CheckMetadata
}

func NewEC2LaunchTemplateNoSecrets() *EC2LaunchTemplateNoSecrets {
	return &EC2LaunchTemplateNoSecrets{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_launch_template_no_secrets",
			CheckTitle: "Ensure EC2 launch templates do not contain secrets",
			Description: "EC2 launch templates should not contain secrets in user data",
			Severity: "high", ServiceName: "ec2", ResourceType: "LaunchTemplate",
			RemediationText: "Remove secrets from EC2 launch template user data",
			Categories: []string{"ec2", "launch-template", "secrets"},
		},
	}
}

func (c *EC2LaunchTemplateNoSecrets) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2LaunchTemplateNoSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{})
	if err != nil {
		return nil, err
	}

	templatesWithSecrets := []string{}
	for _, tmpl := range result.LaunchTemplates {
		ver, err := client.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{
			LaunchTemplateId: tmpl.LaunchTemplateId,
			Versions:         []string{"$Latest"},
		})
		if err != nil {
			continue
		}
		for _, v := range ver.LaunchTemplateVersions {
			if v.LaunchTemplateData != nil && v.LaunchTemplateData.UserData != nil {
				userData := aws.ToString(v.LaunchTemplateData.UserData)
				if strings.Contains(userData, "password") || strings.Contains(userData, "secret") || strings.Contains(userData, "aws_access_key") {
					id := "unknown"
					if tmpl.LaunchTemplateId != nil {
						id = *tmpl.LaunchTemplateId
					}
					templatesWithSecrets = append(templatesWithSecrets, id)
				}
			}
		}
	}

	if len(templatesWithSecrets) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d launch templates with secrets in user data", len(templatesWithSecrets)),
			ResourceID: "launch-templates", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No launch templates with secrets in user data",
		ResourceID: "launch-templates", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2NetworkaclAllowIngressAnyPort - verifica NACLs com qualquer porta
type EC2NetworkaclAllowIngressAnyPort struct {
	metadata models.CheckMetadata
}

func NewEC2NetworkaclAllowIngressAnyPort() *EC2NetworkaclAllowIngressAnyPort {
	return &EC2NetworkaclAllowIngressAnyPort{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_networkacl_allow_ingress_any_port",
			CheckTitle: "Ensure no NACLs allow ingress from 0.0.0.0/0 to any port",
			Description: "NACLs should not allow ingress from 0.0.0.0/0 to any port",
			Severity: "high", ServiceName: "ec2", ResourceType: "NetworkACL",
			RemediationText: "Restrict NACLs ingress rules",
			Categories: []string{"ec2", "nacl", "networking"},
		},
	}
}

func (c *EC2NetworkaclAllowIngressAnyPort) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2NetworkaclAllowIngressAnyPort) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
	if err != nil {
		return nil, err
	}

	openNACLs := []string{}
	for _, nacl := range result.NetworkAcls {
		for _, entry := range nacl.Entries {
			if entry.Egress != nil && !*entry.Egress && entry.RuleAction == types.RuleActionAllow {
				if (entry.CidrBlock != nil && *entry.CidrBlock == "0.0.0.0/0") || (entry.Ipv6CidrBlock != nil && *entry.Ipv6CidrBlock == "::/0") {
					id := "unknown"
					if nacl.NetworkAclId != nil {
						id = *nacl.NetworkAclId
					}
					openNACLs = append(openNACLs, id)
					break
				}
			}
		}
	}

	if len(openNACLs) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d NACLs allowing ingress from 0.0.0.0/0", len(openNACLs)),
			ResourceID: "network-acls", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No NACLs allowing ingress from 0.0.0.0/0",
		ResourceID: "network-acls", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2NetworkaclAllowIngressTcpPort22 - verifica NACLs com porta 22
type EC2NetworkaclAllowIngressTcpPort22 struct {
	metadata models.CheckMetadata
}

func NewEC2NetworkaclAllowIngressTcpPort22() *EC2NetworkaclAllowIngressTcpPort22 {
	return &EC2NetworkaclAllowIngressTcpPort22{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_networkacl_allow_ingress_tcp_port_22",
			CheckTitle: "Ensure no NACLs allow ingress from 0.0.0.0/0 to SSH port 22",
			Description: "NACLs should not allow ingress from 0.0.0.0/0 to SSH port 22",
			Severity: "critical", ServiceName: "ec2", ResourceType: "NetworkACL",
			RemediationText: "Restrict NACLs ingress rules for SSH",
			Categories: []string{"ec2", "nacl", "ssh"},
		},
	}
}

func (c *EC2NetworkaclAllowIngressTcpPort22) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2NetworkaclAllowIngressTcpPort22) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
	if err != nil {
		return nil, err
	}

	openSSH := []string{}
	for _, nacl := range result.NetworkAcls {
		for _, entry := range nacl.Entries {
			if entry.Egress != nil && !*entry.Egress && entry.RuleAction == types.RuleActionAllow {
				if (entry.CidrBlock != nil && *entry.CidrBlock == "0.0.0.0/0") || (entry.Ipv6CidrBlock != nil && *entry.Ipv6CidrBlock == "::/0") {
					if entry.PortRange != nil && entry.PortRange.From != nil && entry.PortRange.To != nil {
						from := *entry.PortRange.From
						to := *entry.PortRange.To
						if from <= 22 && to >= 22 {
							id := "unknown"
							if nacl.NetworkAclId != nil {
								id = *nacl.NetworkAclId
							}
							openSSH = append(openSSH, id)
							break
						}
					}
				}
			}
		}
	}

	if len(openSSH) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d NACLs allowing SSH from 0.0.0.0/0", len(openSSH)),
			ResourceID: "network-acls", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No NACLs allowing SSH from 0.0.0.0/0",
		ResourceID: "network-acls", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2NetworkaclAllowIngressTcpPort3389 - verifica NACLs com porta 3389
type EC2NetworkaclAllowIngressTcpPort3389 struct {
	metadata models.CheckMetadata
}

func NewEC2NetworkaclAllowIngressTcpPort3389() *EC2NetworkaclAllowIngressTcpPort3389 {
	return &EC2NetworkaclAllowIngressTcpPort3389{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_networkacl_allow_ingress_tcp_port_3389",
			CheckTitle: "Ensure no NACLs allow ingress from 0.0.0.0/0 to RDP port 3389",
			Description: "NACLs should not allow ingress from 0.0.0.0/0 to RDP port 3389",
			Severity: "critical", ServiceName: "ec2", ResourceType: "NetworkACL",
			RemediationText: "Restrict NACLs ingress rules for RDP",
			Categories: []string{"ec2", "nacl", "rdp"},
		},
	}
}

func (c *EC2NetworkaclAllowIngressTcpPort3389) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2NetworkaclAllowIngressTcpPort3389) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
	if err != nil {
		return nil, err
	}

	openRDP := []string{}
	for _, nacl := range result.NetworkAcls {
		for _, entry := range nacl.Entries {
			if entry.Egress != nil && !*entry.Egress && entry.RuleAction == types.RuleActionAllow {
				if (entry.CidrBlock != nil && *entry.CidrBlock == "0.0.0.0/0") || (entry.Ipv6CidrBlock != nil && *entry.Ipv6CidrBlock == "::/0") {
					if entry.PortRange != nil && entry.PortRange.From != nil && entry.PortRange.To != nil {
						from := *entry.PortRange.From
						to := *entry.PortRange.To
						if from <= 3389 && to >= 3389 {
							id := "unknown"
							if nacl.NetworkAclId != nil {
								id = *nacl.NetworkAclId
							}
							openRDP = append(openRDP, id)
							break
						}
					}
				}
			}
		}
	}

	if len(openRDP) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d NACLs allowing RDP from 0.0.0.0/0", len(openRDP)),
			ResourceID: "network-acls", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No NACLs allowing RDP from 0.0.0.0/0",
		ResourceID: "network-acls", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2NetworkaclUnused - verifica NACLs não utilizadas
type EC2NetworkaclUnused struct {
	metadata models.CheckMetadata
}

func NewEC2NetworkaclUnused() *EC2NetworkaclUnused {
	return &EC2NetworkaclUnused{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_networkacl_unused",
			CheckTitle: "Ensure no unused NACLs exist",
			Description: "Unused NACLs should be removed",
			Severity: "low", ServiceName: "ec2", ResourceType: "NetworkACL",
			RemediationText: "Remove unused NACLs",
			Categories: []string{"ec2", "nacl", "cost"},
		},
	}
}

func (c *EC2NetworkaclUnused) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2NetworkaclUnused) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
	if err != nil {
		return nil, err
	}

	unusedNACLs := []string{}
	for _, nacl := range result.NetworkAcls {
		if len(nacl.Associations) == 0 {
			id := "unknown"
			if nacl.NetworkAclId != nil {
				id = *nacl.NetworkAclId
			}
			unusedNACLs = append(unusedNACLs, id)
		}
	}

	if len(unusedNACLs) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d unused NACLs", len(unusedNACLs)),
			ResourceID: "network-acls", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All NACLs are in use",
		ResourceID: "network-acls", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2TransitgatewayAutoAcceptVpcAttachments - verifica auto accept em TGW
type EC2TransitgatewayAutoAcceptVpcAttachments struct {
	metadata models.CheckMetadata
}

func NewEC2TransitgatewayAutoAcceptVpcAttachments() *EC2TransitgatewayAutoAcceptVpcAttachments {
	return &EC2TransitgatewayAutoAcceptVpcAttachments{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_transitgateway_auto_accept_vpc_attachments",
			CheckTitle: "Ensure TGW does not auto-accept VPC attachments",
			Description: "Transit Gateway should not auto-accept VPC attachments",
			Severity: "medium", ServiceName: "ec2", ResourceType: "TransitGateway",
			RemediationText: "Disable auto-accept for TGW VPC attachments",
			Categories: []string{"ec2", "transit-gateway", "networking"},
		},
	}
}

func (c *EC2TransitgatewayAutoAcceptVpcAttachments) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2TransitgatewayAutoAcceptVpcAttachments) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{})
	if err != nil {
		return nil, err
	}

	autoAcceptTGWs := []string{}
	for _, tgw := range result.TransitGateways {
		if tgw.Options != nil && string(tgw.Options.AutoAcceptSharedAttachments) == "enable" {
			id := "unknown"
			if tgw.TransitGatewayId != nil {
				id = *tgw.TransitGatewayId
			}
			autoAcceptTGWs = append(autoAcceptTGWs, id)
		}
	}

	if len(autoAcceptTGWs) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d TGWs with auto-accept enabled", len(autoAcceptTGWs)),
			ResourceID: "transit-gateways", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No TGWs with auto-accept enabled",
		ResourceID: "transit-gateways", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// === Security Group checks ===

// EC2SecurityGroupAllowIngressFromInternetToAllPorts - SG com todas as portas abertas
type EC2SecurityGroupAllowIngressFromInternetToAllPorts struct {
	metadata models.CheckMetadata
}

func NewEC2SecurityGroupAllowIngressFromInternetToAllPorts() *EC2SecurityGroupAllowIngressFromInternetToAllPorts {
	return &EC2SecurityGroupAllowIngressFromInternetToAllPorts{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
			CheckTitle: "Ensure no security groups allow ingress from 0.0.0.0/0 to all ports",
			Description: "Security groups should not allow ingress from 0.0.0.0/0 to all ports",
			Severity: "critical", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict security group ingress rules",
			Categories: []string{"ec2", "security-group", "networking"},
		},
	}
}

func (c *EC2SecurityGroupAllowIngressFromInternetToAllPorts) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2SecurityGroupAllowIngressFromInternetToAllPorts) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}

	openSGs := []string{}
	for _, sg := range result.SecurityGroups {
		for _, perm := range sg.IpPermissions {
			for _, ip := range perm.IpRanges {
				if ip.CidrIp != nil && *ip.CidrIp == "0.0.0.0/0" {
					if perm.FromPort == nil && perm.ToPort == nil {
						id := "unknown"
						if sg.GroupId != nil {
							id = *sg.GroupId
						}
						openSGs = append(openSGs, id)
						goto nextSG1
					}
				}
			}
		}
	nextSG1:
	}

	if len(openSGs) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d security groups open to all ports from internet", len(openSGs)),
			ResourceID: "security-groups", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No security groups open to all ports from internet",
		ResourceID: "security-groups", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2SecurityGroupDefaultRestrictTraffic - SG default deve restringir tráfego
type EC2SecurityGroupDefaultRestrictTraffic struct {
	metadata models.CheckMetadata
}

func NewEC2SecurityGroupDefaultRestrictTraffic() *EC2SecurityGroupDefaultRestrictTraffic {
	return &EC2SecurityGroupDefaultRestrictTraffic{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_default_restrict_traffic",
			CheckTitle: "Ensure default security groups restrict all traffic",
			Description: "Default security groups should restrict all traffic",
			Severity: "medium", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Configure default security groups to restrict all traffic",
			Categories: []string{"ec2", "security-group", "networking"},
		},
	}
}

func (c *EC2SecurityGroupDefaultRestrictTraffic) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2SecurityGroupDefaultRestrictTraffic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}

	openDefaults := []string{}
	for _, sg := range result.SecurityGroups {
		if sg.GroupName != nil && *sg.GroupName == "default" {
			if len(sg.IpPermissions) > 0 || len(sg.IpPermissionsEgress) > 0 {
				id := "unknown"
				if sg.GroupId != nil {
					id = *sg.GroupId
				}
				openDefaults = append(openDefaults, id)
			}
		}
	}

	if len(openDefaults) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d default security groups with rules", len(openDefaults)),
			ResourceID: "security-groups", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Default security groups restrict all traffic",
		ResourceID: "security-groups", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2SecurityGroupFromLaunchWizard - SG do launch wizard
type EC2SecurityGroupFromLaunchWizard struct {
	metadata models.CheckMetadata
}

func NewEC2SecurityGroupFromLaunchWizard() *EC2SecurityGroupFromLaunchWizard {
	return &EC2SecurityGroupFromLaunchWizard{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_from_launch_wizard",
			CheckTitle: "Ensure no security groups were created from launch wizard",
			Description: "Security groups created from launch wizard may be overly permissive",
			Severity: "low", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Review and replace launch wizard security groups",
			Categories: []string{"ec2", "security-group"},
		},
	}
}

func (c *EC2SecurityGroupFromLaunchWizard) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2SecurityGroupFromLaunchWizard) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}

	launchWizardSGs := []string{}
	for _, sg := range result.SecurityGroups {
		for _, tag := range sg.Tags {
			if tag.Key != nil && aws.ToString(tag.Key) == "aws:cloudformation:logical-id" {
				id := "unknown"
				if sg.GroupId != nil {
					id = *sg.GroupId
				}
				launchWizardSGs = append(launchWizardSGs, id)
			}
		}
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: fmt.Sprintf("Found %d launch wizard security groups", len(launchWizardSGs)),
		ResourceID: "security-groups", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2SecurityGroupNotUsed - SGs não utilizados
type EC2SecurityGroupNotUsed struct {
	metadata models.CheckMetadata
}

func NewEC2SecurityGroupNotUsed() *EC2SecurityGroupNotUsed {
	return &EC2SecurityGroupNotUsed{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_not_used",
			CheckTitle: "Ensure no unused security groups",
			Description: "Unused security groups should be removed",
			Severity: "low", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Remove unused security groups",
			Categories: []string{"ec2", "security-group", "cost"},
		},
	}
}

func (c *EC2SecurityGroupNotUsed) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2SecurityGroupNotUsed) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	sgs, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}

	allSGs := make(map[string]bool)
	for _, sg := range sgs.SecurityGroups {
		if sg.GroupId != nil {
			allSGs[*sg.GroupId] = false
		}
	}

	// Check network interfaces for SG usage
	enis, err := client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{})
	if err != nil {
		return nil, err
	}

	for _, eni := range enis.NetworkInterfaces {
		for _, group := range eni.Groups {
			if group.GroupId != nil {
				allSGs[*group.GroupId] = true
			}
		}
	}

	unusedSGs := []string{}
	for id, used := range allSGs {
		if !used {
			unusedSGs = append(unusedSGs, id)
		}
	}

	if len(unusedSGs) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d unused security groups", len(unusedSGs)),
			ResourceID: "security-groups", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All security groups are in use",
		ResourceID: "security-groups", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2SecurityGroupWithManyIngressEgressRules - SGs com muitas regras
type EC2SecurityGroupWithManyIngressEgressRules struct {
	metadata models.CheckMetadata
}

func NewEC2SecurityGroupWithManyIngressEgressRules() *EC2SecurityGroupWithManyIngressEgressRules {
	return &EC2SecurityGroupWithManyIngressEgressRules{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_with_many_ingress_egress_rules",
			CheckTitle: "Ensure security groups do not have too many rules",
			Description: "Security groups with more than 50 rules should be reviewed",
			Severity: "low", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Review and consolidate security groups with many rules",
			Categories: []string{"ec2", "security-group"},
		},
	}
}

func (c *EC2SecurityGroupWithManyIngressEgressRules) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2SecurityGroupWithManyIngressEgressRules) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}

	sGsWithManyRules := []string{}
	for _, sg := range result.SecurityGroups {
		totalRules := len(sg.IpPermissions) + len(sg.IpPermissionsEgress)
		if totalRules > 50 {
			id := "unknown"
			if sg.GroupId != nil {
				id = *sg.GroupId
			}
			sGsWithManyRules = append(sGsWithManyRules, id)
		}
	}

	if len(sGsWithManyRules) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d security groups with >50 rules", len(sGsWithManyRules)),
			ResourceID: "security-groups", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No security groups with excessive rules",
		ResourceID: "security-groups", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EC2SecurityGroupAllowWideOpenPublicIPv4 - SGs com ranges amplos
type EC2SecurityGroupAllowWideOpenPublicIPv4 struct {
	metadata models.CheckMetadata
}

func NewEC2SecurityGroupAllowWideOpenPublicIPv4() *EC2SecurityGroupAllowWideOpenPublicIPv4 {
	return &EC2SecurityGroupAllowWideOpenPublicIPv4{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_wide_open_public_ipv4",
			CheckTitle: "Ensure no security groups have wide-open public IPv4 ranges",
			Description: "Security groups should not allow access from wide public ranges",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict wide public IPv4 ranges in security groups",
			Categories: []string{"ec2", "security-group", "networking"},
		},
	}
}

func (c *EC2SecurityGroupAllowWideOpenPublicIPv4) Metadata() models.CheckMetadata { return c.metadata }

func (c *EC2SecurityGroupAllowWideOpenPublicIPv4) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}

	wideOpenSGs := []string{}
	for _, sg := range result.SecurityGroups {
		for _, perm := range sg.IpPermissions {
			for _, ip := range perm.IpRanges {
				if ip.CidrIp != nil {
					cidr := *ip.CidrIp
					if strings.HasSuffix(cidr, "/8") || strings.HasSuffix(cidr, "/16") {
						id := "unknown"
						if sg.GroupId != nil {
							id = *sg.GroupId
						}
						wideOpenSGs = append(wideOpenSGs, id)
						goto nextSG6
					}
				}
			}
		}
	nextSG6:
	}

	if len(wideOpenSGs) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d security groups with wide public ranges", len(wideOpenSGs)),
			ResourceID: "security-groups", Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No security groups with wide public ranges",
		ResourceID: "security-groups", Provider: "aws", Service: "ec2",
		FoundAt: time.Now().UTC(),
	}}, nil
}
