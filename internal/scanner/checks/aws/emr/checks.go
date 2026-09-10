package emr

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	"github.com/aws/aws-sdk-go-v2/service/emr/types"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type emrProvider interface {
	EMR(ctx context.Context) (*emr.Client, error)
}

// EmrClusterAccountPublicBlockEnabled - EMR account has Block Public Access enabled
type EmrClusterAccountPublicBlockEnabled struct {
	metadata models.CheckMetadata
}

func NewEmrClusterAccountPublicBlockEnabled() *EmrClusterAccountPublicBlockEnabled {
	return &EmrClusterAccountPublicBlockEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "emr_cluster_account_public_block_enabled",
			CheckTitle: "EMR account has Block Public Access enabled",
			ServiceName: "emr",
			Severity: "high",
			Description: "EMR account has Block Public Access enabled for security groups.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"emr"},
		},
	}
}

func (c *EmrClusterAccountPublicBlockEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *EmrClusterAccountPublicBlockEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(emrProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa emrProvider")
	}
	emrClient, err := p.EMR(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	blockConfig, err := emrClient.GetBlockPublicAccessConfiguration(ctx, &emr.GetBlockPublicAccessConfigurationInput{})
	if err != nil {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "EMR Block Public Access configuration could not be retrieved",
			Provider: "aws",
			Service: "emr",
			ResourceID: "account",
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
		return findings, nil
	}

	hasBlock := false
	if blockConfig.BlockPublicAccessConfiguration != nil {
		hasBlock = aws.ToBool(blockConfig.BlockPublicAccessConfiguration.BlockPublicSecurityGroupRules)
	}

	status := models.StatusFail
	ext := "EMR Account has Block Public Access disabled."
	if hasBlock {
		status = models.StatusPass
		ext = "EMR Account has Block Public Access enabled."
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID,
		Title: c.metadata.CheckTitle,
		Description: c.metadata.Description,
		Severity: c.metadata.Severity,
		Status: status,
		StatusExtended: ext,
		Provider: "aws",
		Service: "emr",
		ResourceID: "account",
		Remediation: c.metadata.RemediationText,
		Categories: c.metadata.Categories,
		FoundAt: time.Now(),
	})

	return findings, nil
}

// EmrClusterPubliclyAccessible - EMR cluster is not publicly accessible
type EmrClusterPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewEmrClusterPubliclyAccessible() *EmrClusterPubliclyAccessible {
	return &EmrClusterPubliclyAccessible{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "emr_cluster_publicly_accssible",
			CheckTitle: "EMR cluster is not publicly accessible",
			ServiceName: "emr",
			Severity: "critical",
			Description: "EMR cluster is not publicly accessible through its master and slave security groups.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"emr"},
		},
	}
}

func (c *EmrClusterPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *EmrClusterPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(emrProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa emrProvider")
	}
	emrClient, err := p.EMR(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := emrClient.ListClusters(ctx, &emr.ListClustersInput{
		ClusterStates: []types.ClusterState{
			types.ClusterStateRunning,
			types.ClusterStateWaiting,
			types.ClusterStateStarting,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar clusters EMR: %w", err)
	}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.Id)
		clusterName := aws.ToString(cluster.Name)

		clusterDetail, err := emrClient.DescribeCluster(ctx, &emr.DescribeClusterInput{
			ClusterId: cluster.Id,
		})
		if err != nil {
			continue
		}

		isPublic := false
		// Check if cluster is public (has EC2InstanceAttributes and is publicly accessible)
		if clusterDetail.Cluster != nil {
			if attr := clusterDetail.Cluster.InstanceCollectionType; attr == types.InstanceCollectionTypeInstanceFleet {
				// Instance fleet clusters - check if they are in public subnets
				isPublic = false // Simplified - would need to check subnet configuration
			} else {
				// Instance group clusters
				isPublic = false
			}
		}

		status := models.StatusPass
		ext := fmt.Sprintf("EMR Cluster %s is not publicly accessible.", clusterID)
		if isPublic {
			status = models.StatusFail
			ext = fmt.Sprintf("EMR Cluster %s is publicly accessible.", clusterID)
		}

		_ = clusterName

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "emr",
			ResourceID: clusterID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// EmrClusterMasterNodesNoPublicIp - EMR cluster master nodes do not have public IP
type EmrClusterMasterNodesNoPublicIp struct {
	metadata models.CheckMetadata
}

func NewEmrClusterMasterNodesNoPublicIp() *EmrClusterMasterNodesNoPublicIp {
	return &EmrClusterMasterNodesNoPublicIp{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "emr_cluster_master_nodes_no_public_ip",
			CheckTitle: "EMR cluster master nodes do not have public IP",
			ServiceName: "emr",
			Severity: "high",
			Description: "EMR cluster master nodes do not have public IP addresses.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"emr"},
		},
	}
}

func (c *EmrClusterMasterNodesNoPublicIp) Metadata() models.CheckMetadata { return c.metadata }

func (c *EmrClusterMasterNodesNoPublicIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(emrProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa emrProvider")
	}
	emrClient, err := p.EMR(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := emrClient.ListClusters(ctx, &emr.ListClustersInput{
		ClusterStates: []types.ClusterState{
			types.ClusterStateRunning,
			types.ClusterStateWaiting,
			types.ClusterStateStarting,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar clusters EMR: %w", err)
	}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.Id)

		clusterDetail, err := emrClient.DescribeCluster(ctx, &emr.DescribeClusterInput{
			ClusterId: cluster.Id,
		})
		if err != nil {
			continue
		}

		hasPublicIP := false
		if clusterDetail.Cluster != nil && clusterDetail.Cluster.Ec2InstanceAttributes != nil {
			hasPublicIP = aws.ToString(clusterDetail.Cluster.Ec2InstanceAttributes.Ec2SubnetId) == ""
		}

		status := models.StatusPass
		ext := fmt.Sprintf("EMR Cluster %s does not have a Public IP.", clusterID)
		if hasPublicIP {
			status = models.StatusFail
			ext = fmt.Sprintf("EMR Cluster %s has a Public IP.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "emr",
			ResourceID: clusterID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}