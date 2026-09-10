// Package kubernetes provides Kubernetes security checks for all distributions.
package kubernetes

import (
	"context"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/Lorax46/Harpia-Security/pkg/scanner/kubernetes/aks"
	"github.com/Lorax46/Harpia-Security/pkg/scanner/kubernetes/common"
	"github.com/Lorax46/Harpia-Security/pkg/scanner/kubernetes/eks"
	"github.com/Lorax46/Harpia-Security/pkg/scanner/kubernetes/gke"
)

// NewKubernetesChecks returns all Kubernetes security checks.
func NewKubernetesChecks() []CheckFactory {
	return []CheckFactory{
		// CIS Kubernetes Benchmark (common to all distributions)
		{ID: "kubernetes_cis_benchmark", New: func() Checker { return common.NewCheckCISKubernetes() }},

		// EKS-specific checks
		{ID: "eks_control_plane_logging", New: func() Checker { return eks.NewCheckEKSControlPlaneLogging() }},
		{ID: "eks_private_endpoint", New: func() Checker { return eks.NewCheckEKSPrivateEndpoint() }},
		{ID: "eks_encryption", New: func() Checker { return eks.NewCheckEKSEncryption() }},

		// AKS-specific checks
		{ID: "aks_logging", New: func() Checker { return aks.NewCheckAKSLogging() }},
		{ID: "aks_private_endpoint", New: func() Checker { return aks.NewCheckAKSPrivateEndpoint() }},

		// GKE-specific checks
		{ID: "gke_logging", New: func() Checker { return gke.NewCheckGKELogging() }},
		{ID: "gke_private_cluster", New: func() Checker { return gke.NewCheckGKEPrivateCluster() }},
		{ID: "gke_shielded_nodes", New: func() Checker { return gke.NewCheckGKEShieldedNodes() }},
	}
}

// CheckFactory creates new check instances.
type CheckFactory struct {
	ID  string
	New func() Checker
}

// Checker is the interface for Kubernetes security checks.
type Checker interface {
	Metadata() models.CheckMetadata
	Execute(ctx context.Context, provider interface{}) ([]models.Finding, error)
}
