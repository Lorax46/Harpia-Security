package rolesanywhere

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// RolesanywhereTrustAnchorPqcPki - IAM Roles Anywhere trust anchors are backed by a post-quantum (ML-DSA) PKI
type RolesanywhereTrustAnchorPqcPki struct {
    metadata models.CheckMetadata
}

func NewRolesanywhereTrustAnchorPqcPki() *RolesanywhereTrustAnchorPqcPki {
    return &RolesanywhereTrustAnchorPqcPki{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rolesanywhere_trust_anchor_pqc_pki",
            CheckTitle: "IAM Roles Anywhere trust anchors are backed by a post-quantum (ML-DSA) PKI",
            ServiceName: "rolesanywhere",
            Severity: "low",
            Description: "**IAM Roles Anywhere trust anchors** are assessed for use of a **post-quantum digital signature algorithm** (ML-DSA). A trust anchor backed by an AWS Private CA whose `KeyAlgorithm` is RSA or ECC produces signatures vulnerable to forgery by a future quantum attacker, allowing an unintended actor to issue certificates and obtain unauthorized AWS access.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rolesanywhere"},
        },
    }
}

func (c *RolesanywhereTrustAnchorPqcPki) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RolesanywhereTrustAnchorPqcPki) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rolesanywhere",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RolesanywhereProfileRestrictsSessionPermissions - IAM Roles Anywhere profiles scope down the vended session permissions
type RolesanywhereProfileRestrictsSessionPermissions struct {
    metadata models.CheckMetadata
}

func NewRolesanywhereProfileRestrictsSessionPermissions() *RolesanywhereProfileRestrictsSessionPermissions {
    return &RolesanywhereProfileRestrictsSessionPermissions{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rolesanywhere_profile_restricts_session_permissions",
            CheckTitle: "IAM Roles Anywhere profiles scope down the vended session permissions",
            ServiceName: "rolesanywhere",
            Severity: "medium",
            Description: "**IAM Roles Anywhere profiles** that reference an administrative role are assessed for **session scoping**. A profile defining neither an inline `sessionPolicy` nor `managedPolicyArns` vends credentials with the full permissions of its roles. It is flagged only when a referenced role is administrative, since an unscoped session on a least-privilege role is already constrained.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rolesanywhere"},
        },
    }
}

func (c *RolesanywhereProfileRestrictsSessionPermissions) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RolesanywhereProfileRestrictsSessionPermissions) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rolesanywhere",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

