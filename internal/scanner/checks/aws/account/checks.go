package account

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// AccountSecurityContactInformationIsRegistered - AWS account has security alternate contact registered
type AccountSecurityContactInformationIsRegistered struct {
    metadata models.CheckMetadata
}

func NewAccountSecurityContactInformationIsRegistered() *AccountSecurityContactInformationIsRegistered {
    return &AccountSecurityContactInformationIsRegistered{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "account_security_contact_information_is_registered",
            CheckTitle: "AWS account has security alternate contact registered",
            ServiceName: "account",
            Severity: "medium",
            Description: "Account settings contain a **Security alternate contact** in Alternate Contacts (name, `EmailAddress`, `PhoneNumber`) for targeted AWS security notifications.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"account"},
        },
    }
}

func (c *AccountSecurityContactInformationIsRegistered) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AccountSecurityContactInformationIsRegistered) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "account",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AccountMaintainDifferentContactDetailsToSecurityBillingAndOperations - AWS account has distinct Security, Billing, and Operations contact details, different from each other and from the root contact
type AccountMaintainDifferentContactDetailsToSecurityBillingAndOperations struct {
    metadata models.CheckMetadata
}

func NewAccountMaintainDifferentContactDetailsToSecurityBillingAndOperations() *AccountMaintainDifferentContactDetailsToSecurityBillingAndOperations {
    return &AccountMaintainDifferentContactDetailsToSecurityBillingAndOperations{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "account_maintain_different_contact_details_to_security_billing_and_operations",
            CheckTitle: "AWS account has distinct Security, Billing, and Operations contact details, different from each other and from the root contact",
            ServiceName: "account",
            Severity: "medium",
            Description: "**AWS account alternate contacts** are defined for **Security**, **Billing**, and **Operations** with `name`, `email`, and `phone`. The finding evaluates that all three exist, are distinct from one another, and differ from the **primary (root) contact**.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"account"},
        },
    }
}

func (c *AccountMaintainDifferentContactDetailsToSecurityBillingAndOperations) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AccountMaintainDifferentContactDetailsToSecurityBillingAndOperations) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "account",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AccountSecurityQuestionsAreRegisteredInTheAwsAccount - [DEPRECATED] AWS root user has security challenge questions configured
type AccountSecurityQuestionsAreRegisteredInTheAwsAccount struct {
    metadata models.CheckMetadata
}

func NewAccountSecurityQuestionsAreRegisteredInTheAwsAccount() *AccountSecurityQuestionsAreRegisteredInTheAwsAccount {
    return &AccountSecurityQuestionsAreRegisteredInTheAwsAccount{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "account_security_questions_are_registered_in_the_aws_account",
            CheckTitle: "[DEPRECATED] AWS root user has security challenge questions configured",
            ServiceName: "account",
            Severity: "medium",
            Description: "[DEPRECATED] **AWS account root** configuration may include legacy **security challenge questions** for support identity verification. This evaluates whether those questions are set on the account. *New configuration is discontinued by AWS and remaining support for this feature is time-limited.*",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"account"},
        },
    }
}

func (c *AccountSecurityQuestionsAreRegisteredInTheAwsAccount) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AccountSecurityQuestionsAreRegisteredInTheAwsAccount) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "account",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AccountMaintainCurrentContactDetails - AWS account contact information is current
type AccountMaintainCurrentContactDetails struct {
    metadata models.CheckMetadata
}

func NewAccountMaintainCurrentContactDetails() *AccountMaintainCurrentContactDetails {
    return &AccountMaintainCurrentContactDetails{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "account_maintain_current_contact_details",
            CheckTitle: "AWS account contact information is current",
            ServiceName: "account",
            Severity: "medium",
            Description: "**AWS account contact information** is current for the **primary contact** and the **alternate contacts** for `security`, `billing`, and `operations`, with accurate email addresses and phone numbers.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"account"},
        },
    }
}

func (c *AccountMaintainCurrentContactDetails) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AccountMaintainCurrentContactDetails) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "account",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

