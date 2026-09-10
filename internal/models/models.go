// Package models provides database models for the CNAPP platform.
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents a dashboard user
type User struct {
	ID           uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Username     string         `gorm:"uniqueIndex;not null" json:"username"`
	Email        string         `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash string         `gorm:"not null" json:"-"`
	Role         string         `gorm:"default:'viewer'" json:"role"`
	IsActive     bool           `gorm:"default:true" json:"is_active"`
	LastLoginAt  *time.Time     `json:"last_login_at"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// Provider represents a cloud provider configuration
type Provider struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name        string         `gorm:"not null" json:"name"`
	Type        string         `gorm:"not null" json:"type"`
	Credentials map[string]interface{} `gorm:"type:jsonb;not null" json:"credentials"`
	Status      string         `gorm:"default:'active'" json:"status"`
	LastScanAt  *time.Time     `json:"last_scan_at"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// Scan represents a security scan
type Scan struct {
	ID         uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	ProviderID *uuid.UUID     `gorm:"type:uuid" json:"provider_id"`
	Name       string         `gorm:"not null" json:"name"`
	Status     string         `gorm:"default:'pending'" json:"status"`
	Provider   string         `gorm:"not null" json:"provider"`
	Region     string         `json:"region"`
	StartedAt  *time.Time     `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at"`
	CreatedBy  *uuid.UUID     `gorm:"type:uuid" json:"created_by"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
}

// Finding represents a security finding
type Finding struct {
	ID              uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	ScanID          *uuid.UUID     `gorm:"type:uuid" json:"scan_id"`
	CheckID         string         `gorm:"not null" json:"check_id"`
	Title           string         `gorm:"not null" json:"title"`
	Description     string         `json:"description"`
	Severity        string         `gorm:"not null" json:"severity"`
	Status          string         `gorm:"not null" json:"status"`
	Provider        string         `gorm:"not null" json:"provider"`
	Service         string         `gorm:"not null" json:"service"`
	ResourceID      string         `json:"resource_id"`
	ResourceARN     string         `json:"resource_arn"`
	Region          string         `json:"region"`
	Remediation     string         `json:"remediation"`
	RemediationURL  string         `json:"remediation_url"`
	Categories      []string       `gorm:"type:jsonb" json:"categories"`
	FoundAt         time.Time      `gorm:"default:now()" json:"found_at"`
	ResolvedAt      *time.Time     `json:"resolved_at"`
	CreatedAt       time.Time      `json:"created_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
}

// ComplianceReport represents a compliance report
type ComplianceReport struct {
	ID              uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	ScanID          *uuid.UUID     `gorm:"type:uuid" json:"scan_id"`
	FrameworkID     string         `gorm:"not null" json:"framework_id"`
	FrameworkName   string         `gorm:"not null" json:"framework_name"`
	FrameworkVersion string        `json:"framework_version"`
	TotalChecks     int            `gorm:"default:0" json:"total_checks"`
	Passed          int            `gorm:"default:0" json:"passed"`
	Failed          int            `gorm:"default:0" json:"failed"`
	Manual          int            `gorm:"default:0" json:"manual"`
	PassRate        float64        `gorm:"type:decimal(5,2)" json:"pass_rate"`
	CreatedAt       time.Time      `json:"created_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
}

// ComplianceControl represents a compliance control
type ComplianceControl struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	ReportID    *uuid.UUID     `gorm:"type:uuid" json:"report_id"`
	ControlID   string         `gorm:"not null" json:"control_id"`
	ControlTitle string        `gorm:"not null" json:"control_title"`
	Description string         `json:"description"`
	Severity    string         `gorm:"not null" json:"severity"`
	Status      string         `gorm:"not null" json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// Inventory represents a cloud resource
type Inventory struct {
	ID              uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Provider        string         `gorm:"not null" json:"provider"`
	Service         string         `gorm:"not null" json:"service"`
	ResourceType    string         `gorm:"not null" json:"resource_type"`
	ResourceID      string         `gorm:"not null" json:"resource_id"`
	ResourceName    string         `json:"resource_name"`
	Region          string         `json:"region"`
	AccountID       string         `json:"account_id"`
	Tags            map[string]interface{} `gorm:"type:jsonb" json:"tags"`
	Configurations  map[string]interface{} `gorm:"type:jsonb" json:"configurations"`
	Metadata        map[string]interface{} `gorm:"type:jsonb" json:"metadata"`
	LastSeenAt      *time.Time     `json:"last_seen_at"`
	SyncedAt        time.Time      `gorm:"default:now()" json:"synced_at"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
}

// InventoryChange represents a change in inventory
type InventoryChange struct {
	ID            uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	ResourceID    *uuid.UUID     `gorm:"type:uuid" json:"resource_id"`
	ChangeType    string         `gorm:"not null" json:"change_type"`
	ChangeDetails map[string]interface{} `gorm:"type:jsonb" json:"change_details"`
	ChangedAt     time.Time      `gorm:"default:now()" json:"changed_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
}

// Vulnerability represents a known vulnerability
type Vulnerability struct {
	ID                uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	CVEID             string         `gorm:"not null" json:"cve_id"`
	Severity          string         `gorm:"not null" json:"severity"`
	Score             float64        `gorm:"type:decimal(4,2)" json:"score"`
	EPSSScore         float64        `gorm:"type:decimal(5,4)" json:"epss_score"`
	KEV               bool           `gorm:"default:false" json:"kev"`
	Description       string         `json:"description"`
	AffectedResource  string         `json:"affected_resource"`
	AffectedPackage   string         `json:"affected_package"`
	FixedVersion      string         `json:"fixed_version"`
	Provider          string         `json:"provider"`
	Service           string         `json:"service"`
	Status            string         `gorm:"default:'open'" json:"status"`
	DiscoveredAt      time.Time      `gorm:"default:now()" json:"discovered_at"`
	ResolvedAt        *time.Time     `json:"resolved_at"`
	CreatedAt         time.Time      `json:"created_at"`
	DeletedAt         gorm.DeletedAt `gorm:"index" json:"-"`
}

// ASMAsset represents an attack surface asset
type ASMAsset struct {
	ID           uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Type         string         `gorm:"not null" json:"type"`
	Value        string         `gorm:"not null" json:"value"`
	Provider     string         `json:"provider"`
	Exposure     string         `json:"exposure"`
	Technology   string         `json:"technology"`
	Port         int            `json:"port"`
	Protocol     string         `json:"protocol"`
	Status       string         `json:"status"`
	Metadata     map[string]interface{} `gorm:"type:jsonb" json:"metadata"`
	FirstSeenAt  time.Time      `gorm:"default:now()" json:"first_seen_at"`
	LastSeenAt   *time.Time     `json:"last_seen_at"`
	DiscoveredAt time.Time      `gorm:"default:now()" json:"discovered_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// SOARPlaybook represents an incident response playbook
type SOARPlaybook struct {
	ID              uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name            string         `gorm:"not null" json:"name"`
	Trigger         string         `gorm:"not null" json:"trigger"`
	TriggerConditions map[string]interface{} `gorm:"type:jsonb" json:"trigger_conditions"`
	Actions         map[string]interface{} `gorm:"type:jsonb;not null" json:"actions"`
	Enabled         bool           `gorm:"default:true" json:"enabled"`
	ExecutionCount  int            `gorm:"default:0" json:"execution_count"`
	LastExecutedAt  *time.Time     `json:"last_executed_at"`
	CreatedBy       *uuid.UUID     `gorm:"type:uuid" json:"created_by"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
}

// DSPMAsset represents a data security asset
type DSPMAsset struct {
	ID               uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Provider         string         `gorm:"not null" json:"provider"`
	Service          string         `gorm:"not null" json:"service"`
	ResourceID       string         `gorm:"not null" json:"resource_id"`
	ResourceType     string         `gorm:"not null" json:"resource_type"`
	Classification   string         `json:"classification"`
	EncryptionStatus string         `json:"encryption_status"`
	Exposure         string         `json:"exposure"`
	DataTypes        []string       `gorm:"type:jsonb" json:"data_types"`
	LastScanAt       *time.Time     `json:"last_scan_at"`
	SyncedAt         time.Time      `gorm:"default:now()" json:"synced_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`
}

// APIKey represents an API key for integrations
type APIKey struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID      *uuid.UUID     `gorm:"type:uuid" json:"user_id"`
	Name        string         `gorm:"not null" json:"name"`
	KeyHash     string         `gorm:"not null" json:"-"`
	KeyPrefix   string         `json:"key_prefix"`
	Scopes      []string       `gorm:"type:jsonb;not null;default:'[\"read\"]'" json:"scopes"`
	RateLimit   int            `gorm:"default:1000" json:"rate_limit"`
	LastUsedAt  *time.Time     `json:"last_used_at"`
	ExpiresAt   *time.Time     `json:"expires_at"`
	IsActive    bool           `gorm:"default:true" json:"is_active"`
	CreatedAt   time.Time      `json:"created_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID           uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID       *uuid.UUID     `gorm:"type:uuid" json:"user_id"`
	Action       string         `gorm:"not null" json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	IPAddress    string         `json:"ip_address"`
	UserAgent    string         `json:"user_agent"`
	Details      map[string]interface{} `gorm:"type:jsonb" json:"details"`
	CreatedAt    time.Time      `gorm:"default:now()" json:"created_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// ScheduledScan represents a scheduled scan
type ScheduledScan struct {
	ID             uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name           string         `gorm:"not null" json:"name"`
	ProviderID     *uuid.UUID     `gorm:"type:uuid" json:"provider_id"`
	CronExpression string         `gorm:"not null" json:"cron_expression"`
	Enabled        bool           `gorm:"default:true" json:"enabled"`
	LastRunAt      *time.Time     `json:"last_run_at"`
	NextRunAt      *time.Time     `json:"next_run_at"`
	CreatedBy      *uuid.UUID     `gorm:"type:uuid" json:"created_by"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`
}

// Notification represents a notification
type Notification struct {
	ID        uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID    *uuid.UUID     `gorm:"type:uuid" json:"user_id"`
	Type      string         `gorm:"not null" json:"type"`
	Title     string         `gorm:"not null" json:"title"`
	Message   string         `json:"message"`
	Severity  string         `json:"severity"`
	Read      bool           `gorm:"default:false" json:"read"`
	Metadata  map[string]interface{} `gorm:"type:jsonb" json:"metadata"`
	CreatedAt time.Time      `gorm:"default:now()" json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// Integration represents an external integration
type Integration struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name        string         `gorm:"not null" json:"name"`
	Type        string         `gorm:"not null" json:"type"`
	Config      map[string]interface{} `gorm:"type:jsonb;not null" json:"config"`
	Credentials map[string]interface{} `gorm:"type:jsonb" json:"credentials"`
	Status      string         `gorm:"default:'active'" json:"status"`
	LastSyncAt  *time.Time     `json:"last_sync_at"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// Setting represents a system setting
type Setting struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Key         string         `gorm:"uniqueIndex;not null" json:"key"`
	Value       string         `json:"value"`
	Description string         `json:"description"`
	UpdatedBy   *uuid.UUID     `gorm:"type:uuid" json:"updated_by"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}
