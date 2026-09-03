package oci

import (
	"context"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/audit"
	"github.com/oracle/oci-go-sdk/v65/cloudguard"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/events"
	"github.com/oracle/oci-go-sdk/v65/identity"
	objectstorage "github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// Provider representa um cliente OCI autenticado
type Provider struct {
	region        string
	tenancyId     string
	userId        string
	keyFingerprint string
	privateKey    string
	config        common.ConfigurationProvider
}

// NewProvider cria um novo provider OCI
func NewProvider(ctx context.Context, region, tenancyId, userId, keyFingerprint, privateKey, passphrase string) (*Provider, error) {
	if privateKey == "" {
		return nil, fmt.Errorf("private_key é obrigatório")
	}

	config := common.NewRawConfigurationProvider(
		tenancyId,
		userId,
		region,
		keyFingerprint,
		privateKey,
		common.String(passphrase),
	)

	return &Provider{
		region:        region,
		tenancyId:     tenancyId,
		userId:        userId,
		keyFingerprint: keyFingerprint,
		privateKey:    privateKey,
		config:        config,
	}, nil
}

// Identity retorna o cliente Identity
func (p *Provider) Identity() (identity.IdentityClient, error) {
	client, err := identity.NewIdentityClientWithConfigurationProvider(p.config)
	if err != nil {
		return client, fmt.Errorf("falha ao criar identity client: %w", err)
	}
	client.SetRegion(p.region)
	return client, nil
}

// Compute retorna o cliente Compute
func (p *Provider) Compute() (core.ComputeClient, error) {
	client, err := core.NewComputeClientWithConfigurationProvider(p.config)
	if err != nil {
		return client, fmt.Errorf("falha ao criar compute client: %w", err)
	}
	client.SetRegion(p.region)
	return client, nil
}

// Audit retorna o cliente Audit
func (p *Provider) Audit() (audit.AuditClient, error) {
	client, err := audit.NewAuditClientWithConfigurationProvider(p.config)
	if err != nil {
		return client, fmt.Errorf("falha ao criar audit client: %w", err)
	}
	client.SetRegion(p.region)
	return client, nil
}

// Network retorna o cliente Network
func (p *Provider) Network() (core.VirtualNetworkClient, error) {
	client, err := core.NewVirtualNetworkClientWithConfigurationProvider(p.config)
	if err != nil {
		return client, fmt.Errorf("falha ao criar network client: %w", err)
	}
	client.SetRegion(p.region)
	return client, nil
}

// ObjectStore retorna o cliente Object Storage
func (p *Provider) ObjectStore() (objectstorage.ObjectStorageClient, error) {
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(p.config)
	if err != nil {
		return client, fmt.Errorf("falha ao criar object storage client: %w", err)
	}
	client.SetRegion(p.region)
	return client, nil
}

// CloudGuard retorna o cliente Cloud Guard
func (p *Provider) CloudGuard() (cloudguard.CloudGuardClient, error) {
	client, err := cloudguard.NewCloudGuardClientWithConfigurationProvider(p.config)
	if err != nil {
		return client, fmt.Errorf("falha ao criar cloud guard client: %w", err)
	}
	client.SetRegion(p.region)
	return client, nil
}

// Events retorna o cliente Events
func (p *Provider) Events() (events.EventsClient, error) {
	client, err := events.NewEventsClientWithConfigurationProvider(p.config)
	if err != nil {
		return client, fmt.Errorf("falha ao criar events client: %w", err)
	}
	client.SetRegion(p.region)
	return client, nil
}

// Storage retorna o cliente Blockstorage
func (p *Provider) Storage() (core.BlockstorageClient, error) {
	client, err := core.NewBlockstorageClientWithConfigurationProvider(p.config)
	if err != nil {
		return client, fmt.Errorf("falha ao criar blockstorage client: %w", err)
	}
	client.SetRegion(p.region)
	return client, nil
}

// Region retorna a região configurada
func (p *Provider) Region() string {
	return p.region
}

// TenancyId retorna o tenancy OCID
func (p *Provider) TenancyId() string {
	return p.tenancyId
}
