package oci

import (
	"context"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
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

// GetIdentityClient retorna um cliente Identity
func (p *Provider) GetIdentityClient(ctx context.Context) (identity.IdentityClient, error) {
	client, err := identity.NewIdentityClientWithConfigurationProvider(p.config)
	if err != nil {
		return client, fmt.Errorf("falha ao criar identity client: %w", err)
	}
	client.SetRegion(p.region)
	return client, nil
}

// GetComputeClient retorna um cliente Core (Compute)
func (p *Provider) GetComputeClient(ctx context.Context) (core.ComputeClient, error) {
	client, err := core.NewComputeClientWithConfigurationProvider(p.config)
	if err != nil {
		return client, fmt.Errorf("falha ao criar compute client: %w", err)
	}
	client.SetRegion(p.region)
	return client, nil
}

// GetRegion retorna a região configurada
func (p *Provider) GetRegion() string {
	return p.region
}

// GetTenancyId retorna o tenancy OCID
func (p *Provider) GetTenancyId() string {
	return p.tenancyId
}
