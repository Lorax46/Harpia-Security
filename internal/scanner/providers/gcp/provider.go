package gcp

import (
	"context"
	"fmt"
	"os"
	"sync"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/accesscontextmanager/v1"
	"google.golang.org/api/artifactregistry/v1"
	"google.golang.org/api/bigquery/v2"
	"google.golang.org/api/bigtableadmin/v2"
	"google.golang.org/api/cloudasset/v1"
	"google.golang.org/api/cloudbuild/v1"
	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/cloudscheduler/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/containeranalysis/v1"
	"google.golang.org/api/dataproc/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/file/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/logging/v2"
	"google.golang.org/api/option"
	"google.golang.org/api/run/v1"
	"google.golang.org/api/spanner/v1"
	"google.golang.org/api/sqladmin/v1"
	"google.golang.org/api/storage/v1"
)

// Provider representa um cliente GCP autenticado
type Provider struct {
	projectID       string
	zone            string
	region          string
	credentialsPath string
	credentialsJSON []byte
	mu              sync.Mutex
}

// NewProvider cria um novo provider GCP
func NewProvider(ctx context.Context, projectID, zone, region, credentialsPath string) (*Provider, error) {
	if projectID == "" {
		return nil, fmt.Errorf("project_id é obrigatório")
	}

	if zone == "" {
		zone = "us-central1-a"
	}

	if region == "" {
		region = "us-central1"
	}

	provider := &Provider{
		projectID:       projectID,
		zone:            zone,
		region:          region,
		credentialsPath: credentialsPath,
	}

	if credentialsPath != "" {
		jsonData, err := os.ReadFile(credentialsPath)
		if err != nil {
			return nil, fmt.Errorf("falha ao ler arquivo de credenciais: %w", err)
		}
		provider.credentialsJSON = jsonData
	}

	return provider, nil
}

// clientOptions retorna as opções de cliente para autenticação
func (p *Provider) clientOptions(ctx context.Context) ([]option.ClientOption, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var opts []option.ClientOption

	if p.credentialsJSON != nil {
		creds, err := google.CredentialsFromJSON(ctx, p.credentialsJSON, compute.CloudPlatformScope)
		if err != nil {
			return nil, fmt.Errorf("falha ao carregar credenciais: %w", err)
		}
		opts = append(opts, option.WithCredentials(creds))
	}

	return opts, nil
}

// Compute retorna o cliente Compute Engine
func (p *Provider) Compute(ctx context.Context) (*compute.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}
	return service, nil
}

// Storage retorna o cliente Cloud Storage
func (p *Provider) Storage(ctx context.Context) (*storage.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := storage.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar storage client: %w", err)
	}
	return service, nil
}

// KMS retorna o cliente Cloud KMS
func (p *Provider) KMS(ctx context.Context) (*cloudkms.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := cloudkms.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar kms client: %w", err)
	}
	return service, nil
}

// Logging retorna o cliente Cloud Logging
func (p *Provider) Logging(ctx context.Context) (*logging.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := logging.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar logging client: %w", err)
	}
	return service, nil
}

// DNS retorna o cliente Cloud DNS
func (p *Provider) DNS(ctx context.Context) (*dns.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := dns.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar dns client: %w", err)
	}
	return service, nil
}

// BigQuery retorna o cliente BigQuery
func (p *Provider) BigQuery(ctx context.Context) (*bigquery.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := bigquery.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar bigquery client: %w", err)
	}
	return service, nil
}

// SQL retorna o cliente Cloud SQL Admin
func (p *Provider) SQL(ctx context.Context) (*sqladmin.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := sqladmin.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar sql client: %w", err)
	}
	return service, nil
}

// GKE retorna o cliente Kubernetes Engine
func (p *Provider) GKE(ctx context.Context) (*container.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := container.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar gke client: %w", err)
	}
	return service, nil
}

// CloudRun retorna o cliente Cloud Run
func (p *Provider) CloudRun(ctx context.Context) (*run.APIService, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := run.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cloudrun client: %w", err)
	}
	return service, nil
}

// ResourceManager retorna o cliente Cloud Resource Manager
func (p *Provider) ResourceManager(ctx context.Context) (*cloudresourcemanager.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar resourcemanager client: %w", err)
	}
	return service, nil
}

// CloudFunctions retorna o cliente Cloud Functions
func (p *Provider) CloudFunctions(ctx context.Context) (*cloudfunctions.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := cloudfunctions.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cloudfunctions client: %w", err)
	}
	return service, nil
}

// ArtifactRegistry retorna o cliente Artifact Registry
func (p *Provider) ArtifactRegistry(ctx context.Context) (*artifactregistry.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := artifactregistry.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar artifactregistry client: %w", err)
	}
	return service, nil
}

// GCR retorna o cliente Container Analysis (GCR)
func (p *Provider) GCR(ctx context.Context) (*containeranalysis.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := containeranalysis.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar containeranalysis client: %w", err)
	}
	return service, nil
}

// Spanner retorna o cliente Cloud Spanner
func (p *Provider) Spanner(ctx context.Context) (*spanner.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := spanner.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar spanner client: %w", err)
	}
	return service, nil
}

// Dataproc retorna o cliente Cloud Dataproc
func (p *Provider) Dataproc(ctx context.Context) (*dataproc.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := dataproc.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar dataproc client: %w", err)
	}
	return service, nil
}

// BigTable retorna o cliente Cloud BigTable Admin
func (p *Provider) BigTable(ctx context.Context) (*bigtableadmin.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := bigtableadmin.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar bigtable client: %w", err)
	}
	return service, nil
}

// CloudScheduler retorna o cliente Cloud Scheduler
func (p *Provider) CloudScheduler(ctx context.Context) (*cloudscheduler.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := cloudscheduler.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cloudscheduler client: %w", err)
	}
	return service, nil
}

// Filestore retorna o cliente Cloud Filestore
func (p *Provider) Filestore(ctx context.Context) (*file.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := file.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar filestore client: %w", err)
	}
	return service, nil
}

// CloudBuild retorna o cliente Cloud Build
func (p *Provider) CloudBuild(ctx context.Context) (*cloudbuild.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := cloudbuild.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cloudbuild client: %w", err)
	}
	return service, nil
}

// CloudAsset retorna o cliente Cloud Asset Inventory
func (p *Provider) CloudAsset(ctx context.Context) (*cloudasset.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := cloudasset.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cloudasset client: %w", err)
	}
	return service, nil
}

// AccessContextManager retorna o cliente Access Context Manager
func (p *Provider) AccessContextManager(ctx context.Context) (*accesscontextmanager.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := accesscontextmanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar accesscontextmanager client: %w", err)
	}
	return service, nil
}

// IAM retorna o cliente IAM
func (p *Provider) IAM(ctx context.Context) (*iam.Service, error) {
	opts, err := p.clientOptions(ctx)
	if err != nil {
		return nil, err
	}
	service, err := iam.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar iam client: %w", err)
	}
	return service, nil
}

// ProjectID retorna o ID do projeto
func (p *Provider) ProjectID() string {
	return p.projectID
}

// Zone retorna a zona configurada
func (p *Provider) Zone() string {
	return p.zone
}

// Region retorna a região configurada
func (p *Provider) Region() string {
	return p.region
}