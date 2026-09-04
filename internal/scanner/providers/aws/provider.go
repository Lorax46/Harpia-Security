package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Provider representa um cliente AWS autenticado
type Provider struct {
	region    string
	accessKey string
	secretKey string
	cfg       aws.Config
}

// NewProvider cria um novo provider AWS
func NewProvider(ctx context.Context, region, accessKey, secretKey string) (*Provider, error) {
	if region == "" {
		region = "us-east-1"
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(
			aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     accessKey,
					SecretAccessKey: secretKey,
				}, nil
			}),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("falha ao carregar config AWS: %w", err)
	}

	return &Provider{
		region:    region,
		accessKey: accessKey,
		secretKey: secretKey,
		cfg:       cfg,
	}, nil
}

// IAM retorna o cliente IAM
func (p *Provider) IAM() (*iam.Client, error) {
	return iam.NewFromConfig(p.cfg), nil
}

// EC2 retorna o cliente EC2
func (p *Provider) EC2() (*ec2.Client, error) {
	return ec2.NewFromConfig(p.cfg), nil
}

// S3 retorna o cliente S3
func (p *Provider) S3() (*s3.Client, error) {
	return s3.NewFromConfig(p.cfg), nil
}

// STS retorna o cliente STS
func (p *Provider) STS() (*sts.Client, error) {
	return sts.NewFromConfig(p.cfg), nil
}

// Region retorna a região configurada
func (p *Provider) Region() string {
	return p.region
}

// AccountId retorna o ID da conta AWS
func (p *Provider) AccountId() string {
	client, _ := p.STS()
	if client == nil {
		return ""
	}
	identity, err := client.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return ""
	}
	return *identity.Account
}
