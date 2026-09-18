package github

import (
	"context"
	"fmt"

	"github.com/google/go-github/v53/github"
	"golang.org/x/oauth2"
)

// Provider represents an authenticated GitHub client
type Provider struct {
	client *github.Client
	token  string
	orgs   []string
	ctx    context.Context
}

// NewProvider creates a new GitHub provider
func NewProvider(ctx context.Context, token string, orgs []string) *Provider {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)
	return &Provider{client: client, token: token, orgs: orgs, ctx: ctx}
}

// Repositories returns all repositories (for all orgs if specified, otherwise user repos)
func (p *Provider) Repositories() ([]*github.Repository, error) {
	if len(p.orgs) > 0 {
		var allRepos []*github.Repository
		for _, org := range p.orgs {
			opts := &github.RepositoryListByOrgOptions{
				ListOptions: github.ListOptions{PerPage: 100},
			}
			for {
				repos, resp, err := p.client.Repositories.ListByOrg(p.ctx, org, opts)
				if err != nil {
					return nil, fmt.Errorf("failed to list org repos for %s: %w", org, err)
				}
				allRepos = append(allRepos, repos...)
				if resp.NextPage == 0 {
					break
				}
				opts.Page = resp.NextPage
			}
		}
		return allRepos, nil
	}

	opts := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}
	var allRepos []*github.Repository
	for {
		repos, resp, err := p.client.Repositories.List(p.ctx, "", opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list repos: %w", err)
		}
		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return allRepos, nil
}

// Organizations returns all organizations
func (p *Provider) Organizations() ([]*github.Organization, error) {
	opts := &github.ListOptions{PerPage: 100}
	var allOrgs []*github.Organization
	for {
		orgs, resp, err := p.client.Organizations.List(p.ctx, "", opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list orgs: %w", err)
		}
		allOrgs = append(allOrgs, orgs...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return allOrgs, nil
}

// GetBranchProtection returns branch protection for a repo
func (p *Provider) GetBranchProtection(ctx context.Context, owner, repo, branch string) (*github.Protection, error) {
	protection, _, err := p.client.Repositories.GetBranchProtection(ctx, owner, repo, branch)
	return protection, err
}

// GetRulesets returns rulesets for a repo
func (p *Provider) GetRulesets(ctx context.Context, owner, repo string) ([]*github.Ruleset, error) {
	rulesets, _, err := p.client.Repositories.GetAllRulesets(ctx, owner, repo, false)
	return rulesets, err
}

// GetRepository returns a specific repository
func (p *Provider) GetRepository(ctx context.Context, owner, repo string) (*github.Repository, error) {
	repository, _, err := p.client.Repositories.Get(ctx, owner, repo)
	return repository, err
}

// GetSecretScanningAlerts returns secret scanning alerts for a repo
func (p *Provider) GetSecretScanningAlerts(ctx context.Context, owner, repo string) ([]*github.SecretScanningAlert, error) {
	opts := &github.SecretScanningAlertListOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}
	var allAlerts []*github.SecretScanningAlert
	for {
		alerts, resp, err := p.client.SecretScanning.ListAlertsForRepo(ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list secret scanning alerts: %w", err)
		}
		allAlerts = append(allAlerts, alerts...)
		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}
	return allAlerts, nil
}

// GetDependabotAlerts returns dependabot alerts for a repo
func (p *Provider) GetDependabotAlerts(ctx context.Context, owner, repo string) ([]*github.DependabotAlert, error) {
	opts := &github.ListAlertsOptions{
		ListCursorOptions: github.ListCursorOptions{
			PerPage: 100,
		},
	}
	var allAlerts []*github.DependabotAlert
	for {
		alerts, resp, err := p.client.Dependabot.ListRepoAlerts(ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list dependabot alerts: %w", err)
		}
		allAlerts = append(allAlerts, alerts...)
		if resp.Cursor == "" {
			break
		}
		opts.Cursor = resp.Cursor
	}
	return allAlerts, nil
}

// ListOrganizationMembers returns members of an organization
func (p *Provider) ListOrganizationMembers(ctx context.Context, org string) ([]*github.User, error) {
	opts := &github.ListMembersOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}
	var allMembers []*github.User
	for {
		members, resp, err := p.client.Organizations.ListMembers(ctx, org, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list org members: %w", err)
		}
		allMembers = append(allMembers, members...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return allMembers, nil
}

// Client returns the underlying github client for direct API access
func (p *Provider) Client() *github.Client {
	return p.client
}
