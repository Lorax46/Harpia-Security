package ec2

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// Ec2InstanceAccountImdsv2Enabled - IMDSv2 is required by default for EC2 instances at the account level
type Ec2InstanceAccountImdsv2Enabled struct {
    metadata models.CheckMetadata
}

func NewEc2InstanceAccountImdsv2Enabled() *Ec2InstanceAccountImdsv2Enabled {
    return &Ec2InstanceAccountImdsv2Enabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_account_imdsv2_enabled",
            CheckTitle: "IMDSv2 is required by default for EC2 instances at the account level",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 account IMDS defaults** with `http_tokens`=`required` ensure new instances in the Region use **IMDSv2** by default and disable IMDSv1. *Existing instances keep their current setting.*",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstanceAccountImdsv2Enabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstanceAccountImdsv2Enabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2ConfidentialWorkloadHostVsockProxyExposed - Confidential-workload host does not expose likely vsock-proxy TCP ports to the internet
type Ec2ConfidentialWorkloadHostVsockProxyExposed struct {
    metadata models.CheckMetadata
}

func NewEc2ConfidentialWorkloadHostVsockProxyExposed() *Ec2ConfidentialWorkloadHostVsockProxyExposed {
    return &Ec2ConfidentialWorkloadHostVsockProxyExposed{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_confidential_workload_host_vsock_proxy_exposed",
            CheckTitle: "Confidential-workload host does not expose likely vsock-proxy TCP ports to the internet",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "Hosts of **Nitro Enclave** workloads are evaluated for unrestricted ingress on TCP ports commonly used by *vsock-proxy* applications (`enclave_vsock_ports`, default `[5000, 8000-8090, 9000]`). vsock is AF_VSOCK, but proxy applications bridge to TCP; this heuristic targets the bridge. Assesses the host environment only.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2ConfidentialWorkloadHostVsockProxyExposed) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2ConfidentialWorkloadHostVsockProxyExposed) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2NetworkaclAllowIngressTcpPort3389 - Network ACL does not allow ingress from the Internet to TCP port 3389 (RDP)
type Ec2NetworkaclAllowIngressTcpPort3389 struct {
    metadata models.CheckMetadata
}

func NewEc2NetworkaclAllowIngressTcpPort3389() *Ec2NetworkaclAllowIngressTcpPort3389 {
    return &Ec2NetworkaclAllowIngressTcpPort3389{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_networkacl_allow_ingress_tcp_port_3389",
            CheckTitle: "Network ACL does not allow ingress from the Internet to TCP port 3389 (RDP)",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "**VPC network ACLs** with inbound rules allowing **RDP** on `TCP 3389` from `0.0.0.0/0` are identified.  Assessment focuses on subnet-level ACL entries that permit this traffic.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2NetworkaclAllowIngressTcpPort3389) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2NetworkaclAllowIngressTcpPort3389) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2EbsPublicSnapshot - EBS snapshot is not public
type Ec2EbsPublicSnapshot struct {
    metadata models.CheckMetadata
}

func NewEc2EbsPublicSnapshot() *Ec2EbsPublicSnapshot {
    return &Ec2EbsPublicSnapshot{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_ebs_public_snapshot",
            CheckTitle: "EBS snapshot is not public",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EBS snapshots** with **public sharing** permissions (accessible by all AWS accounts) are identified, as opposed to snapshots shared privately with specific accounts.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2EbsPublicSnapshot) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2EbsPublicSnapshot) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2ConfidentialWorkloadHostUnrestrictedIngress - Confidential-workload host does not expose non-standard ports to the internet
type Ec2ConfidentialWorkloadHostUnrestrictedIngress struct {
    metadata models.CheckMetadata
}

func NewEc2ConfidentialWorkloadHostUnrestrictedIngress() *Ec2ConfidentialWorkloadHostUnrestrictedIngress {
    return &Ec2ConfidentialWorkloadHostUnrestrictedIngress{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_confidential_workload_host_unrestricted_ingress",
            CheckTitle: "Confidential-workload host does not expose non-standard ports to the internet",
            ServiceName: "ec2",
            Severity: "high",
            Description: "Hosts of **Nitro Enclave** workloads are evaluated for unrestricted ingress (`0.0.0.0/0` or `::/0`) on TCP/UDP ports outside a configurable allow-list (`enclave_sg_allow_ports`, default `[22, 80, 443]`). Aggregates ingress across every security group attached to the host. Assesses the host environment only.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2ConfidentialWorkloadHostUnrestrictedIngress) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2ConfidentialWorkloadHostUnrestrictedIngress) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortElasticsearchKibanaExposedToInternet - EC2 instance does not allow ingress from the Internet to Elasticsearch and Kibana ports (TCP 9200, 9300, 5601)
type Ec2InstancePortElasticsearchKibanaExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortElasticsearchKibanaExposedToInternet() *Ec2InstancePortElasticsearchKibanaExposedToInternet {
    return &Ec2InstancePortElasticsearchKibanaExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_elasticsearch_kibana_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to Elasticsearch and Kibana ports (TCP 9200, 9300, 5601)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** with **Elasticsearch/Kibana ports** (`9200`, `9300`, `5601`) exposed to the Internet through inbound security group rules.  Assesses reachability considering instance public IP and subnet to reflect real exposure.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortElasticsearchKibanaExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortElasticsearchKibanaExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPortCassandra719991608888 - Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Cassandra TCP ports 7199, 9160, or 8888
type Ec2SecuritygroupAllowIngressFromInternetToTcpPortCassandra719991608888 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPortCassandra719991608888() *Ec2SecuritygroupAllowIngressFromInternetToTcpPortCassandra719991608888 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPortCassandra719991608888{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888",
            CheckTitle: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Cassandra TCP ports 7199, 9160, or 8888",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** are evaluated for inbound rules that allow the Internet (`0.0.0.0/0` or `::/0`) to reach **Cassandra ports** `7199`, `9160`, or `8888`.  Focuses on `tcp` rules that expose these ports to public sources.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortCassandra719991608888) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortCassandra719991608888) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortMemcachedExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP port 11211 (Memcached)
type Ec2InstancePortMemcachedExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortMemcachedExposedToInternet() *Ec2InstancePortMemcachedExposedToInternet {
    return &Ec2InstancePortMemcachedExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_memcached_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP port 11211 (Memcached)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** are evaluated for **open Memcached access**: inbound `TCP 11211` allowed from any address (`0.0.0.0/0` or `::/0`) via their security groups, considering the instance's public exposure.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortMemcachedExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortMemcachedExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2ElasticIpUnassigned - Elastic IP is associated with an instance or network interface
type Ec2ElasticIpUnassigned struct {
    metadata models.CheckMetadata
}

func NewEc2ElasticIpUnassigned() *Ec2ElasticIpUnassigned {
    return &Ec2ElasticIpUnassigned{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_elastic_ip_unassigned",
            CheckTitle: "Elastic IP is associated with an instance or network interface",
            ServiceName: "ec2",
            Severity: "low",
            Description: "**EC2 Elastic IPs** that are allocated but **not associated** with any instance or network interface. The evaluation identifies EIPs present in the account without an active association.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2ElasticIpUnassigned) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2ElasticIpUnassigned) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstanceImdsv2Enabled - EC2 instance requires IMDSv2 or has the instance metadata service disabled
type Ec2InstanceImdsv2Enabled struct {
    metadata models.CheckMetadata
}

func NewEc2InstanceImdsv2Enabled() *Ec2InstanceImdsv2Enabled {
    return &Ec2InstanceImdsv2Enabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_imdsv2_enabled",
            CheckTitle: "EC2 instance requires IMDSv2 or has the instance metadata service disabled",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 instances** are evaluated for **IMDSv2 enforcement**: metadata endpoint enabled with `http_tokens: required`, or metadata service fully disabled (`http_endpoint: disabled`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstanceImdsv2Enabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstanceImdsv2Enabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstanceOlderThanSpecificDays - EC2 instance is not older than the configured maximum age or is not running
type Ec2InstanceOlderThanSpecificDays struct {
    metadata models.CheckMetadata
}

func NewEc2InstanceOlderThanSpecificDays() *Ec2InstanceOlderThanSpecificDays {
    return &Ec2InstanceOlderThanSpecificDays{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_older_than_specific_days",
            CheckTitle: "EC2 instance is not older than the configured maximum age or is not running",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "**EC2 instances** are evaluated for age while in `running` state. Instances launched beyond the configurable limit (`max_ec2_instance_age_in_days`, default `180`) are flagged as older than the allowed lifetime. Stopped instances are ignored.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstanceOlderThanSpecificDays) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstanceOlderThanSpecificDays) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowWideOpenPublicIpv4 - Security group has no ingress or egress rules with public IPv4 CIDR ranges from /1 to /23
type Ec2SecuritygroupAllowWideOpenPublicIpv4 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowWideOpenPublicIpv4() *Ec2SecuritygroupAllowWideOpenPublicIpv4 {
    return &Ec2SecuritygroupAllowWideOpenPublicIpv4{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_wide_open_public_ipv4",
            CheckTitle: "Security group has no ingress or egress rules with public IPv4 CIDR ranges from /1 to /23",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** with rules that permit non-RFC1918 IPv4 ranges wider than `/24` are identified across both **ingress** and **egress**.  The focus is on public CIDRs (`/1`-`/23`) that broadly expose sources or destinations, not on private networks.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowWideOpenPublicIpv4) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowWideOpenPublicIpv4) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortCassandraExposedToInternet - EC2 instance does not have Cassandra ports (TCP 7000, 7001, 7199, 9042, 9160) open to the Internet
type Ec2InstancePortCassandraExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortCassandraExposedToInternet() *Ec2InstancePortCassandraExposedToInternet {
    return &Ec2InstancePortCassandraExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_cassandra_exposed_to_internet",
            CheckTitle: "EC2 instance does not have Cassandra ports (TCP 7000, 7001, 7199, 9042, 9160) open to the Internet",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** have **Cassandra service ports** (`7000`, `7001`, `7199`, `9042`, `9160`) reachable from the Internet through security group ingress.  Public IP presence and subnet exposure are considered to assess external reachability.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortCassandraExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortCassandraExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToAnyPort - Security group has no 0.0.0.0/0 or ::/0 ingress to any port, or is attached only to allowed interface types or instance owners
type Ec2SecuritygroupAllowIngressFromInternetToAnyPort struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToAnyPort() *Ec2SecuritygroupAllowIngressFromInternetToAnyPort {
    return &Ec2SecuritygroupAllowIngressFromInternetToAnyPort{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
            CheckTitle: "Security group has no 0.0.0.0/0 or ::/0 ingress to any port, or is attached only to allowed interface types or instance owners",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** with **internet-sourced ingress** from `0.0.0.0/0` or `::/0` to any port, and their attachments, are evaluated. Groups linked to network interfaces or instance owners outside an approved list for public exposure are identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToAnyPort) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToAnyPort) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPortMemcached11211 - Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Memcached TCP port 11211
type Ec2SecuritygroupAllowIngressFromInternetToTcpPortMemcached11211 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPortMemcached11211() *Ec2SecuritygroupAllowIngressFromInternetToTcpPortMemcached11211 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPortMemcached11211{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211",
            CheckTitle: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Memcached TCP port 11211",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** are evaluated for inbound rules that permit Internet-sourced access to `TCP 11211` (Memcached) from `0.0.0.0/0` or `::/0`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortMemcached11211) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortMemcached11211) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2LaunchTemplateNoSecrets - EC2 launch template user data contains no secrets in any version
type Ec2LaunchTemplateNoSecrets struct {
    metadata models.CheckMetadata
}

func NewEc2LaunchTemplateNoSecrets() *Ec2LaunchTemplateNoSecrets {
    return &Ec2LaunchTemplateNoSecrets{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_launch_template_no_secrets",
            CheckTitle: "EC2 launch template user data contains no secrets in any version",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 launch template** user data is analyzed across versions to identify embedded secrets-hard-coded passwords, tokens, API keys, or private keys-within the startup scripts or configuration supplied to instances.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2LaunchTemplateNoSecrets) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2LaunchTemplateNoSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2EbsSnapshotsEncrypted - EBS snapshot is encrypted
type Ec2EbsSnapshotsEncrypted struct {
    metadata models.CheckMetadata
}

func NewEc2EbsSnapshotsEncrypted() *Ec2EbsSnapshotsEncrypted {
    return &Ec2EbsSnapshotsEncrypted{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_ebs_snapshots_encrypted",
            CheckTitle: "EBS snapshot is encrypted",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EBS snapshots** are evaluated for **encryption at rest** with AWS KMS. The finding identifies snapshots where encryption is not enabled.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2EbsSnapshotsEncrypted) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2EbsSnapshotsEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2EbsVolumeSnapshotsExists - EBS volume has at least one snapshot
type Ec2EbsVolumeSnapshotsExists struct {
    metadata models.CheckMetadata
}

func NewEc2EbsVolumeSnapshotsExists() *Ec2EbsVolumeSnapshotsExists {
    return &Ec2EbsVolumeSnapshotsExists{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_ebs_volume_snapshots_exists",
            CheckTitle: "EBS volume has at least one snapshot",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EBS volumes** are evaluated for the existence of at least one associated **snapshot**, identifying volumes without any point-in-time backup available.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2EbsVolumeSnapshotsExists) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2EbsVolumeSnapshotsExists) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortMysqlExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP port 3306 (MySQL)
type Ec2InstancePortMysqlExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortMysqlExposedToInternet() *Ec2InstancePortMysqlExposedToInternet {
    return &Ec2InstancePortMysqlExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_mysql_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP port 3306 (MySQL)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** with security groups that expose **MySQL** on `TCP 3306` to the Internet (`0.0.0.0/0` or `::/0`) are identified, with context on public IP and subnet exposure.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortMysqlExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortMysqlExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToAnyPortFromIp - Security group does not have any port open to a specific public IP address
type Ec2SecuritygroupAllowIngressFromInternetToAnyPortFromIp struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToAnyPortFromIp() *Ec2SecuritygroupAllowIngressFromInternetToAnyPortFromIp {
    return &Ec2SecuritygroupAllowIngressFromInternetToAnyPortFromIp{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip",
            CheckTitle: "Security group does not have any port open to a specific public IP address",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "EC2 security groups with inbound rules allowing traffic from specific globally routable IP addresses to any port or protocol. Wildcard CIDRs (0.0.0.0/0 and ::/0) are excluded as they are covered by the related checks. This targets cases where developers add personal or third-party IPs directly to security groups.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToAnyPortFromIp) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToAnyPortFromIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstanceUsesSingleEni - EC2 instance has no more than one Elastic Network Interface (ENI) attached
type Ec2InstanceUsesSingleEni struct {
    metadata models.CheckMetadata
}

func NewEc2InstanceUsesSingleEni() *Ec2InstanceUsesSingleEni {
    return &Ec2InstanceUsesSingleEni{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_uses_single_eni",
            CheckTitle: "EC2 instance has no more than one Elastic Network Interface (ENI) attached",
            ServiceName: "ec2",
            Severity: "low",
            Description: "**EC2 instances** are evaluated for attached network adapters. It identifies instances with more than one `ENI`-including `efa`, `interface`, or `trunk` types-and distinguishes those using a single adapter.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstanceUsesSingleEni) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstanceUsesSingleEni) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToAllPorts - Security group does not have all ports open to the Internet
type Ec2SecuritygroupAllowIngressFromInternetToAllPorts struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToAllPorts() *Ec2SecuritygroupAllowIngressFromInternetToAllPorts {
    return &Ec2SecuritygroupAllowIngressFromInternetToAllPorts{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
            CheckTitle: "Security group does not have all ports open to the Internet",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 security groups** with **inbound rules** permitting Internet sources (`0.0.0.0/0`, `::/0`) to `all ports` across any protocol",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToAllPorts) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToAllPorts) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2AmiAccountBlockPublicAccess - AMI block public access is enabled at the account level
type Ec2AmiAccountBlockPublicAccess struct {
    metadata models.CheckMetadata
}

func NewEc2AmiAccountBlockPublicAccess() *Ec2AmiAccountBlockPublicAccess {
    return &Ec2AmiAccountBlockPublicAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_ami_account_block_public_access",
            CheckTitle: "AMI block public access is enabled at the account level",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "AMI block public access configuration is assessed to see whether public sharing of AMIs is blocked in the account and Region. When enabled (`block-new-sharing`), no AMI in the Region can be made public regardless of individual image permissions.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2AmiAccountBlockPublicAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2AmiAccountBlockPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePublicIp - EC2 instance does not have a public IP address
type Ec2InstancePublicIp struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePublicIp() *Ec2InstancePublicIp {
    return &Ec2InstancePublicIp{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_public_ip",
            CheckTitle: "EC2 instance does not have a public IP address",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "**EC2 instances** are assessed for the presence of a **public IPv4 address** and public DNS. A public IP indicates the instance is directly reachable from the Internet; no public IP implies access only through private networking paths such as load balancers, gateways, or proxies.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePublicIp) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePublicIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2LaunchTemplateImdsv2Required - EC2 launch template has IMDSv2 enabled and required or instance metadata service disabled
type Ec2LaunchTemplateImdsv2Required struct {
    metadata models.CheckMetadata
}

func NewEc2LaunchTemplateImdsv2Required() *Ec2LaunchTemplateImdsv2Required {
    return &Ec2LaunchTemplateImdsv2Required{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_launch_template_imdsv2_required",
            CheckTitle: "EC2 launch template has IMDSv2 enabled and required or instance metadata service disabled",
            ServiceName: "ec2",
            Severity: "high",
            Description: "EC2 launch templates are inspected for **Instance Metadata Service** configuration. It identifies versions where `http_endpoint` is `enabled` and `http_tokens` is `required` (IMDSv2 enforced), versions with the metadata service `disabled`, and versions that allow metadata without requiring tokens.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2LaunchTemplateImdsv2Required) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2LaunchTemplateImdsv2Required) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstanceManagedBySsm - EC2 instance is managed by AWS Systems Manager or not running
type Ec2InstanceManagedBySsm struct {
    metadata models.CheckMetadata
}

func NewEc2InstanceManagedBySsm() *Ec2InstanceManagedBySsm {
    return &Ec2InstanceManagedBySsm{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_managed_by_ssm",
            CheckTitle: "EC2 instance is managed by AWS Systems Manager or not running",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "**EC2 instances** are assessed for enrollment as **Systems Manager managed nodes**. Running instances lacking Systems Manager registration are marked as unmanaged; instances in `stopped`, `terminated`, or `pending` states are noted separately.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstanceManagedBySsm) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstanceManagedBySsm) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortTelnetExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP port 23 (Telnet)
type Ec2InstancePortTelnetExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortTelnetExposedToInternet() *Ec2InstancePortTelnetExposedToInternet {
    return &Ec2InstancePortTelnetExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_telnet_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP port 23 (Telnet)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "EC2 instances with security groups allowing inbound **Telnet** on `TCP 23` from the Internet are identified, including open IPv4/IPv6 sources like `0.0.0.0/0` and `::/0`.  Exposure is evaluated considering public IP assignment and subnet reachability.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortTelnetExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortTelnetExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortLdapExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP ports 389 or 636 (LDAP/LDAPS)
type Ec2InstancePortLdapExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortLdapExposedToInternet() *Ec2InstancePortLdapExposedToInternet {
    return &Ec2InstancePortLdapExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_ldap_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP ports 389 or 636 (LDAP/LDAPS)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** with security groups permitting Internet-sourced access to **LDAP** on `TCP 389` or **LDAPS** on `TCP 636` are identified.  Public exposure context (presence of public IP and subnet reachability) is considered to gauge how broadly these ports can be accessed.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortLdapExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortLdapExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstanceWithOutdatedAmi - EC2 instance uses a non-deprecated Amazon AMI
type Ec2InstanceWithOutdatedAmi struct {
    metadata models.CheckMetadata
}

func NewEc2InstanceWithOutdatedAmi() *Ec2InstanceWithOutdatedAmi {
    return &Ec2InstanceWithOutdatedAmi{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_with_outdated_ami",
            CheckTitle: "EC2 instance uses a non-deprecated Amazon AMI",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "**EC2 instances** launched from **Amazon-owned AMIs** are evaluated for the AMI's `DeprecationTime`; instances tied to images with a deprecation date in the past are reported as using **deprecated AMIs**.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstanceWithOutdatedAmi) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstanceWithOutdatedAmi) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupWithManyIngressEgressRules - Security group has 50 or fewer inbound rules and 50 or fewer outbound rules
type Ec2SecuritygroupWithManyIngressEgressRules struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupWithManyIngressEgressRules() *Ec2SecuritygroupWithManyIngressEgressRules {
    return &Ec2SecuritygroupWithManyIngressEgressRules{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_with_many_ingress_egress_rules",
            CheckTitle: "Security group has 50 or fewer inbound rules and 50 or fewer outbound rules",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "**EC2 security groups** are evaluated for excessive rule counts, flagging groups where `ingress` or `egress` entries exceed the configured threshold (default `50`). This targets groups with unusually large rule sets that complicate access control.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupWithManyIngressEgressRules) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupWithManyIngressEgressRules) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupFromLaunchWizard - Security group not created using the EC2 Launch Wizard
type Ec2SecuritygroupFromLaunchWizard struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupFromLaunchWizard() *Ec2SecuritygroupFromLaunchWizard {
    return &Ec2SecuritygroupFromLaunchWizard{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_from_launch_wizard",
            CheckTitle: "Security group not created using the EC2 Launch Wizard",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "**EC2 security groups** whose names include `launch-wizard` are identified as created by the **EC2 Launch Wizard**, distinguishing auto-generated groups from curated, baseline-controlled groups.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupFromLaunchWizard) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupFromLaunchWizard) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortSqlserverExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP ports 1433 or 1434 (SQL Server)
type Ec2InstancePortSqlserverExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortSqlserverExposedToInternet() *Ec2InstancePortSqlserverExposedToInternet {
    return &Ec2InstancePortSqlserverExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_sqlserver_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP ports 1433 or 1434 (SQL Server)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** with security groups permitting any source to `TCP 1433` or `1434` (SQL Server) are identified, considering the instance's public reachability based on IP and subnet exposure.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortSqlserverExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortSqlserverExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstanceProfileAttached - EC2 instance is associated with an IAM instance profile role
type Ec2InstanceProfileAttached struct {
    metadata models.CheckMetadata
}

func NewEc2InstanceProfileAttached() *Ec2InstanceProfileAttached {
    return &Ec2InstanceProfileAttached{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_profile_attached",
            CheckTitle: "EC2 instance is associated with an IAM instance profile role",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "**EC2 instances** are evaluated for association with an **IAM instance profile role** that delivers temporary credentials to workloads running on the instance",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstanceProfileAttached) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstanceProfileAttached) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2ConfidentialWorkloadHostNotRunning - Nitro Enclave parent instance is in the running state
type Ec2ConfidentialWorkloadHostNotRunning struct {
    metadata models.CheckMetadata
}

func NewEc2ConfidentialWorkloadHostNotRunning() *Ec2ConfidentialWorkloadHostNotRunning {
    return &Ec2ConfidentialWorkloadHostNotRunning{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_confidential_workload_host_not_running",
            CheckTitle: "Nitro Enclave parent instance is in the running state",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "**Nitro Enclave** parent instances are evaluated against the EC2 lifecycle: the instance state must not be `stopped`, `shutting-down`, or `terminated`. Enclaves are destroyed when their parent stops, so any consumer depending on enclave availability breaks if the parent moves to a terminal state. Transient states (`pending`, `stopping`) are reported as PASS with a note.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2ConfidentialWorkloadHostNotRunning) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2ConfidentialWorkloadHostNotRunning) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2NetworkaclUnused - Non-default network ACL is associated with a subnet
type Ec2NetworkaclUnused struct {
    metadata models.CheckMetadata
}

func NewEc2NetworkaclUnused() *Ec2NetworkaclUnused {
    return &Ec2NetworkaclUnused{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_networkacl_unused",
            CheckTitle: "Non-default network ACL is associated with a subnet",
            ServiceName: "ec2",
            Severity: "low",
            Description: "**VPC network ACLs** that are **not associated with any subnet** are considered unused. The evaluation focuses on non-default ACLs and identifies those without a current subnet association; the default network ACL is excluded.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2NetworkaclUnused) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2NetworkaclUnused) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPortTelnet23 - Security group does not allow ingress from the Internet to TCP port 23 (Telnet)
type Ec2SecuritygroupAllowIngressFromInternetToTcpPortTelnet23 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPortTelnet23() *Ec2SecuritygroupAllowIngressFromInternetToTcpPortTelnet23 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPortTelnet23{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23",
            CheckTitle: "Security group does not allow ingress from the Internet to TCP port 23 (Telnet)",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** are evaluated for rules that allow **inbound Telnet** on `TCP 23` from the Internet (`0.0.0.0/0` or `::/0`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortTelnet23) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortTelnet23) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPortFtp2021 - Security group does not allow ingress from 0.0.0.0/0 or ::/0 to FTP ports 20 or 21
type Ec2SecuritygroupAllowIngressFromInternetToTcpPortFtp2021 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPortFtp2021() *Ec2SecuritygroupAllowIngressFromInternetToTcpPortFtp2021 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPortFtp2021{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_ftp_20_21",
            CheckTitle: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to FTP ports 20 or 21",
            ServiceName: "ec2",
            Severity: "high",
            Description: "EC2 security groups are evaluated for Internet-exposed **FTP**: any inbound rule allowing `tcp` ports `20` or `21` from `0.0.0.0/0` or `::/0`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortFtp2021) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortFtp2021) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2NetworkaclAllowIngressAnyPort - Network ACL does not allow ingress from 0.0.0.0/0 to any port
type Ec2NetworkaclAllowIngressAnyPort struct {
    metadata models.CheckMetadata
}

func NewEc2NetworkaclAllowIngressAnyPort() *Ec2NetworkaclAllowIngressAnyPort {
    return &Ec2NetworkaclAllowIngressAnyPort{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_networkacl_allow_ingress_any_port",
            CheckTitle: "Network ACL does not allow ingress from 0.0.0.0/0 to any port",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**VPC network ACLs** with **inbound entries** that permit traffic from `0.0.0.0/0` to any port (any protocol) are identified at the subnet boundary.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2NetworkaclAllowIngressAnyPort) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2NetworkaclAllowIngressAnyPort) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPortPostgres5432 - Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Postgres TCP port 5432
type Ec2SecuritygroupAllowIngressFromInternetToTcpPortPostgres5432 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPortPostgres5432() *Ec2SecuritygroupAllowIngressFromInternetToTcpPortPostgres5432 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPortPostgres5432{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432",
            CheckTitle: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Postgres TCP port 5432",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** are evaluated for inbound rules that expose **Postgres** on `TCP 5432` to the Internet. Rules permitting `0.0.0.0/0` or `::/0` to this port, or policies that open all ports publicly, are identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortPostgres5432) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortPostgres5432) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2ConfidentialWorkloadHostImdsv2NotEnforced - Confidential-workload host enforces IMDSv2
type Ec2ConfidentialWorkloadHostImdsv2NotEnforced struct {
    metadata models.CheckMetadata
}

func NewEc2ConfidentialWorkloadHostImdsv2NotEnforced() *Ec2ConfidentialWorkloadHostImdsv2NotEnforced {
    return &Ec2ConfidentialWorkloadHostImdsv2NotEnforced{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_confidential_workload_host_imdsv2_not_enforced",
            CheckTitle: "Confidential-workload host enforces IMDSv2",
            ServiceName: "ec2",
            Severity: "high",
            Description: "Instances hosting **Nitro Enclave** workloads (`EnclaveOptions.Enabled=true`) are evaluated for **IMDSv2 enforcement** on the metadata service (`HttpTokens=required`). This check assesses the host environment; it does not audit the enclave itself.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2ConfidentialWorkloadHostImdsv2NotEnforced) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2ConfidentialWorkloadHostImdsv2NotEnforced) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2EbsVolumeEncryption - EBS volume is encrypted
type Ec2EbsVolumeEncryption struct {
    metadata models.CheckMetadata
}

func NewEc2EbsVolumeEncryption() *Ec2EbsVolumeEncryption {
    return &Ec2EbsVolumeEncryption{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_ebs_volume_encryption",
            CheckTitle: "EBS volume is encrypted",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EBS volumes** are assessed for **encryption at rest** using **AWS KMS**.  The finding identifies volumes whose `encrypted` state is disabled, meaning data is stored unencrypted on block storage.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2EbsVolumeEncryption) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2EbsVolumeEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2TransitgatewayAutoAcceptVpcAttachments - Amazon EC2 Transit Gateway does not automatically accept shared VPC attachments
type Ec2TransitgatewayAutoAcceptVpcAttachments struct {
    metadata models.CheckMetadata
}

func NewEc2TransitgatewayAutoAcceptVpcAttachments() *Ec2TransitgatewayAutoAcceptVpcAttachments {
    return &Ec2TransitgatewayAutoAcceptVpcAttachments{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_transitgateway_auto_accept_vpc_attachments",
            CheckTitle: "Amazon EC2 Transit Gateway does not automatically accept shared VPC attachments",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 Transit Gateways** with `AutoAcceptSharedAttachments=enable` automatically approve cross-account **VPC attachments**.  The evaluation identifies transit gateways configured to auto-accept shared attachments.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2TransitgatewayAutoAcceptVpcAttachments) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2TransitgatewayAutoAcceptVpcAttachments) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPortOracle15212483 - Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Oracle TCP ports 1521 or 2483
type Ec2SecuritygroupAllowIngressFromInternetToTcpPortOracle15212483 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPortOracle15212483() *Ec2SecuritygroupAllowIngressFromInternetToTcpPortOracle15212483 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPortOracle15212483{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483",
            CheckTitle: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Oracle TCP ports 1521 or 2483",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** are evaluated for inbound rules that permit public sources (`0.0.0.0/0` or `::/0`) to `TCP 1521` or `TCP 2483`-Oracle listener ports.  The focus is on rules that make these ports reachable from the Internet over IPv4 or IPv6.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortOracle15212483) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortOracle15212483) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortCifsExposedToInternet - EC2 instance does not allow Internet ingress to TCP ports 139 or 445 (CIFS)
type Ec2InstancePortCifsExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortCifsExposedToInternet() *Ec2InstancePortCifsExposedToInternet {
    return &Ec2InstancePortCifsExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_cifs_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow Internet ingress to TCP ports 139 or 445 (CIFS)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** with security groups permitting **inbound** TCP `139` or `445` (**CIFS/SMB**) from `0.0.0.0/0` are identified.  Exposure level reflects whether the instance has a **public IP** and the subnet's Internet reachability.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortCifsExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortCifsExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstanceDetailedMonitoringEnabled - EC2 instance has detailed monitoring enabled
type Ec2InstanceDetailedMonitoringEnabled struct {
    metadata models.CheckMetadata
}

func NewEc2InstanceDetailedMonitoringEnabled() *Ec2InstanceDetailedMonitoringEnabled {
    return &Ec2InstanceDetailedMonitoringEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_detailed_monitoring_enabled",
            CheckTitle: "EC2 instance has detailed monitoring enabled",
            ServiceName: "ec2",
            Severity: "low",
            Description: "**EC2 instances** are assessed for **CloudWatch detailed monitoring**, indicating whether 1-minute metrics collection is enabled.  Instances lacking this setting provide only 5-minute metrics.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstanceDetailedMonitoringEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstanceDetailedMonitoringEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstanceParavirtualType - EC2 instance virtualization type is HVM
type Ec2InstanceParavirtualType struct {
    metadata models.CheckMetadata
}

func NewEc2InstanceParavirtualType() *Ec2InstanceParavirtualType {
    return &Ec2InstanceParavirtualType{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_paravirtual_type",
            CheckTitle: "EC2 instance virtualization type is HVM",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "**EC2 instances** are evaluated for their virtualization mode. Instances with `virtualization_type` set to `paravirtual` are identified; those using **HVM** are recognized as hardware-assisted virtualization.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstanceParavirtualType) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstanceParavirtualType) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPortElasticsearchKibana920093005601 - Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Elasticsearch/Kibana TCP ports 9200, 9300, and 5601
type Ec2SecuritygroupAllowIngressFromInternetToTcpPortElasticsearchKibana920093005601 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPortElasticsearchKibana920093005601() *Ec2SecuritygroupAllowIngressFromInternetToTcpPortElasticsearchKibana920093005601 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPortElasticsearchKibana920093005601{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601",
            CheckTitle: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Elasticsearch/Kibana TCP ports 9200, 9300, and 5601",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** restrict public ingress to Elasticsearch/Kibana ports `9200`, `9300`, and `5601`, denying sources `0.0.0.0/0` and `::/0`",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortElasticsearchKibana920093005601) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortElasticsearchKibana920093005601) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortSshExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP port 22 (SSH)
type Ec2InstancePortSshExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortSshExposedToInternet() *Ec2InstancePortSshExposedToInternet {
    return &Ec2InstancePortSshExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_ssh_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP port 22 (SSH)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** with **SSH (TCP 22)** exposed to the Internet via security group inbound rules allowing `0.0.0.0/0` or `::/0`.  Exposure is qualified using the instance's public IP status and subnet reachability.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortSshExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortSshExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2EbsSnapshotAccountBlockPublicAccess - All EBS snapshots have public access blocked
type Ec2EbsSnapshotAccountBlockPublicAccess struct {
    metadata models.CheckMetadata
}

func NewEc2EbsSnapshotAccountBlockPublicAccess() *Ec2EbsSnapshotAccountBlockPublicAccess {
    return &Ec2EbsSnapshotAccountBlockPublicAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_ebs_snapshot_account_block_public_access",
            CheckTitle: "All EBS snapshots have public access blocked",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EBS snapshots** account/Region configuration for **Block Public Access** is assessed to see whether public sharing is fully blocked (`block-all-sharing`) versus only new sharing (`block-new-sharing`) or unblocked. The state indicates if any snapshot can be publicly shared.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2EbsSnapshotAccountBlockPublicAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2EbsSnapshotAccountBlockPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPortKafka9092 - Security group does not allow ingress from 0.0.0.0/0 or ::/0 to TCP port 9092 (Kafka)
type Ec2SecuritygroupAllowIngressFromInternetToTcpPortKafka9092 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPortKafka9092() *Ec2SecuritygroupAllowIngressFromInternetToTcpPortKafka9092 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPortKafka9092{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092",
            CheckTitle: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to TCP port 9092 (Kafka)",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** are evaluated for ingress rules that expose **Kafka** on `TCP 9092` to the Internet via `0.0.0.0/0` or `::/0`",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortKafka9092) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortKafka9092) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPortRedis6379 - Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Redis TCP port 6379
type Ec2SecuritygroupAllowIngressFromInternetToTcpPortRedis6379 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPortRedis6379() *Ec2SecuritygroupAllowIngressFromInternetToTcpPortRedis6379 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPortRedis6379{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379",
            CheckTitle: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Redis TCP port 6379",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** permitting Internet sources (`0.0.0.0/0` or `::/0`) to `TCP 6379` are identified, indicating Redis is reachable from public networks",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortRedis6379) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortRedis6379) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2ElasticIpShodan - EC2 Elastic IP address is not listed in Shodan
type Ec2ElasticIpShodan struct {
    metadata models.CheckMetadata
}

func NewEc2ElasticIpShodan() *Ec2ElasticIpShodan {
    return &Ec2ElasticIpShodan{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_elastic_ip_shodan",
            CheckTitle: "EC2 Elastic IP address is not listed in Shodan",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "**EC2 Elastic IPs** are compared with **Shodan**'s index to identify publicly reachable addresses that have been scanned and cataloged, including metadata such as open ports, ISP, and geolocation",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2ElasticIpShodan) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2ElasticIpShodan) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPort3389 - Security group does not allow ingress from the Internet to TCP port 3389 (RDP)
type Ec2SecuritygroupAllowIngressFromInternetToTcpPort3389 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPort3389() *Ec2SecuritygroupAllowIngressFromInternetToTcpPort3389 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPort3389{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
            CheckTitle: "Security group does not allow ingress from the Internet to TCP port 3389 (RDP)",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** restrict **inbound RDP** on `TCP 3389` to trusted sources, avoiding Internet-wide (`0.0.0.0/0`, `::/0`) exposure.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPort3389) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPort3389) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortRdpExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP port 3389 (RDP)
type Ec2InstancePortRdpExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortRdpExposedToInternet() *Ec2InstancePortRdpExposedToInternet {
    return &Ec2InstancePortRdpExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_rdp_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP port 3389 (RDP)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** whose security groups allow Internet-wide inbound **RDP** on `TCP 3389` (`0.0.0.0/0` or `::/0`). The instance's public IP and subnet routing are considered to determine external reachability.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortRdpExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortRdpExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstanceSecretsUserData - EC2 instance user data contains no secrets
type Ec2InstanceSecretsUserData struct {
    metadata models.CheckMetadata
}

func NewEc2InstanceSecretsUserData() *Ec2InstanceSecretsUserData {
    return &Ec2InstanceSecretsUserData{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_secrets_user_data",
            CheckTitle: "EC2 instance user data contains no secrets",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 instance User Data** is inspected for **secret-like values** (credentials, tokens, keys). Both plain and compressed content are parsed, honoring configured exclusions, to identify patterns that resemble sensitive material within initialization scripts.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstanceSecretsUserData) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstanceSecretsUserData) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortKafkaExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP port 9092 (Kafka)
type Ec2InstancePortKafkaExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortKafkaExposedToInternet() *Ec2InstancePortKafkaExposedToInternet {
    return &Ec2InstancePortKafkaExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_kafka_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP port 9092 (Kafka)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** with security group rules that allow inbound `TCP 9092` (Kafka) from the Internet are reported. The evaluation inspects ingress rules to detect broad sources (for example `0.0.0.0/0` or `::/0`) that expose Kafka brokers.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortKafkaExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortKafkaExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortOracleExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP ports 1521, 2483, or 2484 (Oracle)
type Ec2InstancePortOracleExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortOracleExposedToInternet() *Ec2InstancePortOracleExposedToInternet {
    return &Ec2InstancePortOracleExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_oracle_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP ports 1521, 2483, or 2484 (Oracle)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** with security groups allowing inbound `TCP` from any address to Oracle listener ports `1521`, `2483`, or `2484`",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortOracleExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortOracleExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstanceStoppedOlderThanSpecificDays - EC2 instance has not been stopped longer than the configured maximum days
type Ec2InstanceStoppedOlderThanSpecificDays struct {
    metadata models.CheckMetadata
}

func NewEc2InstanceStoppedOlderThanSpecificDays() *Ec2InstanceStoppedOlderThanSpecificDays {
    return &Ec2InstanceStoppedOlderThanSpecificDays{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_stopped_older_than_specific_days",
            CheckTitle: "EC2 instance has not been stopped longer than the configured maximum days",
            ServiceName: "ec2",
            Severity: "low",
            Description: "**EC2 instances** in the `stopped` state are evaluated for how long they have remained stopped. Instances stopped beyond the configurable limit (`max_ec2_instance_stopped_days`, default `30`) are flagged. Running, pending, and other non-stopped instances pass.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstanceStoppedOlderThanSpecificDays) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstanceStoppedOlderThanSpecificDays) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2NetworkaclAllowIngressTcpPort22 - Network ACL does not allow ingress from the Internet to TCP port 22 (SSH)
type Ec2NetworkaclAllowIngressTcpPort22 struct {
    metadata models.CheckMetadata
}

func NewEc2NetworkaclAllowIngressTcpPort22() *Ec2NetworkaclAllowIngressTcpPort22 {
    return &Ec2NetworkaclAllowIngressTcpPort22{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_networkacl_allow_ingress_tcp_port_22",
            CheckTitle: "Network ACL does not allow ingress from the Internet to TCP port 22 (SSH)",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "**VPC network ACLs** are evaluated for inbound rules that permit `0.0.0.0/0` to access **SSH** on `TCP 22` at the subnet boundary.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2NetworkaclAllowIngressTcpPort22) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2NetworkaclAllowIngressTcpPort22) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortPostgresqlExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP port 5432 (PostgreSQL)
type Ec2InstancePortPostgresqlExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortPostgresqlExposedToInternet() *Ec2InstancePortPostgresqlExposedToInternet {
    return &Ec2InstancePortPostgresqlExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_postgresql_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP port 5432 (PostgreSQL)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** with security group rules allowing inbound **PostgreSQL** on `TCP 5432` from the Internet (`0.0.0.0/0` or `::/0`) are identified, considering the instance's public reachability via IP and subnet.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortPostgresqlExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortPostgresqlExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2LaunchTemplateNoPublicIp - Amazon EC2 launch template has no public IP addresses configured on network interfaces
type Ec2LaunchTemplateNoPublicIp struct {
    metadata models.CheckMetadata
}

func NewEc2LaunchTemplateNoPublicIp() *Ec2LaunchTemplateNoPublicIp {
    return &Ec2LaunchTemplateNoPublicIp{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_launch_template_no_public_ip",
            CheckTitle: "Amazon EC2 launch template has no public IP addresses configured on network interfaces",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 launch templates** with versions that either enable `associate_public_ip_address` for network interfaces or reference **ENIs** already associated with public IPs",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2LaunchTemplateNoPublicIp) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2LaunchTemplateNoPublicIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstanceInternetFacingWithInstanceProfile - EC2 instance is not internet-facing with an instance profile attached
type Ec2InstanceInternetFacingWithInstanceProfile struct {
    metadata models.CheckMetadata
}

func NewEc2InstanceInternetFacingWithInstanceProfile() *Ec2InstanceInternetFacingWithInstanceProfile {
    return &Ec2InstanceInternetFacingWithInstanceProfile{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_internet_facing_with_instance_profile",
            CheckTitle: "EC2 instance is not internet-facing with an instance profile attached",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 instances** with a public IP address and an attached **instance profile** (IAM role) are identified.  Instances lacking public exposure or without an instance profile are excluded.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstanceInternetFacingWithInstanceProfile) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstanceInternetFacingWithInstanceProfile) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortMongodbExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP ports 27017 or 27018 (MongoDB)
type Ec2InstancePortMongodbExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortMongodbExposedToInternet() *Ec2InstancePortMongodbExposedToInternet {
    return &Ec2InstancePortMongodbExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_mongodb_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP ports 27017 or 27018 (MongoDB)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** with security groups permitting inbound `TCP 27017` or `27018` (MongoDB) from `0.0.0.0/0` or `::/0` are identified, factoring the instance's public reachability to gauge exposure.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortMongodbExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortMongodbExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2AmiPublic - EC2 AMI owned by the account is not public
type Ec2AmiPublic struct {
    metadata models.CheckMetadata
}

func NewEc2AmiPublic() *Ec2AmiPublic {
    return &Ec2AmiPublic{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_ami_public",
            CheckTitle: "EC2 AMI owned by the account is not public",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 AMIs owned by the account** are evaluated for **public visibility** via their launch permissions. Images shared with all accounts (`Group=all`) are treated as publicly accessible.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2AmiPublic) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2AmiPublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2ClientVpnEndpointConnectionLoggingEnabled - EC2 Client VPN endpoint has client connection logging enabled
type Ec2ClientVpnEndpointConnectionLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewEc2ClientVpnEndpointConnectionLoggingEnabled() *Ec2ClientVpnEndpointConnectionLoggingEnabled {
    return &Ec2ClientVpnEndpointConnectionLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_client_vpn_endpoint_connection_logging_enabled",
            CheckTitle: "EC2 Client VPN endpoint has client connection logging enabled",
            ServiceName: "ec2",
            Severity: "low",
            Description: "**AWS Client VPN endpoints** are evaluated for **client connection logging** that records client connect/disconnect events to CloudWatch Logs. The evaluation detects endpoints where this logging is disabled.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2ClientVpnEndpointConnectionLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2ClientVpnEndpointConnectionLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2ConfidentialWorkloadHostPublicIp - Confidential-workload host is not exposed to the internet
type Ec2ConfidentialWorkloadHostPublicIp struct {
    metadata models.CheckMetadata
}

func NewEc2ConfidentialWorkloadHostPublicIp() *Ec2ConfidentialWorkloadHostPublicIp {
    return &Ec2ConfidentialWorkloadHostPublicIp{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_confidential_workload_host_public_ip",
            CheckTitle: "Confidential-workload host is not exposed to the internet",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "Instances hosting **Nitro Enclave** workloads (`EnclaveOptions.Enabled=true`) are evaluated for direct internet reachability. The host must not carry a public IP and must not sit in a subnet whose route table sends `0.0.0.0/0` or `::/0` to an Internet Gateway. NAT Gateway routes are not flagged. This check assesses the host environment; it does not audit the enclave itself.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2ConfidentialWorkloadHostPublicIp) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2ConfidentialWorkloadHostPublicIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupNotUsed - Non-default EC2 security group is in use
type Ec2SecuritygroupNotUsed struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupNotUsed() *Ec2SecuritygroupNotUsed {
    return &Ec2SecuritygroupNotUsed{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_not_used",
            CheckTitle: "Non-default EC2 security group is in use",
            ServiceName: "ec2",
            Severity: "low",
            Description: "EC2 security groups, except `default`, are assessed for **unused** status: zero attached network interfaces, no AWS Lambda associations, no AWS Batch compute environment associations, and no references from other security groups.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupNotUsed) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupNotUsed) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2EbsDefaultEncryption - EBS default encryption is enabled
type Ec2EbsDefaultEncryption struct {
    metadata models.CheckMetadata
}

func NewEc2EbsDefaultEncryption() *Ec2EbsDefaultEncryption {
    return &Ec2EbsDefaultEncryption{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_ebs_default_encryption",
            CheckTitle: "EBS default encryption is enabled",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EBS** uses `encryption by default` at the account and region level, ensuring new volumes, snapshots, and AMI-backed volumes are automatically encrypted with a chosen **KMS key**",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2EbsDefaultEncryption) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2EbsDefaultEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2EbsVolumeProtectedByBackupPlan - EBS volume is protected by a backup plan
type Ec2EbsVolumeProtectedByBackupPlan struct {
    metadata models.CheckMetadata
}

func NewEc2EbsVolumeProtectedByBackupPlan() *Ec2EbsVolumeProtectedByBackupPlan {
    return &Ec2EbsVolumeProtectedByBackupPlan{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_ebs_volume_protected_by_backup_plan",
            CheckTitle: "EBS volume is protected by a backup plan",
            ServiceName: "ec2",
            Severity: "medium",
            Description: "**EBS volumes** are evaluated for coverage by an **AWS Backup plan**, whether explicitly targeted or included via broad resource selection, confirming scheduled, policy-driven backups exist for the volume.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2EbsVolumeProtectedByBackupPlan) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2EbsVolumeProtectedByBackupPlan) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPortSqlServer14331434 - Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Microsoft SQL Server ports 1433 and 1434
type Ec2SecuritygroupAllowIngressFromInternetToTcpPortSqlServer14331434 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPortSqlServer14331434() *Ec2SecuritygroupAllowIngressFromInternetToTcpPortSqlServer14331434 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPortSqlServer14331434{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434",
            CheckTitle: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Microsoft SQL Server ports 1433 and 1434",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** with inbound rules that allow Internet sources (`0.0.0.0/0`, `::/0`) to reach **Microsoft SQL Server** on `TCP 1433` or `TCP 1434`",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortSqlServer14331434) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortSqlServer14331434) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPort22 - Security group does not allow ingress from 0.0.0.0/0 or ::/0 to TCP port 22 (SSH)
type Ec2SecuritygroupAllowIngressFromInternetToTcpPort22 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPort22() *Ec2SecuritygroupAllowIngressFromInternetToTcpPort22 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPort22{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
            CheckTitle: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to TCP port 22 (SSH)",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** are assessed for **inbound SSH exposure** by locating ingress rules that allow `TCP 22` from the Internet (`0.0.0.0/0` or `::/0`).  Only groups in use are considered; sets already flagged for all-port exposure are not repeated.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPort22) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPort22) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToHighRiskTcpPorts - Security group does not allow ingress from 0.0.0.0/0 or ::/0 to high-risk TCP ports
type Ec2SecuritygroupAllowIngressFromInternetToHighRiskTcpPorts struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToHighRiskTcpPorts() *Ec2SecuritygroupAllowIngressFromInternetToHighRiskTcpPorts {
    return &Ec2SecuritygroupAllowIngressFromInternetToHighRiskTcpPorts{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports",
            CheckTitle: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to high-risk TCP ports",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** are assessed for inbound rules that allow Internet sources (`0.0.0.0/0` or `::/0`) to **high-risk TCP ports**: `25, 110, 135, 143, 445, 3000, 4333, 5000, 5500, 8080, 8088`.  Findings highlight groups exposing any of these ports to the public network.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToHighRiskTcpPorts) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToHighRiskTcpPorts) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortFtpExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP ports 20 or 21 (FTP)
type Ec2InstancePortFtpExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortFtpExposedToInternet() *Ec2InstancePortFtpExposedToInternet {
    return &Ec2InstancePortFtpExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_ftp_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP ports 20 or 21 (FTP)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** with security groups permitting inbound **FTP** on `TCP 20-21` from any address (e.g., `0.0.0.0/0` or `::/0`) are identified.  Exposure is contextualized by the instance's public reachability (public IP and subnet).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortFtpExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortFtpExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortKerberosExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP ports 88, 464, 749, or 750 (Kerberos)
type Ec2InstancePortKerberosExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortKerberosExposedToInternet() *Ec2InstancePortKerberosExposedToInternet {
    return &Ec2InstancePortKerberosExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_kerberos_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP ports 88, 464, 749, or 750 (Kerberos)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** whose security groups allow public **inbound TCP** access to Kerberos ports `88`, `464`, `749`, or `750` (authentication, password change, admin).  Rules permitting `0.0.0.0/0` or `::/0` are treated as Internet-exposed.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortKerberosExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortKerberosExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPortMysql3306 - Security group does not allow ingress from 0.0.0.0/0 or ::/0 to MySQL port 3306
type Ec2SecuritygroupAllowIngressFromInternetToTcpPortMysql3306 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPortMysql3306() *Ec2SecuritygroupAllowIngressFromInternetToTcpPortMysql3306 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPortMysql3306{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306",
            CheckTitle: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to MySQL port 3306",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** are assessed for **inbound exposure** of **MySQL** on `TCP 3306` from `0.0.0.0/0` or `::/0`.  The finding reflects whether this port is reachable from any IPv4 or IPv6 address.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortMysql3306) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortMysql3306) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupAllowIngressFromInternetToTcpPortMongodb2701727018 - Security group does not allow ingress from 0.0.0.0/0 or ::/0 to MongoDB TCP ports 27017 and 27018
type Ec2SecuritygroupAllowIngressFromInternetToTcpPortMongodb2701727018 struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupAllowIngressFromInternetToTcpPortMongodb2701727018() *Ec2SecuritygroupAllowIngressFromInternetToTcpPortMongodb2701727018 {
    return &Ec2SecuritygroupAllowIngressFromInternetToTcpPortMongodb2701727018{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mongodb_27017_27018",
            CheckTitle: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to MongoDB TCP ports 27017 and 27018",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**EC2 security groups** are inspected for inbound rules that expose **MongoDB** on `TCP 27017-27018` to the Internet via `0.0.0.0/0` or `::/0`.  It identifies groups where these ports are reachable from any address.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortMongodb2701727018) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupAllowIngressFromInternetToTcpPortMongodb2701727018) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2SecuritygroupDefaultRestrictTraffic - VPC default security group has no inbound or outbound rules
type Ec2SecuritygroupDefaultRestrictTraffic struct {
    metadata models.CheckMetadata
}

func NewEc2SecuritygroupDefaultRestrictTraffic() *Ec2SecuritygroupDefaultRestrictTraffic {
    return &Ec2SecuritygroupDefaultRestrictTraffic{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_securitygroup_default_restrict_traffic",
            CheckTitle: "VPC default security group has no inbound or outbound rules",
            ServiceName: "ec2",
            Severity: "high",
            Description: "**Default VPC security group** should have **no inbound or outbound rules**. This evaluates whether the group allows any traffic-ingress, egress, or self-referencing-instead of remaining empty.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2SecuritygroupDefaultRestrictTraffic) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2SecuritygroupDefaultRestrictTraffic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Ec2InstancePortRedisExposedToInternet - EC2 instance does not allow ingress from the Internet to TCP port 6379 (Redis)
type Ec2InstancePortRedisExposedToInternet struct {
    metadata models.CheckMetadata
}

func NewEc2InstancePortRedisExposedToInternet() *Ec2InstancePortRedisExposedToInternet {
    return &Ec2InstancePortRedisExposedToInternet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ec2_instance_port_redis_exposed_to_internet",
            CheckTitle: "EC2 instance does not allow ingress from the Internet to TCP port 6379 (Redis)",
            ServiceName: "ec2",
            Severity: "critical",
            Description: "**EC2 instances** with security groups permitting Internet access to **Redis** on `TCP 6379` are identified.  Exposure is assessed using public IP assignment and subnet reachability to reflect how broadly the service can be contacted.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ec2"},
        },
    }
}

func (c *Ec2InstancePortRedisExposedToInternet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Ec2InstancePortRedisExposedToInternet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ec2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

