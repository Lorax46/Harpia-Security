package ec2

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// isCidrPublic verifica se um CIDR é público (0.0.0.0/0 ou ::/0)
func isCidrPublic(cidr string, anyAddress bool) bool {
	if cidr == "0.0.0.0/0" || cidr == "::/0" {
		return true
	}
	if anyAddress {
		return false
	}
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	if ip.To4() != nil {
		size, _ := ipNet.Mask.Size()
		return size < 24
	}
	return false
}

// checkSecurityGroupRule verifica se uma regra de security group tem acesso público
func checkSecurityGroupRule(rule types.IpPermission, protocol string, ports []int32) bool {
	// Verifica se o protocolo corresponde
	if aws.ToString(rule.IpProtocol) != protocol && aws.ToString(rule.IpProtocol) != "-1" {
		return false
	}

	// Se for all traffic (-1)
	if aws.ToString(rule.IpProtocol) == "-1" {
		for _, ipRange := range rule.IpRanges {
			if isCidrPublic(aws.ToString(ipRange.CidrIp), true) {
				return true
			}
		}
		for _, ipv6Range := range rule.Ipv6Ranges {
			if isCidrPublic(aws.ToString(ipv6Range.CidrIpv6), true) {
				return true
			}
		}
		return false
	}

	// Verifica portas específicas
	fromPort := aws.ToInt32(rule.FromPort)
	toPort := aws.ToInt32(rule.ToPort)

	for _, ipRange := range rule.IpRanges {
		if isCidrPublic(aws.ToString(ipRange.CidrIp), true) {
			for _, port := range ports {
				if port >= fromPort && port <= toPort {
					return true
				}
			}
		}
	}
	for _, ipv6Range := range rule.Ipv6Ranges {
		if isCidrPublic(aws.ToString(ipv6Range.CidrIpv6), true) {
			for _, port := range ports {
				if port >= fromPort && port <= toPort {
					return true
				}
			}
		}
	}
	return false
}

// securityGroupCheck é a estrutura base para checks de security group
type securityGroupCheck struct {
	metadata models.CheckMetadata
	ports    []int32
	protocol string
	allPorts bool
}

func (c *securityGroupCheck) check(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, sg := range result.SecurityGroups {
		hasViolation := false
		for _, perm := range sg.IpPermissions {
			if c.allPorts {
				// Verifica se todas as portas estão abertas
				for _, ipRange := range perm.IpRanges {
					if isCidrPublic(aws.ToString(ipRange.CidrIp), true) {
						hasViolation = true
						break
					}
				}
			} else {
				if checkSecurityGroupRule(perm, c.protocol, c.ports) {
					hasViolation = true
					break
				}
			}
		}

		status := models.StatusPass
		msg := fmt.Sprintf("Security group %s is compliant", aws.ToString(sg.GroupName))
		if hasViolation {
			status = models.StatusFail
			msg = fmt.Sprintf("Security group %s has public access violations", aws.ToString(sg.GroupName))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(sg.GroupId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

func (c *securityGroupCheck) Metadata() models.CheckMetadata { return c.metadata }
func (c *securityGroupCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return c.check(ctx, provider)
}

// Funções helper para criar checks de porta específicos
func NewEc2SecurityGroupPortSsh() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
			CheckTitle: "Ensure SSH port 22 not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to TCP port 22",
			Severity: "critical", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict SSH access to specific IPs",
			Categories: []string{"ec2", "ssh", "security-group"},
		},
		ports: []int32{22}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortRdp() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
			CheckTitle: "Ensure RDP port 3389 not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to TCP port 3389",
			Severity: "critical", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict RDP access to specific IPs",
			Categories: []string{"ec2", "rdp", "security-group"},
		},
		ports: []int32{3389}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortMysql() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306",
			CheckTitle: "Ensure MySQL port 3306 not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to MySQL port 3306",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict MySQL access to specific IPs",
			Categories: []string{"ec2", "mysql", "database"},
		},
		ports: []int32{3306}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortPostgres() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432",
			CheckTitle: "Ensure PostgreSQL port 5432 not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to PostgreSQL port 5432",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict PostgreSQL access to specific IPs",
			Categories: []string{"ec2", "postgresql", "database"},
		},
		ports: []int32{5432}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortOracle() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483",
			CheckTitle: "Ensure Oracle ports not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to Oracle ports",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict Oracle access to specific IPs",
			Categories: []string{"ec2", "oracle", "database"},
		},
		ports: []int32{1521, 2483}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortSqlserver() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434",
			CheckTitle: "Ensure SQL Server ports not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to SQL Server ports",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict SQL Server access to specific IPs",
			Categories: []string{"ec2", "sqlserver", "database"},
		},
		ports: []int32{1433, 1434}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortRedis() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379",
			CheckTitle: "Ensure Redis port 6379 not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to Redis port 6379",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict Redis access to specific IPs",
			Categories: []string{"ec2", "redis", "cache"},
		},
		ports: []int32{6379}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortMongodb() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mongodb_27017_27018",
			CheckTitle: "Ensure MongoDB ports not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to MongoDB ports",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict MongoDB access to specific IPs",
			Categories: []string{"ec2", "mongodb", "database"},
		},
		ports: []int32{27017, 27018}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortCassandra() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888",
			CheckTitle: "Ensure Cassandra ports not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to Cassandra ports",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict Cassandra access to specific IPs",
			Categories: []string{"ec2", "cassandra", "database"},
		},
		ports: []int32{7199, 9160, 8888}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortElasticsearch() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601",
			CheckTitle: "Ensure Elasticsearch/Kibana ports not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to Elasticsearch/Kibana ports",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict Elasticsearch access to specific IPs",
			Categories: []string{"ec2", "elasticsearch", "kibana"},
		},
		ports: []int32{9200, 9300, 5601}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortKafka() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092",
			CheckTitle: "Ensure Kafka port 9092 not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to Kafka port 9092",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict Kafka access to specific IPs",
			Categories: []string{"ec2", "kafka", "messaging"},
		},
		ports: []int32{9092}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortMemcached() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211",
			CheckTitle: "Ensure Memcached port 11211 not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to Memcached port 11211",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict Memcached access to specific IPs",
			Categories: []string{"ec2", "memcached", "cache"},
		},
		ports: []int32{11211}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortFtp() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_ftp_20_21",
			CheckTitle: "Ensure FTP ports not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to FTP ports",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict FTP access or use SFTP",
			Categories: []string{"ec2", "ftp", "file-transfer"},
		},
		ports: []int32{20, 21}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortTelnet() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23",
			CheckTitle: "Ensure Telnet port 23 not open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to Telnet port 23",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Disable Telnet and use SSH",
			Categories: []string{"ec2", "telnet", "networking"},
		},
		ports: []int32{23}, protocol: "tcp",
	}
}

func NewEc2SecurityGroupPortAll() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
			CheckTitle: "Ensure security group does not allow all ports open to Internet",
			Description: "Security group should not allow ingress from 0.0.0.0/0 to all ports",
			Severity: "critical", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict security group rules",
			Categories: []string{"ec2", "security-group", "all-ports"},
		},
		allPorts: true,
	}
}

func NewEc2SecurityGroupPortAny() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
			CheckTitle: "Ensure security group does not allow any port from Internet",
			Description: "Security group should not have wide open rules to Internet",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict security group rules",
			Categories: []string{"ec2", "security-group", "any-port"},
		},
		allPorts: true,
	}
}

func NewEc2SecurityGroupNotUsed() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_not_used",
			CheckTitle: "Ensure unused security groups are removed",
			Description: "Non-default security groups should be in use",
			Severity: "low", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Remove unused security groups",
			Categories: []string{"ec2", "security-group", "unused"},
		},
		allPorts: false,
	}
}

func NewEc2SecurityGroupRestrictTraffic() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_default_restrict_traffic",
			CheckTitle: "Ensure default security group restricts all traffic",
			Description: "VPC default security group should have no inbound or outbound rules",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Remove rules from default security group",
			Categories: []string{"ec2", "security-group", "default"},
		},
		allPorts: false,
	}
}

func NewEc2SecurityGroupManyRules() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_with_many_ingress_egress_rules",
			CheckTitle: "Ensure security groups have limited number of rules",
			Description: "Security groups should have 50 or fewer inbound/outbound rules",
			Severity: "medium", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Consolidate security group rules",
			Categories: []string{"ec2", "security-group", "rules"},
		},
		allPorts: false,
	}
}

func NewEc2SecurityGroupWideOpen() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_wide_open_public_ipv4",
			CheckTitle: "Ensure security groups do not allow wide public CIDR ranges",
			Description: "Security groups should not have ingress from public IPv4 CIDR ranges /1 to /23",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict CIDR ranges in security group rules",
			Categories: []string{"ec2", "security-group", "cidr"},
		},
		allPorts: false,
	}
}

func NewEc2SecurityGroupLaunchWizard() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_from_launch_wizard",
			CheckTitle: "Ensure security groups are not created by Launch Wizard",
			Description: "Security groups created by Launch Wizard may have overly permissive rules",
			Severity: "medium", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Review Launch Wizard security groups",
			Categories: []string{"ec2", "security-group", "launch-wizard"},
		},
		allPorts: false,
	}
}

func NewEc2SecurityGroupPortHighRiskTcpPorts() *securityGroupCheck {
	return &securityGroupCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports",
			CheckTitle: "Ensure high-risk TCP ports are not open to Internet",
			Description: "Security groups should not expose high-risk ports to Internet",
			Severity: "critical", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict high-risk port access",
			Categories: []string{"ec2", "security-group", "high-risk"},
		},
		ports: []int32{22, 3389, 3306, 5432, 1521, 1433, 6379, 27017, 11211, 9092}, protocol: "tcp",
	}
}
