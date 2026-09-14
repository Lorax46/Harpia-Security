package cloudflare

import (
	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
)

var Registry = map[string][]executor.Check{
	"cloudflare": {
		NewCloudflareWafEnabledCheck(),
		NewCloudflareDnsSecurityCheck(),
		NewCloudflareSslTlsCheck(),
		NewCloudflareDdosProtectionCheck(),
		NewCloudflareBotManagementCheck(),
		NewCloudflareFirewallRulesCheck(),
		NewCloudflareAccessRulesCheck(),
		NewCloudflareRateLimitCheck(),
		NewCloudflareDnsRecordCnameTargetValidCheck(),
		NewCloudflareDnsRecordNoInternalIpCheck(),
		NewCloudflareDnsRecordNoWildcardCheck(),
		NewCloudflareDnsRecordProxiedCheck(),
		NewCloudflareDnssecEnabledCheck(),
		NewCloudflareMinTlsVersionCheck(),
		NewCloudflareHstsEnabledCheck(),
		NewCloudflareSslStrictCheck(),
		NewCloudflareTls13EnabledCheck(),
		NewCloudflareUniversalSslEnabledCheck(),
		NewCloudflareHttpsRedirectEnabledCheck(),
		NewCloudflareWafOwaspRulesetEnabledCheck(),
		NewCloudflareFirewallBlockingRulesConfiguredCheck(),
		NewCloudflareRateLimitingEnabledCheck(),
		NewCloudflareSpfRecordExistsCheck(),
		NewCloudflareDkimRecordExistsCheck(),
		NewCloudflareDmarcRecordExistsCheck(),
		NewCloudflareCaaRecordExistsCheck(),
		NewCloudflareAlwaysOnlineDisabledCheck(),
		NewCloudflareUnderAttackModeDisabledCheck(),
		NewCloudflareChallengePassageConfiguredCheck(),
	},
}
