package azure

import (
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/azure/compute"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/azure/keyvault"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/azure/monitor"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/azure/network"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/azure/sql"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/azure/storage"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/azure/webapp"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/executor"
)

// Registry contém todos os checks Azure implementados
var Registry = map[string][]executor.Check{
	"compute": {
		compute.NewVMEncryptedAtRestCheck(),
		compute.NewVMPublicIPDisabledCheck(),
		compute.NewDiskEncryptedAtRestCheck(),
		compute.NewVMUsesManagedDisksCheck(),
	},
	"network": {
		network.NewNSGSSHRestrictedCheck(),
		network.NewNSGRDPRestrictedCheck(),
		network.NewPublicIPSecuredCheck(),
	},
	"storage": {
		storage.NewHTTPSOnlyCheck(),
		storage.NewStorageEncryptionAtRestCheck(),
		storage.NewPublicAccessDisabledCheck(),
		storage.NewMinimumTLSVersionCheck(),
		storage.NewSharedKeyAccessDisabledCheck(),
	},
	"sql": {
		sql.NewSQLAuditingEnabledCheck(),
		sql.NewSQLEncryptedAtRestCheck(),
	},
	"keyvault": {
		keyvault.NewPurgeProtectionCheck(),
		keyvault.NewSoftDeleteCheck(),
		keyvault.NewRBACAuthorizationCheck(),
	},
	"monitor": {
		monitor.NewDiagnosticSettingsCheck(),
		monitor.NewActivityLogAlertsCheck(),
	},
	"webapp": {
		webapp.NewHTTPSOnlyCheck(),
		webapp.NewMinimumTLSVersionCheck(),
		webapp.NewFTPDisabledCheck(),
	},
}
