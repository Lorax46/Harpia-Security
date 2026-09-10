-- Migration 007: Create vulnerabilities table
-- Tabela de vulnerabilidades

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id VARCHAR(50) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    score DECIMAL(4,2),
    epss_score DECIMAL(5,4),
    kev BOOLEAN DEFAULT FALSE,
    description TEXT,
    affected_resource VARCHAR(500),
    affected_package VARCHAR(255),
    fixed_version VARCHAR(100),
    provider VARCHAR(50),
    service VARCHAR(100),
    status VARCHAR(50) DEFAULT 'open',
    discovered_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_vulnerabilities_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_kev ON vulnerabilities(kev);
CREATE INDEX idx_vulnerabilities_status ON vulnerabilities(status);
CREATE INDEX idx_vulnerabilities_resource ON vulnerabilities(affected_resource);
CREATE INDEX idx_vulnerabilities_epss ON vulnerabilities(epss_score);

-- Migration 007: Create asm_assets table
-- Tabela de attack surface assets

CREATE TABLE IF NOT EXISTS asm_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL, -- domain, ip, port, certificate, technology
    value VARCHAR(500) NOT NULL,
    provider VARCHAR(50),
    exposure VARCHAR(50), -- public, private
    technology VARCHAR(100),
    port INT,
    protocol VARCHAR(10),
    status VARCHAR(50),
    metadata JSONB,
    first_seen_at TIMESTAMP DEFAULT NOW(),
    last_seen_at TIMESTAMP,
    discovered_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_asm_type ON asm_assets(type);
CREATE INDEX idx_asm_value ON asm_assets(value);
CREATE INDEX idx_asm_exposure ON asm_assets(exposure);
CREATE INDEX idx_asm_provider ON asm_assets(provider);

-- Migration 007: Create soar_playbooks table
-- Tabela de playbooks de resposta a incidentes

CREATE TABLE IF NOT EXISTS soar_playbooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    trigger VARCHAR(255) NOT NULL,
    trigger_conditions JSONB,
    actions JSONB NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    execution_count INT DEFAULT 0,
    last_executed_at TIMESTAMP,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TRIGGER update_playbooks_updated_at
    BEFORE UPDATE ON soar_playbooks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Migration 007: Create dspm_assets table
-- Tabela de data security assets

CREATE TABLE IF NOT EXISTS dspm_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider VARCHAR(50) NOT NULL,
    service VARCHAR(100) NOT NULL,
    resource_id VARCHAR(500) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    classification VARCHAR(50), -- pii, pci, phi, public, internal, confidential
    encryption_status VARCHAR(50), -- encrypted, unencrypted, unknown
    exposure VARCHAR(50), -- public, private, internal
    data_types JSONB,
    last_scan_at TIMESTAMP,
    synced_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(provider, service, resource_id)
);

CREATE INDEX idx_dspm_provider ON dspm_assets(provider);
CREATE INDEX idx_dspm_classification ON dspm_assets(classification);
CREATE INDEX idx_dspm_encryption ON dspm_assets(encryption_status);
CREATE INDEX idx_dspm_exposure ON dspm_assets(exposure);
