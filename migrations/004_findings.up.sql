-- Migration 004: Create findings table
-- Tabela de achados de segurança

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    check_id VARCHAR(255) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    service VARCHAR(100) NOT NULL,
    resource_id VARCHAR(500),
    resource_arn VARCHAR(500),
    region VARCHAR(50),
    remediation TEXT,
    remediation_url TEXT,
    categories JSONB,
    found_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_provider ON findings(provider);
CREATE INDEX idx_findings_service ON findings(service);
CREATE INDEX idx_findings_resource ON findings(resource_id);
CREATE INDEX idx_findings_found_at ON findings(found_at);
