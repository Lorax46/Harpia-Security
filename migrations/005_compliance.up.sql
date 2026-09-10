-- Migration 005: Create compliance_reports table
-- Tabela de relatórios de compliance

CREATE TABLE IF NOT EXISTS compliance_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    framework_id VARCHAR(100) NOT NULL,
    framework_name VARCHAR(255) NOT NULL,
    framework_version VARCHAR(50),
    total_checks INT DEFAULT 0,
    passed INT DEFAULT 0,
    failed INT DEFAULT 0,
    manual INT DEFAULT 0,
    pass_rate DECIMAL(5,2),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_compliance_framework ON compliance_reports(framework_id);
CREATE INDEX idx_compliance_scan ON compliance_reports(scan_id);

-- Migration 005: Create compliance_controls table
-- Tabela de controles de compliance por relatório

CREATE TABLE IF NOT EXISTS compliance_controls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID REFERENCES compliance_reports(id),
    control_id VARCHAR(100) NOT NULL,
    control_title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_controls_report ON compliance_controls(report_id);
CREATE INDEX idx_controls_status ON compliance_controls(status);
