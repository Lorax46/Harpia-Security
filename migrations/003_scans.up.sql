-- Migration 003: Create scans table
-- Tabela de scans executados

CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID REFERENCES providers(id),
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, running, completed, failed
    provider VARCHAR(50) NOT NULL,
    region VARCHAR(50),
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_scans_provider ON scans(provider_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at);

CREATE TRIGGER update_scans_updated_at
    BEFORE UPDATE ON scans
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
