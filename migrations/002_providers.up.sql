-- Migration 002: Create providers table
-- Tabela de configuração de cloud providers

CREATE TABLE IF NOT EXISTS providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- aws, gcp, azure, oci
    credentials JSONB NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    last_scan_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_providers_type ON providers(type);
CREATE INDEX idx_providers_status ON providers(status);

CREATE TRIGGER update_providers_updated_at
    BEFORE UPDATE ON providers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
