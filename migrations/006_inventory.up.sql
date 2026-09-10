-- Migration 006: Create inventory table
-- Tabela de inventário de recursos

CREATE TABLE IF NOT EXISTS inventory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider VARCHAR(50) NOT NULL,
    service VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(500) NOT NULL,
    resource_name VARCHAR(500),
    region VARCHAR(50),
    account_id VARCHAR(100),
    tags JSONB,
    configurations JSONB,
    metadata JSONB,
    last_seen_at TIMESTAMP,
    synced_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(provider, service, resource_id, region)
);

CREATE INDEX idx_inventory_provider ON inventory(provider);
CREATE INDEX idx_inventory_service ON inventory(provider, service);
CREATE INDEX idx_inventory_type ON inventory(resource_type);
CREATE INDEX idx_inventory_region ON inventory(region);
CREATE INDEX idx_inventory_account ON inventory(account_id);
CREATE INDEX idx_inventory_synced ON inventory(synced_at);

CREATE TRIGGER update_inventory_updated_at
    BEFORE UPDATE ON inventory
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Migration 006: Create inventory_changes table
-- Tabela de mudanças no inventário

CREATE TABLE IF NOT EXISTS inventory_changes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id UUID REFERENCES inventory(id),
    change_type VARCHAR(50) NOT NULL, -- created, updated, deleted
    change_details JSONB,
    changed_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_inventory_changes_resource ON inventory_changes(resource_id);
CREATE INDEX idx_inventory_changes_type ON inventory_changes(change_type);
