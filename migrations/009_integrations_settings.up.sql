-- Migration 009: Create integrations table
-- Tabela de configuração de integrações externas

CREATE TABLE IF NOT EXISTS integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL, -- slack, pagerduty, jira, openai, shodan, etc.
    config JSONB NOT NULL,
    credentials JSONB,
    status VARCHAR(50) DEFAULT 'active',
    last_sync_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_integrations_type ON integrations(type);
CREATE INDEX idx_integrations_status ON integrations(status);

CREATE TRIGGER update_integrations_updated_at
    BEFORE UPDATE ON integrations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Migration 009: Create settings table
-- Tabela de configurações do sistema

CREATE TABLE IF NOT EXISTS settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(255) UNIQUE NOT NULL,
    value TEXT,
    description TEXT,
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_settings_key ON settings(key);

-- Seed default settings
INSERT INTO settings (key, value, description) VALUES
    ('app_version', '2.0.0-beta', 'Versão do sistema'),
    ('scan_timeout_minutes', '60', 'Timeout padrão para scans'),
    ('max_concurrent_scans', '5', 'Máximo de scans simultâneos'),
    ('default_scan_schedule', '0 2 * * *', 'Agendamento padrão (2h da manhã)'),
    ('data_retention_days', '90', 'Retenção de dados em dias'),
    ('enable_auto_remediation', 'false', 'Auto-remediation habilitado'),
    ('enable_slack_notifications', 'false', 'Notificações Slack habilitadas'),
    ('enable_epss_scoring', 'true', 'EPSS scoring habilitado'),
    ('enable_kev_detection', 'true', 'KEV detection habilitado'),
    ('llm_provider', 'openai', 'Provider de LLM'),
    ('llm_model', 'gpt-4', 'Modelo de LLM');
