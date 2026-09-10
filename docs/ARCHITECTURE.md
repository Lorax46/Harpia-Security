# Arquitetura Harpia Security

## Componentes

### 1. Scanner Engine (Go)
- Orquestra scans multi-cloud
- Integração com Prowler via subprocess
- Parser de resultados (JSON/CSV)

### 2. Inventory Service
- Descoberta automática de recursos
- Mapeamento de endpoints de rede
- Suporte a AWS, GCP, Azure, OCI

### 3. API Server (REST)
- Endpoints para triggers de scan
- Dashboard de severidade
- Webhooks para alertas

### 4. Dashboard (Web)
- Visualização de findings
- Filtros por severidade/provider
- Relatórios exportáveis

## Fluxo de Scan

```
[Trigger] → [Inventory] → [Prowler Scan] → [Parse Results] → [API/Dashboard]
```

## Severidade

| Nível | Peso | Ação |
|-------|------|------|
| Critical | 5 | Alerta imediato |
| High | 4 | Corrigir em 24h |
| Medium | 3 | Corrigir em 7 dias |
| Low | 2 | Corrigir em 30 dias |
| Informational | 1 | Visibilidade |
