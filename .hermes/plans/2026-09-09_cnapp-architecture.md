# Plano de Arquitetura CNAPP Completo — TOTVS Horus v2.0

> **Para Hermes:** Use subagent-driven-development skill para implementar este plano task-by-task.

**Goal:** Transformar o TOTVS Horus em um CNAPP completo de classe mundial, com arquitetura de microserviços, database dedicado, e integrações externas (LLM, Shodan, etc.)

**Architecture:** Arquitetura de microserviços com API Gateway, banco de dados PostgreSQL + Redis, message queue para processamento assíncrono, e frontend React. Cada módulo CNAPP (CSPM, CWPP, CIEM, etc.) roda como serviço independente.

**Tech Stack:** Go (backend), PostgreSQL (database), Redis (cache/sessions), Docker Compose (orquestração), Gin (HTTP), GORM (ORM), React (frontend)

---

## 1. Visão Geral da Arquitetura

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              API GATEWAY (Gin)                               │
│                         Autenticação, Rate Limiting                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  CSPM       │  │  CWPP       │  │  CIEM       │  │  KSPM       │        │
│  │  Service    │  │  Service    │  │  Service    │  │  Service    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  IaC        │  │  Container  │  │  Compliance │  │  Inventory  │        │
│  │  Service    │  │  Service    │  │  Service    │  │  Service    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  Vuln       │  │  ASM        │  │  DSPM       │  │  SOAR       │        │
│  │  Service    │  │  Service    │  │  Service    │  │  Service    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                         MESSAGE QUEUE (Redis/RabbitMQ)                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ PostgreSQL  │  │    Redis    │  │   MinIO     │  │  ClickHouse │        │
│  │  (Primary)  │  │   (Cache)   │  │  (Reports)  │  │ (Analytics) │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Microserviços

### 2.1 API Gateway (`cmd/gateway/`)

| Componente | Descrição |
|------------|-----------|
| **Auth** | JWT validation, RBAC, API keys |
| **Rate Limiting** | Token bucket por cliente |
| **Routing** | Reverse proxy para microserviços |
| **Logging** | Request/Response logging |
| **CORS** | Cross-origin resource sharing |

### 2.2 CSPM Service (`cmd/cspm/`)

| Capacidade | Checks | Status |
|------------|--------|--------|
| AWS | 687/2000 | 34% |
| GCP | 109/500 | 22% |
| Azure | 22/300 | 7% |
| OCI | 37/150 | 25% |

**Open Source Base:** Prowler (2000+ checks AWS)

### 2.3 CWPP Service (`cmd/cwpp/`)

| Capacidade | Ferramenta Base | Status |
|------------|-----------------|--------|
| Runtime Security | Falco | Nova |
| Container Policies | KubeArmor | Nova |
| Syscall Monitoring | Tracee | Nova |
| Serverless Security | — | Nova |

### 2.4 CIEM Service (`cmd/ciem/`)

| Capacidade | Ferramenta Base | Status |
|------------|-----------------|--------|
| IAM Analysis | Principal Mapper | Nova |
| Permission Graph | Cartography | Nova |
| Escalation Paths | — | Nova |
| Service Account Keys | — | Nova |

### 2.5 KSPM Service (`cmd/kspm/`)

| Capacidade | Ferramenta Base | Status |
|------------|-----------------|--------|
| CIS Benchmark | kube-bench | ✅ |
| Pod Security | Popeye | Nova |
| Network Policies | — | Nova |
| Admission Control | Kyverno | Nova |

### 2.6 IaC Service (`cmd/iac/`)

| Capacidade | Ferramenta Base | Status |
|------------|-----------------|--------|
| Terraform | Checkov, tfsec | ✅ |
| CloudFormation | cfn-nag | ✅ |
| Helm | — | ✅ |
| Dockerfile | — | ✅ |

### 2.7 Container Service (`cmd/container/`)

| Capacidade | Ferramenta Base | Status |
|------------|-----------------|--------|
| Image Scanning | Trivy | Nova |
| SBOM Generation | Syft | Nova |
| Runtime Security | Falco | Nova |
| Registry Scanning | — | ✅ |

### 2.8 Compliance Service (`cmd/compliance/`)

| Framework | Status |
|-----------|--------|
| CIS | ✅ |
| SOC 2 | ✅ |
| HIPAA | ✅ |
| PCI DSS | ✅ |
| NIST 800-53 | ✅ |
| ISO 27001 | ✅ |
| GDPR | ✅ |
| FedRAMP | ✅ |
| LGPD | Nova |
| BACEN | Nova |

### 2.9 Inventory Service (`cmd/inventory/`)

| Provider | Status |
|----------|--------|
| AWS | ✅ |
| GCP | ✅ |
| Azure | ✅ |
| OCI | ✅ |
| Kubernetes | Nova |

### 2.10 Vulnerability Service (`cmd/vuln/`)

| Capacidade | Ferramenta Base | Status |
|------------|-----------------|--------|
| CVE Scanning | Trivy, OSV | Nova |
| EPSS Scoring | — | Nova |
| KEV Detection | — | Nova |
| SBOM Analysis | Dependency-Track | Nova |

### 2.11 ASM Service (`cmd/asm/`)

| Capacidade | Ferramenta Base | Status |
|------------|-----------------|--------|
| Subdomain Discovery | Amass, Subfinder | Nova |
| Port Scanning | Nuclei | Nova |
| Certificate Monitoring | — | Nova |
| DNS Monitoring | — | Nova |

### 2.12 DSPM Service (`cmd/dspm/`)

| Capacidade | Ferramenta Base | Status |
|------------|-----------------|--------|
| PII Detection | Macie-style | Nova |
| Data Classification | — | Nova |
| Public Exposure | — | Nova |
| Encryption Status | — | Nova |

### 2.13 SOAR Service (`cmd/soar/`)

| Capacidade | Ferramenta Base | Status |
|------------|-----------------|--------|
| Playbooks | — | Nova |
| Auto-remediation | — | Nova |
| Notifications | Slack, PagerDuty | Nova |
| Ticketing | Jira, ServiceNow | Nova |

### 2.14 Report Service (`cmd/report/`)

| Capacidade | Status |
|------------|--------|
| PDF Generation | Nova |
| CSV Export | ✅ |
| HTML Reports | Nova |
| Scheduled Reports | Nova |

---

## 3. Database

### 3.1 PostgreSQL (Primary Database)

```sql
-- Tabelas principais
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- aws, gcp, azure, oci
    credentials JSONB NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID REFERENCES providers(id),
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL, -- pending, running, completed, failed
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE findings (
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
    categories JSONB,
    found_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP
);

CREATE TABLE compliance_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id VARCHAR(100) NOT NULL,
    framework_name VARCHAR(255) NOT NULL,
    total_checks INT DEFAULT 0,
    passed INT DEFAULT 0,
    failed INT DEFAULT 0,
    manual INT DEFAULT 0,
    pass_rate DECIMAL(5,2),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE inventory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider VARCHAR(50) NOT NULL,
    service VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(500) NOT NULL,
    region VARCHAR(50),
    tags JSONB,
    properties JSONB,
    synced_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id VARCHAR(50) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    epss_score DECIMAL(5,4),
    kev BOOLEAN DEFAULT FALSE,
    description TEXT,
    affected_resource VARCHAR(500),
    discovered_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE asm_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL, -- domain, ip, port, certificate
    value VARCHAR(500) NOT NULL,
    provider VARCHAR(50),
    exposure VARCHAR(50), -- public, private
    discovered_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE soar_playbooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    trigger VARCHAR(255) NOT NULL,
    actions JSONB NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Índices
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_provider ON findings(provider);
CREATE INDEX idx_inventory_provider ON inventory(provider, service);
CREATE INDEX idx_vulnerabilities_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_asm_assets_type ON asm_assets(type);
```

### 3.2 Redis (Cache + Sessions)

| Uso | TTL |
|-----|-----|
| Session tokens | 24h |
| API rate limiting | 1h |
| Scan results cache | 1h |
| Inventory cache | 30min |
| Compliance reports | 1h |

### 3.3 MinIO (Object Storage)

| Bucket | Conteúdo |
|--------|----------|
| `reports` | PDF, CSV reports |
| `sboms` | Software Bill of Materials |
| `scan-results` | Raw scan results |
| `exports` | Data exports |

### 3.4 ClickHouse (Analytics)

| Tabela | Descrição |
|--------|-----------|
| `findings_timeseries` | Findings ao longo do tempo |
| `compliance_scores` | Score de compliance diário |
| `attack_surface` | Mudanças na superfície de ataque |
| `vulnerability_trends` | Tendências de vulnerabilidades |

---

## 4. Docker Compose

```yaml
version: '3.8'

services:
  # API Gateway
  gateway:
    build:
      context: .
      dockerfile: Dockerfile.gateway
    ports:
      - "8080:8080"
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - REDIS_URL=redis:6379
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
    depends_on:
      - postgres
      - redis
    networks:
      - horus-net

  # Microserviços
  cspm:
    build:
      context: .
      dockerfile: Dockerfile.cspm
    environment:
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
      - REDIS_URL=redis:6379
    depends_on:
      - postgres
      - redis
    networks:
      - horus-net

  cwpp:
    build:
      context: .
      dockerfile: Dockerfile.cwpp
    environment:
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
    depends_on:
      - postgres
    networks:
      - horus-net

  ciem:
    build:
      context: .
      dockerfile: Dockerfile.ciem
    environment:
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
    depends_on:
      - postgres
    networks:
      - horus-net

  kspm:
    build:
      context: .
      dockerfile: Dockerfile.kspm
    environment:
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
    depends_on:
      - postgres
    networks:
      - horus-net

  iac:
    build:
      context: .
      dockerfile: Dockerfile.iac
    environment:
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
    depends_on:
      - postgres
    networks:
      - horus-net

  container:
    build:
      context: .
      dockerfile: Dockerfile.container
    environment:
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
    depends_on:
      - postgres
    networks:
      - horus-net

  compliance:
    build:
      context: .
      dockerfile: Dockerfile.compliance
    environment:
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
    depends_on:
      - postgres
    networks:
      - horus-net

  inventory:
    build:
      context: .
      dockerfile: Dockerfile.inventory
    environment:
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
      - REDIS_URL=redis:6379
    depends_on:
      - postgres
      - redis
    networks:
      - horus-net

  vuln:
    build:
      context: .
      dockerfile: Dockerfile.vuln
    environment:
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
    depends_on:
      - postgres
    networks:
      - horus-net

  asm:
    build:
      context: .
      dockerfile: Dockerfile.asm
    environment:
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
    depends_on:
      - postgres
    networks:
      - horus-net

  dspm:
    build:
      context: .
      dockerfile: Dockerfile.dspm
    environment:
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
    depends_on:
      - postgres
    networks:
      - horus-net

  soar:
    build:
      context: .
      dockerfile: Dockerfile.soar
    environment:
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
      - PAGERDUTY_KEY=${PAGERDUTY_KEY}
    depends_on:
      - postgres
    networks:
      - horus-net

  report:
    build:
      context: .
      dockerfile: Dockerfile.report
    environment:
      - DATABASE_URL=postgres://horus:horus@postgres:5432/horus?sslmode=disable
      - MINIO_ENDPOINT=minio:9000
      - MINIO_ACCESS_KEY=${MINIO_ACCESS_KEY}
      - MINIO_SECRET_KEY=${MINIO_SECRET_KEY}
    depends_on:
      - postgres
      - minio
    networks:
      - horus-net

  # Frontend
  frontend:
    build:
      context: ./web/frontend
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - API_URL=http://localhost:8080
    networks:
      - horus-net

  # Databases
  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=horus
      - POSTGRES_PASSWORD=horus
      - POSTGRES_DB=horus
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    networks:
      - horus-net

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass horus
    volumes:
      - redis-data:/data
    ports:
      - "6379:6379"
    networks:
      - horus-net

  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      - MINIO_ROOT_USER=horus
      - MINIO_ROOT_PASSWORD=horus12345
    volumes:
      - minio-data:/data
    ports:
      - "9000:9000"
      - "9001:9001"
    networks:
      - horus-net

  clickhouse:
    image: clickhouse/clickhouse-server:latest
    environment:
      - CLICKHOUSE_USER=horus
      - CLICKHOUSE_PASSWORD=horus
      - CLICKHOUSE_DB=horus
    volumes:
      - clickhouse-data:/var/lib/clickhouse
    ports:
      - "8123:8123"
      - "9009:9000"
    networks:
      - horus-net

  # Message Queue
  rabbitmq:
    image: rabbitmq:3-management-alpine
    environment:
      - RABBITMQ_DEFAULT_USER=horus
      - RABBITMQ_DEFAULT_PASS=horus
    volumes:
      - rabbitmq-data:/var/lib/rabbitmq
    ports:
      - "5672:5672"
      - "15672:15672"
    networks:
      - horus-net

volumes:
  postgres-data:
  redis-data:
  minio-data:
  clickhouse-data:
  rabbitmq-data:

networks:
  horus-net:
    driver: bridge
```

---

## 5. Integrações Externas

### 5.1 LLM (Large Language Models)

| Integração | Uso | API |
|------------|-----|-----|
| **OpenAI GPT-4** | Análise de findings, remediation suggestions, chatbot | `api.openai.com` |
| **Anthropic Claude** | Análise de segurança, relatório executivo | `api.anthropic.com` |
| **Local LLM (Ollama)** | Análise offline, privacy-first | `localhost:11434` |

**Casos de Uso:**
- **Remediation AI:** Sugestões de correção personalizadas por finding
- **Compliance Chat:** Pergunte sobre compliance em linguagem natural
- **Report Summary:** Resumo executivo gerado por LLM
- **Threat Analysis:** Análise de ameaças contextuais
- **Policy Generation:** Geração de políticas de segurança

### 5.2 Shodan

| Integração | Uso | API |
|------------|-----|-----|
| **Shodan InternetDB** | IP reputation, ports exposed | `https://internetdb.shodan.io` |
| **Shodan Search** | Asset discovery, banners | `api.shodan.io` |

**Casos de Uso:**
- **Attack Surface:** Descoberta de assets expostos
- **Port Monitoring:** Monitoramento de portas abertas
- **Vulnerability Correlation:** CVEs vs serviços expostos
- **Certificate Monitoring:** SSL/TLS certificate tracking

### 5.3 Axur

| Integração | Uso | API |
|------------|-----|-----|
| **Axur Threat Intelligence** | Threat feeds, dark web monitoring | `api.axur.com` |

**Casos de Uso:**
- **Dark Web Monitoring:** Credenciais vazadas
- **Threat Feeds** Indicadores de compromisso (IoCs)
- **Brand Protection:** Proteção de marca

### 5.4 Outras Integrações

| Integração | Uso | API |
|------------|-----|-----|
| **VirusTotal** | Malware scanning, file reputation | `virustotal.com/api/v3` |
| **Have I Been Pwned** | Credential breach checking | `haveibeenpwned.com/api` |
| **CISA KEV** | Known Exploited Vulnerabilities | `cisa.gov/known-exploited-vulnerabilities-catalog` |
| **EPSS** | Exploit Prediction Scoring System | `first.org/epss/api` |
| **NVD** | National Vulnerability Database | `nvd.nist.gov/v2` |
| **Slack** | Notifications, alerts | `slack.com/api` |
| **PagerDuty** | Incident management | `events.pagerduty.com/v2` |
| **Jira** | Ticketing, workflow | `api.atlassian.com` |
| **ServiceNow** | ITSM, incident management | `servicenow.com/api` |
| **Elasticsearch** | Log aggregation, SIEM | `elastic.co` |
| **Splunk** | SIEM, log analysis | `splunk.com` |
| **Datadog** | Monitoring, APM | `api.datadoghq.com` |
| **Cloudflare** | WAF, DNS, DDoS protection | `api.cloudflare.com` |
| **GitHub** | Code scanning, secret detection | `api.github.com` |
| **GitLab** | CI/CD security, SAST | `gitlab.com/api` |

---

## 6. Roadmap de Implementação

### Fase 1: Fundação (Semanas 1-4)

| Task | Descrição | Skill |
|------|-----------|-------|
| 1.1 | Database schema + migrations | plan, test-driven-development |
| 1.2 | Docker Compose base | plan |
| 1.3 | API Gateway com auth | plan, web-session-hardening |
| 1.4 | CSPM Service (expandir checks AWS) | cnapp-scan |
| 1.5 | Inventory Service (integrar Steampipe) | plan |
| 1.6 | Frontend React base | plan |

### Fase 2: Core CNAPP (Semanas 5-8)

| Task | Descrição | Skill |
|------|-----------|-------|
| 2.1 | CWPP Service (Falco integration) | plan |
| 2.2 | CIEM Service (pmapper integration) | plan |
| 2.3 | KSPM Service (kubescape integration) | plan |
| 2.4 | Vuln Service (Trivy integration) | plan |
| 2.5 | ASM Service (Amass integration) | plan |
| 2.6 | Compliance Service (expandir frameworks) | plan |

### Fase 3: Integrações (Semanas 9-12)

| Task | Descrição | Skill |
|------|-----------|-------|
| 3.1 | LLM Integration (OpenAI/Claude) | plan |
| 3.2 | Shodan Integration | plan |
| 3.3 | CISA KEV + EPSS Integration | plan |
| 3.4 | Slack + PagerDuty Integration | plan |
| 3.5 | VirusTotal Integration | plan |
| 3.6 | Report Service (PDF generation) | plan |

### Fase 4: Advanced (Semanas 13-16)

| Task | Descrição | Skill |
|------|-----------|-------|
| 4.1 | SOAR Service (playbooks) | plan |
| 4.2 | DSPM Service (data classification) | plan |
| 4.3 | ClickHouse Analytics | plan |
| 4.4 | Axur Threat Intelligence | plan |
| 4.5 | Service Mesh Security | plan |
| 4.6 | AI Security (model scanning) | plan |

### Fase 5: Polish (Semanas 17-20)

| Task | Descrição | Skill |
|------|-----------|-------|
| 5.1 | Frontend dashboard completo | plan |
| 5.2 | Scheduled scans + reports | plan |
| 5.3 | Multi-tenancy | plan |
| 5.4 | API documentation (OpenAPI) | plan |
| 5.5 | Performance optimization | plan |
| 5.6 | Security hardening | requesting-code-review |

---

## 7. Estrutura de Diretórios Final

```
totvs-horus/
├── cmd/
│   ├── gateway/          # API Gateway
│   ├── cspm/             # CSPM Service
│   ├── cwpp/             # CWPP Service
│   ├── ciem/             # CIEM Service
│   ├── kspm/             # KSPM Service
│   ├── iac/              # IaC Security Service
│   ├── container/        # Container Security Service
│   ├── compliance/       # Compliance Service
│   ├── inventory/        # Inventory Service
│   ├── vuln/             # Vulnerability Service
│   ├── asm/              # Attack Surface Service
│   ├── dspm/             # Data Security Service
│   ├── soar/             # SOAR Service
│   └── report/           # Report Service
├── internal/
│   ├── models/           # Shared models
│   ├── database/         # Database connection
│   ├── auth/             # Auth utilities
│   └── integrations/     # External integrations
│       ├── llm/          # LLM clients
│       ├── shodan/       # Shodan client
│       ├── axur/         # Axur client
│       ├── virustotal/   # VirusTotal client
│       └── slack/        # Slack client
├── pkg/
│   ├── scanner/          # Scanner engine
│   ├── inventory/        # Inventory engine
│   ├── compliance/       # Compliance engine
│   └── web/              # Web server
├── web/
│   ├── dashboard/        # Static HTML (legacy)
│   └── frontend/         # React frontend
├── migrations/           # Database migrations
├── docker-compose.yml    # Docker orchestration
├── Dockerfile.*          # Service Dockerfiles
└── docs/                 # Documentation
```

---

## 8. Métricas de Sucesso

| Métrica | Atual | Meta |
|---------|-------|------|
| AWS CSPM checks | 687 | 2000+ |
| GCP CSPM checks | 109 | 500+ |
| Azure CSPM checks | 22 | 300+ |
| OCI CSPM checks | 37 | 150+ |
| Compliance frameworks | 11 | 70+ |
| Microserviços | 1 | 14 |
| Integrações externas | 0 | 15+ |
| Cobertura CNAPP | 30% | 90% |

---

**Plano completo. Pronto para execução via subagent-driven-development.**
