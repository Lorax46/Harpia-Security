# TOTVS Horus 🦅

**CNAPP (Cloud-Native Application Protection Platform)** — plataforma de segurança multi-cloud com scans agentless, misconfigurations, vulnerabilidades e inventário.

## Visão Geral

O TOTVS Horus consolida os principais módulos de segurança cloud:

| Módulo | Descrição |
|--------|-----------|
| CSPM | Cloud Security Posture Management |
| CWPP | Cloud Workload Protection Platform |
| CIEM | Cloud Infrastructure Entitlement Management |
| KSPM | Kubernetes Security Posture Management |
| IaC Security | Scanning de Terraform, CloudFormation, ARM |
| Container Scanning | Vulnerabilidades em imagens |
| Vulnerability Management | CVEs com priorização por exploitabilidade |
| DSPM | Data Security Posture Management |
| API Security | Descoberta e proteção de APIs |
| CDR | Cloud Detection & Response |
| AppSec | SAST/DAST/SCA (code-to-cloud) |

## Arquitetura

- **Multi-cloud:** AWS, GCP, Azure, OCI
- **Scan agentless:** sem agentes nas instâncias
- **Prowler:** motor de scan para misconfigurations
- **Severidade:** Critical, High, Medium, Low, Informacional

## Quick Start

```bash
# Build
docker compose up -d

# Executar scan
./scripts/setup_prowler.sh install
./scripts/setup_prowler.sh scan aws

# Build local
make build
./bin/totvs-horus version
```

## Estrutura

```
.
├── cmd/totvs-horus/        # Entrypoint Go
├── internal/          # Core packages
│   ├── providers/     # AWS, GCP, Azure, OCI
│   ├── scanner/       # Motor de scan
│   ├── inventory/     # Descoberta de recursos
│   └── api/           # REST API
├── pkg/
│   ├── models/        # Modelos de dados
│   └── severity/      # Lógica de severidade
├── configs/           # Configurações YAML
├── scripts/           # Scripts auxiliares
├── web/dashboard/     # Frontend
└── docs/              # Documentação
```

## Licença

MIT
