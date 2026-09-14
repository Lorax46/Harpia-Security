# Harpia Security v3.0 — Protótipo

Scanner CNAPP multi-cloud (AWS, GCP, Azure, OCI) baseado no Prowler v5.41.

## Status Atual (14/09/2026)

### Providers Implementados
| Provider | Checks | Status |
|----------|--------|--------|
| AWS | ~521 | ✅ 83% cobertura Prowler |
| Azure | 17 | 🟡 9% cobertura |
| GCP | 143 | 🟡 130% (extras) |
| OCI | 34 | 🟡 65% cobertura |
| Cloudflare | 29 | ✅ 100% |

### Arquitetura

```
main.go → web.NewScanService()
         ↓
    scanner.NewService()
         ↓
    aws.NewProvider() → Clients SDK v2
         ↓
    executor.New(provider, checks...) → Run()
         ↓
    ScanResult → API REST → Frontend
```

## Como Testar

### 1. Build
```bash
cd /home/ubuntu/totvs-horus
go build -o ./harpia ./cmd/totvs-horus/
```

### 2. Configurar Credenciais

Opção A — AWS CLI configurado:
```bash
aws configure
```

Opção B — Variáveis de ambiente:
```bash
export AWS_ACCESS_KEY_ID=sua_chave
export AWS_SECRET_ACCESS_KEY=sua_secret
export AWS_REGION=us-east-1
```

### 3. Executar
```bash
./harpia
# Servidor em :8080
```

### 4. Endpoints

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | /api/auth/login | Login (admin/admin) |
| GET | /api/scans | Listar scans |
| POST | /api/scans | Criar scan |
| GET | /api/scans/:id | Detalhes do scan |
| POST | /api/scans/:id/run | Executar scan |
| GET | /api/findings | Listar findings |
| GET | /api/findings/:id | Detalhe do finding |
| GET | /api/stats | Estatísticas |

### 5. Executar Scan via API

```bash
# Criar scan
curl -X POST http://localhost:8080/api/scans \
  -H "Authorization: Bearer beta-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "AWS Scan", "provider": "aws"}'

# Executar scan (substitua :id)
curl -X POST http://localhost:8080/api/scans/:id/run \
  -H "Authorization: Bearer beta-admin-token"

# Ver findings
curl http://localhost:8080/api/findings \
  -H "Authorization: Bearer beta-admin-token"
```

## Estrutura de Diretórios

```
cmd/totvs-horus/main.go          # Entry point
internal/
  scanner/
    executor/                     # Executor de checks (paralelo)
    models/                       # Finding, CheckMetadata, ScanResult
    providers/aws/                # Provider AWS (todos os clients SDK)
    checks/
      aws/                        # ~521 checks organizados por serviço
        iam/
        ec2/
        s3/
        registry.go               # Registry central AWS
      azure/
      gcp/
      oci/
      cloudflare/
    registry/                     # Registry global
    service.go                    # Orchestrator
pkg/
  web/
    server.go                     # Servidor HTTP (Gin)
    handlers.go                   # Handlers REST
    services.go                   # Mock services
    scan_service.go               # Wrapper scanner → web
```

## Verificar Checks

```bash
# Total no registry
grep -c "New" internal/scanner/checks/aws/registry.go

# Total por provider
for p in aws azure gcp oci cloudflare; do
  echo -n "$p: "
  find internal/scanner/checks/$p -name '*.go' -exec grep -h '^func New' {} \; | wc -l
done

# Comparar com Prowler
prowler aws --list-checks | grep '^\[' | wc -l
```
