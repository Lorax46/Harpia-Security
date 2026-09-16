.PHONY: build run test docker clean version

APP_NAME=harpia-security
BIN=bin/$(APP_NAME)
VERSION=$(shell cat VERSION 2>/dev/null || echo "dev")
DOCKER_IMAGE=ghcr.io/lorax46/harpia-security

## build: compila o binário
build:
	go build -ldflags="-s -w -X main.Version=$(VERSION)" -o $(BIN) cmd/totvs-horus/main.go

## run: executa localmente
run:
	go run cmd/totvs-horus/main.go

## test: roda testes
test:
	go test ./...

## docker: build da imagem local
docker:
	docker build -t $(APP_NAME):$(VERSION) .
	docker tag $(APP_NAME):$(VERSION) $(APP_NAME):latest

## docker-multi: build multi-arch (amd64 + arm64)
docker-multi:
	docker buildx build --platform linux/amd64,linux/arm64 -t $(DOCKER_IMAGE):$(VERSION) --push .

## docker-run: executa container local
docker-run:
	docker compose up -d

## docker-stop: para container
docker-stop:
	docker compose down

## version: mostra versão atual
version:
	@echo "Version: $(VERSION)"

## version-bump-patch: incrementa patch version (0.0.1 -> 0.0.2)
version-bump-patch:
	@echo $(shell echo $(VERSION) | awk -F. '{$$NF = $$NF + 1;} 1' | sed 's/ /./g') > VERSION
	@echo "Bumped to: $(shell cat VERSION)"

## version-bump-minor: incrementa minor version (0.1.0)
version-bump-minor:
	@echo $(shell echo $(VERSION) | awk -F. '{$$2 = $$2 + 1; $$3 = 0;} 1' | sed 's/ /./g') > VERSION
	@echo "Bumped to: $(shell cat VERSION)"

## version-bump-major: incrementa major version (1.0.0)
version-bump-major:
	@echo $(shell echo $(VERSION) | awk -F. '{$$1 = $$1 + 1; $$2 = 0; $$3 = 0;} 1' | sed 's/ /./g') > VERSION
	@echo "Bumped to: $(shell cat VERSION)"

## release: cria tag e push para GitHub (dispara Actions)
release:
	git add VERSION
	git commit -m "chore: bump version to $(VERSION)"
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin main --tags

## clean: limpa artefatos
clean:
	rm -rf bin/ output/ reports/

## dev: hot reload (requires air)
dev:
	air
