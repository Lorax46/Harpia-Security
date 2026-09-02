.PHONY: build run test docker clean

APP_NAME=harpia-security
BIN=bin/$(APP_NAME)

## build: compila o binário
build:
	go build -o $(BIN) cmd/harpia/main.go

## run: executa localmente
run:
	go run cmd/harpia/main.go

## test: roda testes
test:
	go test ./...

## docker: build da imagem
docker:
	docker build -t $(APP_NAME):latest .

## clean: limpa artefatos
clean:
	rm -rf bin/ output/ reports/

## dev: hot reload (requires air)
dev:
	air
