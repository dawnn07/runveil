.PHONY: build test test-race lint vet vuln clean

build:
	go build -o railcore ./cmd/railcore

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

vuln:
	govulncheck ./...

clean:
	rm -f railcore railcore.exe
	rm -rf dist/
