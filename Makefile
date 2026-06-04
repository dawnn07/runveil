.PHONY: build test test-race lint vet vuln clean

build:
	go build -o runveil ./cmd/runveil

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
	rm -f runveil runveil.exe
	rm -rf dist/
