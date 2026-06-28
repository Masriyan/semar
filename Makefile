.PHONY: build test test-integration lint clean install build-all snapshot release

BINARY   := semar
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.1.0-dev)
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE) -s -w"

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./

test:
	go test ./... -race -coverprofile=coverage.out -covermode=atomic

test-integration:
	go test ./test/integration/... -v

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/ dist/ coverage.out

install: build
	cp bin/$(BINARY) /usr/local/bin/$(BINARY)

snapshot:
	goreleaser build --snapshot --clean

release:
	goreleaser release --clean

build-all:
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)_linux_amd64 ./
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)_linux_arm64 ./
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)_darwin_amd64 ./
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)_darwin_arm64 ./
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)_windows_amd64.exe ./
