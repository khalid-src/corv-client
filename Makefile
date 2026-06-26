.PHONY: test vet fmt build build-all vuln clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/khalid-src/corv-client/internal/version.Version=$(VERSION)

test:
	go test -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

build:
	go build -ldflags "$(LDFLAGS)" -o bin/corv ./cmd/corv

# Cross-compile for supported desktop platforms.
build-all:
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/corv-linux-amd64       ./cmd/corv
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/corv-darwin-arm64      ./cmd/corv
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/corv-windows-amd64.exe ./cmd/corv

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

clean:
	rm -rf bin
