.PHONY: build test clean install run docker release

BINARY_NAME=SSHadow
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"
INSTALL_PATH=/usr/local/bin
RELEASE_DIR=release

build:
	go build $(LDFLAGS) -o $(BINARY_NAME) .

test:
	go test -v ./...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	go clean
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html
	rm -f ssh_host_key ssh_host_key.pub
	rm -rf $(RELEASE_DIR)

install: build
	install -m 755 $(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)

run: build
	./$(BINARY_NAME) -hostkey ssh_host_key -listen :2222 -target localhost:22 -metrics :9090

genkey:
	ssh-keygen -t ed25519 -f ssh_host_key -N ""

docker:
	docker build -t sshadow:latest .

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

release: clean
	@echo "Building $(BINARY_NAME) $(VERSION) for all platforms..."
	@mkdir -p $(RELEASE_DIR)

	@echo "  linux/amd64..."
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(RELEASE_DIR)/$(BINARY_NAME)-linux-amd64 .

	@echo "  linux/arm64..."
	@GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(RELEASE_DIR)/$(BINARY_NAME)-linux-arm64 .

	@echo "  darwin/amd64..."
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(RELEASE_DIR)/$(BINARY_NAME)-darwin-amd64 .

	@echo "  darwin/arm64..."
	@GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(RELEASE_DIR)/$(BINARY_NAME)-darwin-arm64 .

	@echo "  windows/amd64..."
	@GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(RELEASE_DIR)/$(BINARY_NAME)-windows-amd64.exe .

	@echo ""
	@echo "Release binaries in $(RELEASE_DIR)/:"
	@ls -lh $(RELEASE_DIR)/
