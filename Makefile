.PHONY: build test clean install run docker

BINARY_NAME=sshmon
INSTALL_PATH=/usr/local/bin

build:
	go build -o $(BINARY_NAME) .

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

install: build
	install -m 755 $(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)

run: build
	./$(BINARY_NAME) -hostkey ssh_host_key -listen :2222 -target localhost:22 -metrics :9090

genkey:
	ssh-keygen -t ed25519 -f ssh_host_key -N ""

docker:
	docker build -t sshmon:latest .

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...

vet:
	go vet ./...
