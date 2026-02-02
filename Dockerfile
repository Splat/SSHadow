FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o SSHadow .

FROM alpine:latest

RUN apk --no-cache add ca-certificates openssh-client

WORKDIR /app

# Copy binary
COPY --from=builder /build/SSHadow .

# Create directory for host keys
RUN mkdir -p /etc/SSHadow && chmod 700 /etc/SSHadow

# Expose ports
EXPOSE 2222 9090

# Run
ENTRYPOINT ["/app/SSHadow"]
CMD ["-hostkey", "/etc/SSHadow/ssh_host_key", "-listen", ":2222", "-target", "host.docker.internal:22", "-metrics", ":9090"]
