#!/bin/bash

# SSH Connection Monitor - Quick Start Script
# This script helps you get started with sshmon

set -e

echo "=== SSH Connection Monitor Setup ==="
echo ""

# Step 1: Generate host key if it doesn't exist
if [ ! -f ssh_host_key ]; then
    echo "[1/4] Generating SSH host key..."
    ssh-keygen -t ed25519 -f ssh_host_key -N "" -C "sshmon-host-key"
    echo "✓ Host key generated"
else
    echo "[1/4] Host key already exists"
fi

# Step 2: Build the binary
echo ""
echo "[2/4] Building sshmon..."
go build -o sshmon .
echo "✓ Build complete"

# Step 3: Start sshmon in background
echo ""
echo "[3/4] Starting sshmon..."
echo "  - SSH Proxy: localhost:2222"
echo "  - Metrics:   http://localhost:9090"
echo "  - Target:    localhost:22"
echo ""

./sshmon -hostkey ssh_host_key -listen :2222 -target localhost:22 -metrics :9090 &
SSHMON_PID=$!

# Give it time to start
sleep 2

echo "✓ sshmon started (PID: $SSHMON_PID)"

# Step 4: Display usage instructions
echo ""
echo "[4/4] Setup complete!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "NEXT STEPS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. View the dashboard:"
echo "   Open http://localhost:9090 in your browser"
echo ""
echo "2. Test SSH connections:"
echo "   ssh -p 2222 \$USER@localhost"
echo ""
echo "3. View metrics in different formats:"
echo "   curl http://localhost:9090/metrics          # Prometheus"
echo "   curl http://localhost:9090/metrics/json     # JSON"
echo ""
echo "4. Stop sshmon:"
echo "   kill $SSHMON_PID"
echo "   or press Ctrl+C"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Wait for user to press Ctrl+C
trap "echo ''; echo 'Stopping sshmon...'; kill $SSHMON_PID 2>/dev/null || true; echo 'Done.'; exit 0" INT TERM

echo "Press Ctrl+C to stop sshmon..."
wait $SSHMON_PID
