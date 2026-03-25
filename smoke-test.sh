#!/usr/bin/env bash
# Smoke test for MCP servers (odoo-mcp-server, google-drive-mcp-server).
# Calls the health endpoint and a representative tool to verify the service is alive.
#
# Usage:
#   ./smoke-test-mcp.sh <base-url> <mcp-secret>
#
# Example:
#   ./smoke-test-mcp.sh http://localhost:8080 dev
#   ./smoke-test-mcp.sh https://odoo-mcp-server-njiacix2yq-as.a.run.app my-secret

set -euo pipefail

BASE_URL="${1:?Usage: $0 <base-url> <mcp-secret>}"
SECRET="${2:?Usage: $0 <base-url> <mcp-secret>}"
PASSED=0
FAILED=0

check() {
    local name="$1"
    local url="$2"
    local expected_status="${3:-200}"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "$url" --max-time 10 2>/dev/null || echo "000")

    if [ "$status" = "$expected_status" ]; then
        echo "  PASS  $name (HTTP $status)"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL  $name (expected HTTP $expected_status, got $status)"
        FAILED=$((FAILED + 1))
    fi
}

echo "Smoke testing: $BASE_URL"
echo "---"

# Health check (no secret needed)
check "Health endpoint" "$BASE_URL/healthz"

# SSE endpoint (should return 200 for GET — starts SSE stream)
check "SSE endpoint reachable" "$BASE_URL/$SECRET/sse"

echo "---"
echo "Results: $PASSED passed, $FAILED failed"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
