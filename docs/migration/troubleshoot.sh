#!/bin/bash

# TrustShell Troubleshooting Script

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "=== TrustShell Troubleshooting ==="
echo "Timestamp: $(date)"
echo

# Check environment variables
log_info "1. Checking environment variables..."
echo "TRUSTIFY_URL: ${TRUSTIFY_URL:-'NOT SET'}"
echo "AUTH_ENDPOINT: ${AUTH_ENDPOINT:-'NOT SET'}"
echo "LOCAL_AUTH_SERVER_PORT: ${LOCAL_AUTH_SERVER_PORT:-'NOT SET'}"
echo

# Check network connectivity
log_info "2. Testing network connectivity..."
if [[ -n "${TRUSTIFY_URL:-}" ]]; then
    base_url=$(echo "$TRUSTIFY_URL" | sed 's|/api/v2/||')
    log_info "Testing connection to: $base_url"
    if timeout 10 curl -s "$base_url" >/dev/null 2>&1; then
        log_success "Base URL is reachable"
    else
        log_error "Cannot reach base URL"
    fi
    
    # Test API endpoint
    log_info "Testing API endpoint: ${TRUSTIFY_URL}analysis/status"
    response=$(timeout 10 curl -s -w "HTTP_CODE:%{http_code}" "${TRUSTIFY_URL}analysis/status" 2>&1 || echo "FAILED")
    if [[ "$response" =~ HTTP_CODE:403 ]]; then
        log_warning "API returned 403 - authentication required (expected in headless mode)"
    elif [[ "$response" =~ HTTP_CODE:200 ]]; then
        log_success "API endpoint is accessible"
    else
        log_error "API endpoint test failed: $response"
    fi
else
    log_error "TRUSTIFY_URL not set"
fi
echo

# Check OIDC server
log_info "3. Checking OIDC server..."
if [[ -n "${LOCAL_AUTH_SERVER_PORT:-}" ]]; then
    if timeout 5 curl -s "http://localhost:${LOCAL_AUTH_SERVER_PORT}/" >/dev/null 2>&1; then
        log_success "OIDC server is responding on port $LOCAL_AUTH_SERVER_PORT"
    else
        log_error "OIDC server not responding on port $LOCAL_AUTH_SERVER_PORT"
        
        # Check if container is running
        if podman ps | grep -q oidc; then
            log_info "OIDC container is running:"
            podman ps | grep oidc
        else
            log_warning "No OIDC container found running"
        fi
    fi
else
    log_warning "LOCAL_AUTH_SERVER_PORT not set"
fi
echo

# Test trust commands with short timeout
log_info "4. Testing trust commands..."

log_info "Testing trust-api analysis/status..."
if output=$(timeout 15 trust-api analysis/status 2>&1); then
    log_success "trust-api worked: $(echo "$output" | head -1)"
else
    log_error "trust-api failed: $(echo "$output" | head -1)"
fi

log_info "Testing trust-purl with very short timeout..."
if output=$(timeout 15 trust-purl --debug test 2>&1); then
    log_success "trust-purl completed"
    echo "$output" | head -5
else
    exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
        log_error "trust-purl timed out after 15 seconds"
    else
        log_error "trust-purl failed with exit code $exit_code"
    fi
    echo "Partial output:"
    echo "$output" | head -5
fi
echo

log_info "5. Recommendations:"
echo "- If OIDC server isn't running: podman run -d -p 127.0.0.1:8650:8650 -e AUTH_ENDPOINT=\"\$AUTH_ENDPOINT\" oidc-pkce-server"
echo "- If network issues: Check VPN connection and firewall settings"  
echo "- If timeouts persist: Try Atlas Stage instead of Production"
echo "- For Atlas Stage: export TRUSTIFY_URL=\"https://atlas.release.stage.devshift.net\""
echo "                  export AUTH_ENDPOINT=\"https://auth.stage.redhat.com/auth/realms/EmployeeIDP/protocol/openid-connect\""
