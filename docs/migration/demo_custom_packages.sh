#!/bin/bash

# Demo script showing custom package testing functionality

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

echo "=== TrustShell Custom Package Testing Demo ==="
echo

log_info "The migration test script now supports custom package testing!"
echo

echo "Usage examples:"
echo "  ./migration_test.sh                          # Default packages: golang, nodejs, string-width, kernel-headers"
echo "  ./migration_test.sh jenkins                  # Test only jenkins"
echo "  ./migration_test.sh jenkins httpd nginx      # Test multiple packages"
echo "  ./migration_test.sh --quick jenkins          # Quick test with shorter timeouts"
echo "  ./migration_test.sh --components-only jenkins # Package search only, skip product mapping"
echo

log_info "Available options:"
echo "  --components-only   Test only package search, skip product mapping and OSIDB tests"
echo "  --quick             Run with shorter timeouts (30s/15s instead of 60s/30s)"
echo "  --verbose           Show additional debug information"
echo "  --help              Show full help message"
echo

log_info "Custom packages you might want to test:"
echo "  jenkins       # Popular CI/CD server"
echo "  httpd         # Apache web server"
echo "  nginx         # Nginx web server"
echo "  postgresql    # PostgreSQL database"
echo "  mysql         # MySQL database"
echo "  redis         # Redis cache"
echo "  docker        # Container runtime"
echo "  kubernetes    # Container orchestration"
echo "  prometheus    # Monitoring system"
echo "  grafana       # Visualization platform"
echo

log_info "Quick test command for jenkins:"
echo "  ./migration_test.sh --components-only --quick jenkins"
echo

log_success "This allows targeted testing of specific packages relevant to your use case!"
