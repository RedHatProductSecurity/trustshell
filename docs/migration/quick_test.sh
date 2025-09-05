#!/bin/bash

# Quick TrustShell Functionality Test
# Tests the basic commands with --use-base-purl fallback

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "=== Quick TrustShell Test ==="
echo "Testing basic functionality with timeout handling"
echo

# Test components from gitlab-ci.yml
components=("golang" "nodejs" "string-width" "kernel-headers")

for component in "${components[@]}"; do
    log_info "Testing: $component"
    
    # Try normal search first (short timeout)
    if result=$(timeout 15 trust-purl "$component" 2>&1); then
        count=$(echo "$result" | grep -c "pkg:" || echo "0")
        log_success "Normal search: $count results"
        echo "$result" | head -3
    else
        log_warning "Normal search timed out, trying --use-base-purl..."
        
        # Fallback to --use-base-purl
        if result=$(timeout 15 trust-purl --use-base-purl "$component" 2>&1); then
            count=$(echo "$result" | grep -c "pkg:" || echo "0")
            log_success "Base-purl search: $count results"
            echo "$result" | head -3
        else
            log_error "Both searches failed for $component"
        fi
    fi
    echo
done

echo "=== Test Complete ==="
echo "If you saw results above, trustshell is working."
echo "The migration test script uses the same fallback logic."
