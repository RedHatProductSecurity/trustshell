#!/bin/bash

# Test script to demonstrate enhanced error reporting
# This simulates what happens when commands fail

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

echo "=== Enhanced Error Reporting Demo ==="
echo "This shows how the migration test script reports failures"
echo

# Test 1: Command timeout simulation
log_info "Test 1: Simulating command timeout..."
component="golang"
failed_command="trust-purl $component"

if output=$(timeout 5 trust-purl "$component" 2>&1); then
    log_success "Command completed: $failed_command"
    echo "$output" | head -3
else
    exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
        log_warning "Command timed out after 5s: $failed_command"
        log_info "Trying fallback with --use-base-purl..."
        
        fallback_command="trust-purl --use-base-purl $component"
        if fallback_output=$(timeout 10 $fallback_command 2>&1); then
            log_success "Fallback succeeded: $fallback_command"
            echo "$fallback_output" | head -3
        else
            fallback_exit_code=$?
            log_error "Both commands failed. Original: '$failed_command' (timeout), Fallback: '$fallback_command' (exit code: $fallback_exit_code)"
            
            # Run with debug mode
            log_info "Running failed fallback command with debug mode for analysis..."
            if debug_output=$(timeout 10 trust-purl --use-base-purl --debug "$component" 2>&1); then
                log_info "Debug output (first 10 lines):"
                echo "$debug_output" | head -10 | sed 's/^/  /'
            else
                log_error "Debug command also failed"
                echo "$debug_output" | head -5 | sed 's/^/  /'
            fi
        fi
    else
        log_error "Command failed with exit code $exit_code: $failed_command"
        
        # Run with debug mode
        log_info "Running failed command with debug mode for analysis..."
        if debug_output=$(timeout 10 trust-purl --debug "$component" 2>&1); then
            log_info "Debug output (first 10 lines):"
            echo "$debug_output" | head -10 | sed 's/^/  /'
        else
            log_error "Debug command also failed"
            echo "$debug_output" | head -5 | sed 's/^/  /'
        fi
    fi
fi

echo
echo "=== Error Reporting Features ==="
echo "✅ Shows exact command that failed"
echo "✅ Distinguishes between timeouts and other failures"
echo "✅ Shows exit codes for non-timeout failures"
echo "✅ Automatically runs failed commands with --debug flag"
echo "✅ Shows debug output for troubleshooting"
echo "✅ Handles both original and fallback command failures"
echo "✅ Provides structured error messages"
