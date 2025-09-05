#!/bin/bash

# TrustShell Migration Test Script
# Automated testing to validate trustshell can replace newtopia-cli

set -euo pipefail

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS] [PACKAGE...]

Test trustshell functionality and compare with newtopia-cli capabilities.

OPTIONS:
    -h, --help          Show this help message
    --components-only   Test only package search, skip product mapping and OSIDB tests
    --quick             Run with shorter timeouts for faster testing
    --verbose           Show additional debug information

PACKAGE:
    One or more package names to test (e.g., jenkins, httpd, nginx)
    If no packages specified, uses default test set: golang, nodejs, string-width, kernel-headers

EXAMPLES:
    $0                          # Test default packages
    $0 jenkins                  # Test only jenkins
    $0 jenkins httpd nginx      # Test multiple specific packages
    $0 --quick golang           # Quick test of golang
    $0 --components-only jenkins # Test jenkins package search only

ENVIRONMENT:
    Required environment variables:
    - TRUSTIFY_URL: Trustify instance URL
    - AUTH_ENDPOINT: Authentication endpoint
    - LOCAL_AUTH_SERVER_PORT: OIDC server port (usually 8650)

EOF
}

# Parse command line arguments
COMPONENTS_ONLY=false
QUICK_MODE=false
VERBOSE_MODE=false
CUSTOM_COMPONENTS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        --components-only)
            COMPONENTS_ONLY=true
            shift
            ;;
        --quick)
            QUICK_MODE=true
            shift
            ;;
        --verbose)
            VERBOSE_MODE=true
            shift
            ;;
        -*)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            CUSTOM_COMPONENTS+=("$1")
            shift
            ;;
    esac
done

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_RESULTS_DIR="${SCRIPT_DIR}/test_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${TEST_RESULTS_DIR}/migration_test_${TIMESTAMP}.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default test components from gitlab-ci.yml
DEFAULT_TEST_COMPONENTS=(
    "golang"
    "nodejs" 
    "string-width"
    "kernel-headers"
)

# Additional test components for comprehensive coverage
EXTENDED_TEST_COMPONENTS=(
    "glibc"
    "openssl"
    "json-pointer"
    "qemu"
    "python3"
)

# Set timeouts based on mode
if [[ "$QUICK_MODE" == "true" ]]; then
    PRIMARY_TIMEOUT=60
    FALLBACK_TIMEOUT=120
    PRODUCT_TIMEOUT=120
else
    PRIMARY_TIMEOUT=150
    FALLBACK_TIMEOUT=300
    PRODUCT_TIMEOUT=300
fi

# Initialize results structure
declare -A test_results

# Utility functions
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

# Create test results directory
setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Determine which components to test
    if [[ ${#CUSTOM_COMPONENTS[@]} -gt 0 ]]; then
        TEST_COMPONENTS=("${CUSTOM_COMPONENTS[@]}")
        log_info "Testing custom components: ${TEST_COMPONENTS[*]}"
    else
        TEST_COMPONENTS=("${DEFAULT_TEST_COMPONENTS[@]}")
        log_info "Testing default components: ${TEST_COMPONENTS[*]}"
    fi
    
    # Log mode information
    if [[ "$QUICK_MODE" == "true" ]]; then
        log_info "Quick mode enabled - using shorter timeouts"
    fi
    
    if [[ "$COMPONENTS_ONLY" == "true" ]]; then
        log_info "Components-only mode - skipping product mapping and OSIDB tests"
    fi
    
    mkdir -p "${TEST_RESULTS_DIR}"
    
    # Verify required environment variables
    local required_vars=(
        "TRUSTIFY_URL"
        "AUTH_ENDPOINT"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required environment variable $var is not set"
            exit 1
        fi
    done
    
    # Set headless mode if not already set
    if [[ -z "${LOCAL_AUTH_SERVER_PORT:-}" ]]; then
        export LOCAL_AUTH_SERVER_PORT=8650
        log_info "Set LOCAL_AUTH_SERVER_PORT=8650 for headless mode"
    fi
    
    log_success "Test environment setup complete"
}

# Check if tools are available
check_tool_availability() {
    log_info "Checking tool availability..."
    
    local tools_available=true
    
    if ! command -v trust-purl &> /dev/null; then
        log_error "trust-purl command not found. Please install trustshell."
        tools_available=false
    fi
    
    if ! command -v trust-products &> /dev/null; then
        log_error "trust-products command not found. Please install trustshell."
        tools_available=false
    fi
    
    if ! command -v newcli &> /dev/null; then
        log_warning "newcli command not found. Some comparison tests will be skipped."
    fi
    
    if [[ "$tools_available" == "false" ]]; then
        exit 1
    fi
    
    # Test basic connectivity to TRUSTIFY_URL
    log_info "Testing connectivity to TRUSTIFY_URL..."
    if [[ -n "$TRUSTIFY_URL" ]]; then
        local base_url=$(echo "$TRUSTIFY_URL" | sed 's|/api/v2/||')
        if curl -s --connect-timeout 10 --max-time 20 "$base_url" >/dev/null 2>&1; then
            log_success "Successfully connected to $base_url"
        else
            log_warning "Could not connect to $base_url - this may cause timeouts"
        fi
    else
        log_warning "TRUSTIFY_URL not set"
    fi
    
    log_success "Tool availability check complete"
}

# Test trustshell authentication
test_authentication() {
    log_info "Testing trustshell authentication..."
    
    local start_time=$(date +%s)
    local auth_result="FAIL"
    local error_message=""
    local auth_output=""
    
    # Test with a simple API call
    if auth_output=$(trust-purl kernel 2>&1); then
        if [[ "$auth_output" =~ "HTTP error 403" ]]; then
            error_message="Authentication required - 403 Forbidden"
            log_warning "$error_message"
        else
            auth_result="PASS"
            log_success "Authentication test passed"
        fi
    else
        local exit_code=$?
        local failed_command="trust-purl kernel"
        
        if [[ $exit_code -eq 124 ]]; then
            error_message="Command timed out: $failed_command"
        else
            error_message="Command failed with exit code $exit_code: $failed_command"
        fi
        log_error "$error_message"
        
        # Show partial output for debugging
        if [[ -n "$auth_output" ]]; then
            log_info "Command output (first 5 lines):"
            echo "$auth_output" | head -5 | sed 's/^/  /'
        fi
        
        # Additional debugging
        log_info "Checking OIDC server status..."
        if curl -s --connect-timeout 5 http://localhost:8650/ >/dev/null 2>&1; then
            log_info "OIDC server is responding on port 8650"
        else
            log_warning "OIDC server may not be running on port 8650"
        fi
        
        # Try with debug mode
        log_info "Running authentication test with debug mode..."
        local debug_output
        if debug_output=$(timeout 15 trust-api --debug analysis/status 2>&1); then
            log_info "Debug output (first 10 lines):"
            echo "$debug_output" | head -10 | sed 's/^/  /'
        else
            log_error "Debug command also failed: trust-api --debug analysis/status"
            echo "$debug_output" | head -5 | sed 's/^/  /'
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    test_results["auth_test"]=$(cat <<EOF
{
    "test": "authentication",
    "result": "$auth_result",
    "duration": $duration,
    "auth_output": "$(echo "$auth_output" | head -3 | tr '\n' '|')",
    "error": "$error_message"
}
EOF
    )
}

# Test basic package search functionality (Step 1: Find PURLs)
test_package_search() {
    local component="$1"
    log_info "Testing package search for: $component (Step 1: Find PURLs)"
    
    local start_time=$(date +%s)
    local search_result="FAIL"
    local result_count=0
    local sample_results=""
    local error_message=""
    local suggested_purl=""
    
    # Run trustshell search with fallback to --use-base-purl
    local trustshell_output
    local used_base_purl=false
    
    log_info "Running: trust-purl $component (timeout: ${PRIMARY_TIMEOUT}s)"
    if trustshell_output=$(timeout $PRIMARY_TIMEOUT trust-purl "$component" 2>&1); then
        if [[ -n "$trustshell_output" ]]; then
            search_result="PASS"
            result_count=$(echo "$trustshell_output" | grep -c "pkg:" || echo "0")
            sample_results=$(echo "$trustshell_output" | head -5 | sed 's/"/\\"/g' | tr '\n' '|')
            
            # Try to identify the most likely exact match PURL for Step 2
            case "$component" in
                "golang")
                    suggested_purl="pkg:rpm/redhat/golang"
                    ;;
                "nodejs") 
                    suggested_purl="pkg:rpm/redhat/nodejs"
                    ;;
                "string-width")
                    suggested_purl="pkg:npm/string-width"
                    ;;
                "kernel-headers")
                    suggested_purl="pkg:rpm/redhat/kernel-headers"
                    ;;
                *)
                    # Extract first RPM PURL if available
                    suggested_purl=$(echo "$trustshell_output" | grep "pkg:rpm" | head -1 || echo "")
                    ;;
            esac
            
            log_success "Found $result_count results for $component (suggested: $suggested_purl)"
        else
            error_message="No results returned"
            log_warning "$error_message"
        fi
    else
        # Capture exit code for better error reporting
        local exit_code=$?
        local failed_command="trust-purl $component"
        
        if [[ $exit_code -eq 124 ]]; then
            log_warning "Command timed out after ${PRIMARY_TIMEOUT}s: $failed_command"
            log_info "Trying fallback with --use-base-purl..."
            used_base_purl=true
            
            # Fallback to --use-base-purl (faster but less accurate)
            local fallback_command="trust-purl --use-base-purl $component"
            if trustshell_output=$(timeout $FALLBACK_TIMEOUT $fallback_command 2>&1); then
                if [[ -n "$trustshell_output" ]]; then
                    search_result="PASS"
                    result_count=$(echo "$trustshell_output" | grep -c "pkg:" || echo "0")
                    sample_results=$(echo "$trustshell_output" | head -5 | sed 's/"/\\"/g' | tr '\n' '|')
                    
                    # Try to identify the most likely exact match PURL for Step 2
                    case "$component" in
                        "golang")
                            suggested_purl="pkg:rpm/redhat/golang"
                            ;;
                        "nodejs") 
                            suggested_purl="pkg:rpm/redhat/nodejs"
                            ;;
                        "string-width")
                            suggested_purl="pkg:npm/string-width"
                            ;;
                        "kernel-headers")
                            suggested_purl="pkg:rpm/redhat/kernel-headers"
                            ;;
                        *)
                            # Extract first RPM PURL if available
                            suggested_purl=$(echo "$trustshell_output" | grep "pkg:rpm" | head -1 || echo "")
                            ;;
                    esac
                    
                    log_success "Found $result_count results for $component using --use-base-purl (suggested: $suggested_purl)"
                else
                    error_message="No results returned even with fallback command: $fallback_command"
                    log_error "$error_message"
                    
                    # Run with debug mode for detailed error analysis
                    log_info "Running fallback command with debug mode for analysis..."
                    local debug_output
                    if debug_output=$(timeout 30 trust-purl --use-base-purl --debug "$component" 2>&1); then
                        log_info "Debug output (first 10 lines):"
                        echo "$debug_output" | head -10 | sed 's/^/  /'
                    else
                        log_error "Debug command also failed: trust-purl --use-base-purl --debug $component"
                        echo "$debug_output" | head -5 | sed 's/^/  /'
                    fi
                fi
            else
                local fallback_exit_code=$?
                error_message="Both commands failed. Original: '$failed_command' (timeout), Fallback: '$fallback_command' (exit code: $fallback_exit_code)"
                log_error "$error_message"
                
                # Run the failed fallback command with debug mode
                log_info "Running failed fallback command with debug mode for analysis..."
                local debug_output
                if debug_output=$(timeout 30 trust-purl --use-base-purl --debug "$component" 2>&1); then
                    log_info "Debug output (first 10 lines):"
                    echo "$debug_output" | head -10 | sed 's/^/  /'
                else
                    log_error "Debug command also failed"
                    echo "$debug_output" | head -5 | sed 's/^/  /'
                fi
            fi
        else
            error_message="Command failed with exit code $exit_code: $failed_command"
            log_error "$error_message"
            
            # Run the failed command with debug mode for analysis
            log_info "Running failed command with debug mode for analysis..."
            local debug_output
            if debug_output=$(timeout 30 trust-purl --debug "$component" 2>&1); then
                log_info "Debug output (first 10 lines):"
                echo "$debug_output" | head -10 | sed 's/^/  /'
            else
                log_error "Debug command also failed"
                echo "$debug_output" | head -5 | sed 's/^/  /'
            fi
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    test_results["search_${component}"]=$(cat <<EOF
{
    "test": "package_search",
    "component": "$component",
    "result": "$search_result",
    "duration": $duration,
    "result_count": $result_count,
    "sample_results": "$sample_results",
    "suggested_purl": "$suggested_purl",
    "used_base_purl": $used_base_purl,
    "error": "$error_message"
}
EOF
    )
    
    # If we found a suggested PURL, test Step 2 (exact product mapping)
    if [[ -n "$suggested_purl" ]]; then
        test_exact_product_mapping "$component" "$suggested_purl"
    fi
}

# Test exact product mapping (Step 2: Get exact product mappings)
test_exact_product_mapping() {
    local component="$1"
    local purl="$2"
    log_info "Testing exact product mapping for: $component -> $purl (Step 2)"
    
    local start_time=$(date +%s)
    local mapping_result="FAIL"
    local product_count=0
    local sample_products=""
    local error_message=""
    
    # Run trustshell product mapping for exact PURL
    local trustshell_output
    if trustshell_output=$(timeout $PRODUCT_TIMEOUT trust-products "$purl" 2>&1); then
        if [[ -n "$trustshell_output" ]]; then
            mapping_result="PASS"
            product_count=$(echo "$trustshell_output" | grep -c "cpe:" || echo "0")
            sample_products=$(echo "$trustshell_output" | head -10 | sed 's/"/\\"/g' | tr '\n' '|')
            log_success "Found $product_count products for exact match: $purl"
        else
            error_message="No product mappings found for exact PURL"
            log_warning "$error_message"
        fi
    else
        local exit_code=$?
        local failed_command="trust-products $purl"
        
        if [[ $exit_code -eq 124 ]]; then
            error_message="Command timed out: $failed_command"
        else
            error_message="Command failed with exit code $exit_code: $failed_command"
        fi
        log_error "$error_message"
        
        # Run with debug mode for detailed error analysis
        log_info "Running failed command with debug mode for analysis..."
        local debug_output
        if debug_output=$(timeout 30 trust-products --debug "$purl" 2>&1); then
            log_info "Debug output (first 10 lines):"
            echo "$debug_output" | head -10 | sed 's/^/  /'
        else
            log_error "Debug command also failed: trust-products --debug $purl"
            echo "$debug_output" | head -5 | sed 's/^/  /'
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    test_results["exact_${component}"]=$(cat <<EOF
{
    "test": "exact_product_mapping",
    "component": "$component",
    "purl": "$purl",
    "result": "$mapping_result",
    "duration": $duration,
    "product_count": $product_count,
    "sample_products": "$sample_products",
    "error": "$error_message"
}
EOF
    )
}

# Test product mapping functionality
test_product_mapping() {
    local purl="$1"
    log_info "Testing product mapping for: $purl"
    
    local start_time=$(date +%s)
    local mapping_result="FAIL"
    local product_count=0
    local sample_products=""
    local error_message=""
    
    # Run trustshell product mapping
    local trustshell_output
    if trustshell_output=$(timeout 60 trust-products "$purl" 2>&1); then
        if [[ -n "$trustshell_output" ]]; then
            mapping_result="PASS"
            product_count=$(echo "$trustshell_output" | grep -c "cpe:" || echo "0")
            sample_products=$(echo "$trustshell_output" | head -10 | sed 's/"/\\"/g' | tr '\n' '|')
            log_success "Found $product_count products for $purl"
        else
            error_message="No product mappings found"
            log_warning "$error_message"
        fi
    else
        error_message="Command failed or timed out"
        log_error "$error_message"
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    test_results["mapping_$(echo "$purl" | sed 's/[^a-zA-Z0-9]/_/g')"]=$(cat <<EOF
{
    "test": "product_mapping",
    "purl": "$purl",
    "result": "$mapping_result",
    "duration": $duration,
    "product_count": $product_count,
    "sample_products": "$sample_products",
    "error": "$error_message"
}
EOF
    )
}

# Test OSIDB integration functionality
test_osidb_integration() {
    local purl="$1"
    local test_flaw="CVE-2023-45288"  # Use a known CVE for testing
    log_info "Testing OSIDB integration for: $purl with $test_flaw"
    
    local start_time=$(date +%s)
    local osidb_result="FAIL"
    local error_message=""
    local dry_run_output=""
    
    # Test OSIDB integration (dry run - don't actually update)
    # First check if the flaw exists and get current affects
    local osidb_output
    if osidb_output=$(timeout 60 trust-products "$purl" --flaw "$test_flaw" 2>&1); then
        if [[ "$osidb_output" =~ "Would you like to add them" ]] || [[ "$osidb_output" =~ "No new affects" ]] || [[ "$osidb_output" =~ "affects will REPLACE" ]]; then
            osidb_result="PASS"
            dry_run_output=$(echo "$osidb_output" | head -20 | sed 's/"/\\"/g' | tr '\n' '|')
            log_success "OSIDB integration works for $purl"
        else
            error_message="Unexpected OSIDB output format"
            dry_run_output=$(echo "$osidb_output" | head -10 | sed 's/"/\\"/g' | tr '\n' '|')
            log_warning "$error_message"
        fi
    else
        local exit_code=$?
        local failed_command="trust-products $purl --flaw $test_flaw"
        
        if [[ $exit_code -eq 124 ]]; then
            error_message="Command timed out: $failed_command"
        else
            error_message="Command failed with exit code $exit_code: $failed_command"
        fi
        log_error "$error_message"
        
        # Run with debug mode for detailed error analysis
        log_info "Running failed command with debug mode for analysis..."
        local debug_output
        if debug_output=$(timeout 30 trust-products --debug "$purl" --flaw "$test_flaw" 2>&1); then
            log_info "Debug output (first 10 lines):"
            echo "$debug_output" | head -10 | sed 's/^/  /'
        else
            log_error "Debug command also failed: trust-products --debug $purl --flaw $test_flaw"
            echo "$debug_output" | head -5 | sed 's/^/  /'
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    test_results["osidb_$(echo "$purl" | sed 's/[^a-zA-Z0-9]/_/g')"]=$(cat <<EOF
{
    "test": "osidb_integration",
    "purl": "$purl",
    "flaw": "$test_flaw",
    "result": "$osidb_result",
    "duration": $duration,
    "dry_run_output": "$dry_run_output",
    "error": "$error_message"
}
EOF
    )
}

# Test build type filtering via PURL types
test_build_type_filtering() {
    log_info "Testing build type filtering via PURL types..."
    
    local build_types=("rpm" "oci" "maven" "npm" "pypi")
    local test_components=("golang" "openssl" "jackson" "lodash" "requests")
    
    for i in "${!build_types[@]}"; do
        local build_type="${build_types[$i]}"
        local component="${test_components[$i]}"
        local search_term="$build_type $component"
        
        log_info "Testing build type filtering: $search_term"
        
        local start_time=$(date +%s)
        local filter_result="FAIL"
        local filtered_count=0
        local error_message=""
        
        local filter_output
        if filter_output=$(timeout 30 trust-purl "$search_term" 2>&1); then
            if [[ -n "$filter_output" ]]; then
                # Check if results contain the expected PURL type
                filtered_count=$(echo "$filter_output" | grep -c "pkg:$build_type" || echo "0")
                if [[ $filtered_count -gt 0 ]]; then
                    filter_result="PASS"
                    log_success "Found $filtered_count $build_type packages for $component"
                else
                    error_message="No packages found with expected build type"
                    log_warning "$error_message"
                fi
            else
                error_message="No results returned"
                log_warning "$error_message"
            fi
        else
            error_message="Build type filtering failed or timed out"
            log_error "$error_message"
        fi
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        test_results["buildtype_${build_type}_${component}"]=$(cat <<EOF
{
    "test": "build_type_filtering",
    "build_type": "$build_type",
    "component": "$component",
    "result": "$filter_result",
    "duration": $duration,
    "filtered_count": $filtered_count,
    "error": "$error_message"
}
EOF
        )
    done
}

# Test data coverage by comparing result counts
test_data_coverage() {
    log_info "Testing data coverage comparison..."
    
    local coverage_components=("openssl" "glibc" "python3" "httpd" "nginx")
    
    for component in "${coverage_components[@]}"; do
        log_info "Testing data coverage for: $component"
        
        local start_time=$(date +%s)
        local coverage_result="INFO"
        local trustshell_count=0
        local error_message=""
        
        # Get trustshell result count with fallback
        local trustshell_output
        if trustshell_output=$(timeout 30 trust-purl "$component" 2>&1); then
            trustshell_count=$(echo "$trustshell_output" | grep -c "pkg:" || echo "0")
            log_info "Found $trustshell_count results for $component in trustshell"
        else
            log_info "Standard search timed out, trying --use-base-purl..."
            if trustshell_output=$(timeout 15 trust-purl --use-base-purl "$component" 2>&1); then
                trustshell_count=$(echo "$trustshell_output" | grep -c "pkg:" || echo "0")
                log_info "Found $trustshell_count results for $component using --use-base-purl"
            else
                error_message="Failed to get trustshell results even with --use-base-purl"
                log_warning "$error_message"
            fi
        fi
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        test_results["coverage_${component}"]=$(cat <<EOF
{
    "test": "data_coverage",
    "component": "$component",
    "result": "$coverage_result",
    "duration": $duration,
    "trustshell_count": $trustshell_count,
    "note": "Compare with manifest-box data at https://product-security.pages.redhat.com/manifest-box/",
    "error": "$error_message"
}
EOF
        )
    done
}


# Run comprehensive package search tests
run_package_search_tests() {
    log_info "Running package search tests..."
    
    # Test selected components
    for component in "${TEST_COMPONENTS[@]}"; do
        test_package_search "$component"
    done
    
    # Test extended components only if using defaults and not in components-only mode
    if [[ ${#CUSTOM_COMPONENTS[@]} -eq 0 && "$COMPONENTS_ONLY" == "false" ]]; then
        log_info "Running extended component tests..."
        for component in "${EXTENDED_TEST_COMPONENTS[@]}"; do
            test_package_search "$component"
        done
    fi
}

# Run product mapping tests with sample PURLs
run_product_mapping_tests() {
    log_info "Running product mapping tests..."
    
    local sample_purls=(
        "pkg:rpm/redhat/glibc"
        "pkg:oci/quay-builder-qemu-rhcos-rhel8"
        "pkg:rpm/redhat/openssl"
        "pkg:golang/golang.org/x/net"
    )
    
    for purl in "${sample_purls[@]}"; do
        test_product_mapping "$purl"
    done
}

# Run OSIDB integration tests
run_osidb_integration_tests() {
    log_info "Running OSIDB integration tests..."
    
    local test_purls=(
        "pkg:rpm/redhat/golang"
        "pkg:golang/golang.org/x/net"
        "pkg:rpm/redhat/openssl"
    )
    
    for purl in "${test_purls[@]}"; do
        test_osidb_integration "$purl"
    done
}

# Generate comprehensive test report
generate_test_report() {
    log_info "Generating test report..."
    
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    local warnings=0
    
    # Create JSON report structure
    cat > "$REPORT_FILE" << EOF
{
    "test_run": {
        "timestamp": "$TIMESTAMP",
        "environment": {
            "TRUSTIFY_URL": "$TRUSTIFY_URL",
            "AUTH_ENDPOINT": "$AUTH_ENDPOINT",
            "LOCAL_AUTH_SERVER_PORT": "${LOCAL_AUTH_SERVER_PORT:-}"
        },
        "summary": {},
        "results": {}
    }
}
EOF
    
    # Add test results to JSON
    local json_results="{"
    local first=true
    
    for test_key in "${!test_results[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            json_results+=","
        fi
        json_results+="\"$test_key\": ${test_results[$test_key]}"
        
        # Count results
        total_tests=$((total_tests + 1))
        if echo "${test_results[$test_key]}" | grep -q '"result": "PASS"'; then
            passed_tests=$((passed_tests + 1))
        elif echo "${test_results[$test_key]}" | grep -q '"result": "FAIL"'; then
            failed_tests=$((failed_tests + 1))
        else
            warnings=$((warnings + 1))
        fi
    done
    
    json_results+="}"
    
    # Update report with results and summary
    local temp_file="${REPORT_FILE}.tmp"
    jq --argjson results "$json_results" \
       --arg total "$total_tests" \
       --arg passed "$passed_tests" \
       --arg failed "$failed_tests" \
       --arg warnings "$warnings" \
       '.test_run.results = $results |
        .test_run.summary = {
            "total_tests": ($total | tonumber),
            "passed_tests": ($passed | tonumber),
            "failed_tests": ($failed | tonumber),
            "warnings": ($warnings | tonumber),
            "success_rate": (($passed | tonumber) / ($total | tonumber) * 100 | round)
        }' "$REPORT_FILE" > "$temp_file"
    
    mv "$temp_file" "$REPORT_FILE"
    
    # Print summary
    echo
    log_info "=== TEST SUMMARY ==="
    log_info "Total Tests: $total_tests"
    log_success "Passed: $passed_tests"
    log_error "Failed: $failed_tests"
    log_warning "Warnings: $warnings"
    
    local success_rate=$(( (passed_tests * 100) / total_tests ))
    log_info "Success Rate: ${success_rate}%"
    
    echo
    log_info "Detailed report saved to: $REPORT_FILE"
    
    # Data coverage assessment
    echo
    log_info "=== DATA COVERAGE ASSESSMENT ==="
    log_info "For comprehensive data coverage analysis, review:"
    log_info "📊 https://product-security.pages.redhat.com/manifest-box/"
    log_info "This compares newtopia-cli (Deptopia) vs TRUSTIFY (Atlas) data coverage"
    echo
    log_info "Test results provide functional validation."
    log_info "Data coverage comparison should be evaluated separately using manifest-box."
}

# Main execution
main() {
    log_info "Starting TrustShell Migration Test Suite"
    echo "Timestamp: $(date)"
    echo "Report will be saved to: $REPORT_FILE"
    echo
    
    setup_test_environment
    check_tool_availability
    
    # Run test suites based on options
    if [[ "$COMPONENTS_ONLY" == "false" ]]; then
        test_authentication
    fi
    
    run_package_search_tests
    
    if [[ "$COMPONENTS_ONLY" == "false" ]]; then
        run_product_mapping_tests
        run_osidb_integration_tests
        test_build_type_filtering
        test_data_coverage
    else
        log_info "Components-only mode: Skipping product mapping, OSIDB, and other tests"
    fi
    
    generate_test_report
    
    log_success "Migration test suite completed!"
}

# Execute main function
main "$@"
