# TrustShell Migration Test Plan

## Overview
This test plan validates that `trustshell` can adequately replace `newtopia-cli` for security analysts querying packages affected by security vulnerabilities. The main difference is that `trustshell` sources data from Trustify while `newtopia-cli` sources from Deptopia and manifest_box.

## Environment Setup

### Prerequisites
1. **Authentication Setup** (Required for trustshell):
   ```bash
   # Atlas Production
   export TRUSTIFY_URL="https://atlas.release.devshift.net"
   export AUTH_ENDPOINT="https://auth.redhat.com/auth/realms/EmployeeIDP/protocol/openid-connect"
   
   # OR Atlas Stage
   export TRUSTIFY_URL="https://atlas.release.stage.devshift.net"
   export AUTH_ENDPOINT="https://auth.stage.redhat.com/auth/realms/EmployeeIDP/protocol/openid-connect"
   
   # Product Mapping
   export PRODDEFS_URL="https://prodsec.pages.example.com/product-definitions/products.json"
   export RHEL_RELEASE_GRAPH_URL="https://gitlab.cee.example.com/api/v4/projects/prodsec%2Frhel-release-graph"
   export SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt
   
   # Headless mode (for container environments)
   export LOCAL_AUTH_SERVER_PORT=8650
   ```

2. **OIDC Server Setup** (for headless environments):
   ```bash
   podman build -f src/trustshell/oidc/Containerfile -t oidc-pkce-server .
   podman run -d -p 127.0.0.1:8650:8650 -e AUTH_ENDPOINT="$AUTH_ENDPOINT" oidc-pkce-server
   ```

3. **Install both tools**:
   ```bash
   # Install newtopia-cli
   pip install --no-cache-dir "git+https://gitlab.cee.redhat.com/prodsec-dev/newtopia-cli#egg=newtopia_cli&subdirectory=python/newtopia_cli"
   
   # Install trustshell
   pip install git+https://github.com/RedHatProductSecurity/trustshell.git#egg=trustshell
   ```

## Core Functionality Mapping

| newtopia-cli Feature | trustshell Equivalent | Status |
|---------------------|----------------------|---------|
| Package search by name | `trust-purl <name>` | ✅ |
| Product mapping | `trust-products <purl>` | ✅ |
| Ecosystem filtering (-e) | Built into purl search | ✅ |
| Strict search (-s) | Built-in exact matching | ✅ |
| Verbose output (-v/-vv) | Built-in detailed output | ✅ |
| Latest streams filtering | Default behavior (same as newtopia-cli) | ✅ |
| OSIDB integration (--flaw) | `trust-products --flaw <CVE>` | ✅ |
| Build type filtering (-b) | Built into purl search | ✅ |
| Community filtering (--no_community) | **MISSING** | ❌ |

## Test Categories

### 1. Basic Package Discovery Tests

#### Test 1.1: Simple Package Search
**Objective**: Verify basic package search functionality

**newtopia-cli commands** (from gitlab-ci.yml with `-s` for exact matching):
```bash
newcli -s golang
newcli -s nodejs  
newcli -s string-width
newcli -s kernel-headers
```

**trustshell equivalents** (two-step process for exact matching):
```bash
# Step 1: Find PURLs
trust-purl golang
trust-purl nodejs
trust-purl string-width
trust-purl kernel-headers

# Step 2: Get exact product mappings  
trust-products pkg:rpm/redhat/golang
trust-products pkg:rpm/redhat/nodejs
trust-products pkg:npm/string-width
trust-products pkg:rpm/redhat/kernel-headers
```

**Validation Criteria**:
- [ ] Both tools return results for each search term
- [ ] trustshell results include PackageURLs with proper ecosystem typing
- [ ] Results contain similar or overlapping package information
- [ ] Performance is comparable (< 30s response time)

#### Test 1.2: Ecosystem-Specific Searches
**Objective**: Test ecosystem filtering capabilities

**newtopia-cli commands**:
```bash
newcli -e golang net/http
newcli -e npm json-pointer
newcli -e maven com.h2database:h2:jar
newcli -e pypi requests
```

**trustshell equivalents**:
```bash
trust-products "pkg:golang/net/http"
trust-purl "npm json-pointer" 
trust-purl "maven com.h2database h2"
trust-purl "pypi requests"
```

**Validation Criteria**:
- [ ] Ecosystem-specific results are returned
- [ ] PURLs have correct type field (golang, npm, maven, pypi)
- [ ] No cross-ecosystem contamination in results

### 2. Product Relationship Tests

#### Test 2.1: Product Mapping
**Objective**: Verify component-to-product relationship discovery

**Test cases**:
```bash
# Test OCI containers
trust-products pkg:oci/quay-builder-qemu-rhcos-rhel8

# Test RPM packages  
trust-products pkg:rpm/redhat/glibc

# Test Maven artifacts
trust-products pkg:maven/com.h2database/h2
```

**Validation Criteria**:
- [ ] Products are correctly identified and mapped
- [ ] CPE relationships are shown where available
- [ ] Tree structure shows component hierarchy
- [ ] Latest streams filtering works by default (same behavior as newtopia-cli)
- [ ] Non-latest results can be accessed when needed

#### Test 2.2: Cross-Reference with newtopia-cli
**Objective**: Compare product mappings between tools

**Process**:
1. Run newtopia-cli searches for common components
2. Extract product/stream information
3. Run equivalent trustshell searches
4. Compare product coverage and accuracy

**Sample components to test**:
- glibc (core system library)
- openssl (security library)
- kernel-headers (kernel component)
- golang (language runtime)

### 3. Advanced Search Features

#### Test 3.1: Strict vs. Fuzzy Matching
**newtopia-cli commands**:
```bash
newcli glibc                    # Fuzzy
newcli -s glibc                 # Strict
newcli --super-strict glibc     # Super strict
```

**trustshell behavior**:
```bash
trust-purl glibc               # Default behavior analysis needed
```

**Validation Criteria**:
- [ ] Understand trustshell's default matching behavior
- [ ] Determine if additional flags needed for strict matching
- [ ] Compare precision/recall between tools

#### Test 3.2: Build Type Filtering
**newtopia-cli commands**:
```bash
newcli -b rpm golang
newcli -b container golang  
newcli -b maven h2
```

**trustshell equivalents**:
```bash
# Build type filtering is built into PURL search
trust-purl "rpm golang"           # Finds pkg:rpm/.../golang
trust-purl "oci golang"           # Finds pkg:oci/.../golang  
trust-purl "maven h2"             # Finds pkg:maven/.../h2
```

**Validation Criteria**:
- [ ] PURL type filtering works for rpm, oci, maven, npm, pypi
- [ ] Results are properly filtered by ecosystem/build type
- [ ] Performance is comparable to newtopia-cli build type filtering

### 4. Performance and Scalability Tests

#### Test 4.1: Response Time Comparison
**Metrics to capture**:
- [ ] Search response time (< 30s target)
- [ ] Product mapping time (< 60s target)
- [ ] Memory usage during large queries
- [ ] Network request patterns

#### Test 4.2: Large Result Set Handling
**Test cases**:
```bash
# Large result sets
trust-purl openssl
trust-products pkg:rpm/redhat/openssl

# Compare with newtopia-cli equivalents
newcli openssl
```

### 5. Data Quality and Coverage Tests

#### Test 5.1: Component Coverage Analysis
**Objective**: Verify trustshell has comparable component coverage

**Process**:
1. Run common searches in both tools
2. Compare total result counts
3. Identify gaps in coverage
4. Document missing components/products

#### Test 5.2: Product Accuracy Validation
**Objective**: Ensure product mappings are accurate

**Process**:
1. Select 20 representative components
2. Manually verify product associations in both tools
3. Cross-reference with known product relationships
4. Document discrepancies

### 6. Integration and Workflow Tests

#### Test 6.1: OSIDB Integration Validation
**Current State**: Both tools support OSIDB integration via `--flaw` flag

**Test Commands**:
```bash
# newtopia-cli OSIDB integration
newcli -s golang --flaw CVE-2023-45288
newcli -s net/http -e golang --flaw CVE-2023-45288

# trustshell OSIDB integration  
trust-products pkg:golang/golang.org/x/net --flaw CVE-2023-45288
trust-products pkg:rpm/redhat/golang --flaw CVE-2023-45288 --replace
```

**Validation Criteria**:
- [ ] Both tools can update OSIDB flaw affects
- [ ] Replace mode works correctly (`--replace` flag)
- [ ] Affects entries are properly formatted
- [ ] Error handling for invalid CVEs/flaws

#### Test 6.2: Batch Processing Capabilities
**Test batch operations**:
```bash
# Test multiple searches
for component in golang nodejs python3; do
  trust-purl $component
  # Compare with newtopia-cli equivalent
done
```

### 7. Authentication and Security Tests

#### Test 7.1: Authentication Flow
**Test scenarios**:
- [ ] Initial authentication (browser flow)
- [ ] Token refresh handling
- [ ] Headless mode operation
- [ ] Token expiration scenarios

#### Test 7.2: Error Handling
**Test error conditions**:
- [ ] Network connectivity issues
- [ ] Authentication failures
- [ ] Invalid search terms
- [ ] API rate limiting

## Test Execution Framework

### Automated Test Script Structure
```bash
#!/bin/bash
# migration_test.sh

# Environment setup
source setup_environment.sh

# Test categories
run_basic_discovery_tests()
run_product_mapping_tests()
run_advanced_search_tests()
run_performance_tests()
run_data_quality_tests()
run_integration_tests()

# Report generation
generate_migration_report()
```

### Test Data Collection
For each test, collect:
- [ ] Command executed
- [ ] Response time
- [ ] Result count
- [ ] Sample results (first 10 items)
- [ ] Error messages (if any)
- [ ] Memory usage

### Data Coverage Validation
**Critical data coverage areas to validate**:
- [ ] Component discovery completeness across ecosystems
- [ ] Product mapping accuracy and completeness  
- [ ] Data freshness compared to newtopia-cli sources
- [ ] Historical version availability
- [ ] CPE relationship accuracy

**Reference**: [Manifest-Box Data Coverage Comparison](https://product-security.pages.redhat.com/manifest-box/) for detailed coverage analysis between newtopia-cli (Deptopia) and TRUSTIFY (Atlas).

### Risk Assessment
**High Risk Items**:
1. **Community Filtering**: No equivalent to `--no_community`
2. **Data Coverage**: Potential gaps in Trustify vs. Deptopia data
3. **Authentication Complexity**: OIDC setup required for headless environments
4. **Performance**: Network latency to Trustify vs. local Deptopia cache

**Mitigation Strategies**:
1. Implement community filtering logic or post-processing
2. Comprehensive data coverage analysis and gap documentation
3. Automated OIDC server deployment and management
4. Performance benchmarking and optimization

## Reporting

### Test Report Structure
1. **Executive Summary**
   - Migration readiness assessment
   - Key findings and recommendations
   - Risk analysis

2. **Detailed Test Results**
   - Test-by-test comparison
   - Performance metrics
   - Data quality analysis

3. **Gap Analysis**
   - Missing features
   - Workaround solutions
   - Development recommendations

4. **Migration Recommendations**
   - Go/no-go decision
   - Required improvements
   - Migration timeline

### Deliverables
- [ ] Automated test suite
- [ ] Migration test report
- [ ] Feature gap analysis
- [ ] Migration guide (if successful)
- [ ] Training materials for analysts

## Timeline
- **Week 1**: Environment setup and basic functionality tests
- **Week 2**: Advanced features and performance testing  
- **Week 3**: Data quality and integration testing
- **Week 4**: Report generation and recommendations
