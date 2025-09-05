# TrustShell Migration Setup Guide

## Quick Start

### 1. Environment Setup
```bash
# Set required environment variables (choose Atlas Production or Stage)

# Atlas Production
export TRUSTIFY_URL="https://atlas.release.devshift.net"
export AUTH_ENDPOINT="https://auth.redhat.com/auth/realms/EmployeeIDP/protocol/openid-connect"

# Product Mapping (required)
export PRODDEFS_URL="https://prodsec.pages.example.com/product-definitions/products.json"
export RHEL_RELEASE_GRAPH_URL="https://gitlab.cee.example.com/api/v4/projects/prodsec%2Frhel-release-graph"
export SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt

# Headless mode (for containers/CI)
export LOCAL_AUTH_SERVER_PORT=8650
```

### 2. Install TrustShell
```bash
pip install git+https://github.com/RedHatProductSecurity/trustshell.git#egg=trustshell
```

### 3. Setup OIDC Server (for headless environments)
```bash
cd /home/jshepher/projects/trustshell
podman build -f src/trustshell/oidc/Containerfile -t oidc-pkce-server .
podman run -d -p 127.0.0.1:8650:8650 -e AUTH_ENDPOINT="$AUTH_ENDPOINT" oidc-pkce-server
```

### 4. Run Migration Tests
```bash
cd /home/jshepher/projects/trustshell

# Test default packages (golang, nodejs, string-width, kernel-headers)
./migration_test.sh

# Test specific packages
./migration_test.sh jenkins httpd nginx

# Quick test with shorter timeouts
./migration_test.sh --quick jenkins

# Test only package search (skip product mapping and OSIDB tests)
./migration_test.sh --components-only jenkins

# Show help for all options
./migration_test.sh --help
```

## Test Commands from GitLab CI

The following commands from newtopia-cli's `.gitlab-ci.yml` should be tested:

```bash
# Original newtopia-cli commands (with -s for exact matching)
pipenv run newcli -s golang
pipenv run newcli -s nodejs  
pipenv run newcli -s -vvv string-width
pipenv run newcli -s kernel-headers

# TrustShell equivalents (two-step process for exact matching)
# Step 1: Find PURLs
trust-purl golang
trust-purl nodejs
trust-purl string-width
trust-purl kernel-headers

# Step 2: Get exact product mappings for specific PURLs
trust-products pkg:rpm/redhat/golang      # Exact match for golang RPM
trust-products pkg:rpm/redhat/nodejs      # Exact match for nodejs RPM  
trust-products pkg:npm/string-width       # Exact match for string-width npm
trust-products pkg:rpm/redhat/kernel-headers  # Exact match for kernel-headers RPM
```

## Key Differences to Validate

| Feature | newtopia-cli | trustshell | Status |
|---------|-------------|------------|---------|
| Package Search | `newcli <term>` | `trust-purl <term>` | ✅ Available |
| Product Mapping | Built into search | `trust-products <purl>` | ✅ Available |
| Ecosystem Filter | `-e <ecosystem>` | Built into PURL | ✅ Available |
| Strict Search | `-s` flag | Default behavior | ✅ Available |
| Verbose Output | `-v/-vv/-vvv` | Default detailed | ✅ Available |
| Latest Streams | Default (--latest_streams) | Default behavior | ✅ Available |
| OSIDB Integration | `--flaw <CVE>` | `trust-products --flaw <CVE>` | ✅ Available |
| Community Filter | `--no_community` | **Missing** | ❌ Gap |
| Build Type Filter | `-b rpm/container` | Built into PURL search | ✅ Available |

## Critical Gaps Identified

### 1. Community Filtering Missing
- **newtopia-cli**: `--no_community` excludes community products
- **trustshell**: No equivalent flag
- **Impact**: Results may include unwanted community components
- **Workaround**: Post-process results to filter community products

### 2. Workflow Differences

#### Exact Component Matching:
- **newtopia-cli**: Single command with `-s` flag: `newcli -s golang`
- **trustshell**: Two-step process:
  1. `trust-purl golang` (find available PURLs)  
  2. `trust-products pkg:rpm/redhat/golang` (exact product mapping)
- **Impact**: Requires identifying specific PURL before product mapping

#### OSIDB Integration:
- **newtopia-cli**: Single command: `newcli -s golang --flaw CVE-2023-45288`
- **trustshell**: Two-step process:
  1. `trust-purl golang` (find PURLs)
  2. `trust-products pkg:rpm/redhat/golang --flaw CVE-2023-45288`
- **Impact**: Slightly more complex workflow for vulnerability management

## Data Coverage Analysis

### Comprehensive Data Coverage Comparison
For detailed information about data coverage differences between newtopia-cli and TRUSTIFY (Atlas), refer to the comprehensive comparison available at:

**📊 [Manifest-Box Data Coverage Comparison](https://product-security.pages.redhat.com/manifest-box/)**

This resource provides:
- **Side-by-side data coverage analysis** between newtopia-cli (Deptopia) and TRUSTIFY
- **Component availability metrics** across different ecosystems
- **Product mapping completeness** comparisons
- **Data freshness and update frequency** information
- **Known gaps and limitations** in each system


## Support and Troubleshooting

### Debug Commands
```bash
# Check authentication status
trust-api analysis/statusu

# Test with debug logging
trust-purl --debug <component>

# If commands timeout, use faster endpoint
trust-purl --use-base-purl <component>
```

### Performance Issues and Solutions

If you encounter timeouts with `trust-purl` commands:

1. **Use the faster endpoint**: Add `--use-base-purl` flag
   ```bash
   trust-purl --use-base-purl golang    # Faster but less accurate
   ```

2. **Check network connectivity**: Ensure stable connection to Atlas
   ```bash
   curl -s https://atlas.release.devshift.net
   ```

3. **Try Atlas Stage**: Stage environment may be less loaded
   ```bash
   export TRUSTIFY_URL="https://atlas.release.stage.devshift.net"
   export AUTH_ENDPOINT="https://auth.stage.redhat.com/auth/realms/EmployeeIDP/protocol/openid-connect"
   ```

The migration test script automatically falls back to `--use-base-purl` if standard commands timeout.
