# TrustShell Migration Documentation

This directory contains all the tools and documentation needed to validate that trustshell can replace newtopia-cli for security analyst workflows.

## Files Overview

### 📋 Documentation
- **`MIGRATION_SETUP.md`** - Quick start guide for running migration tests
- **`MIGRATION_TEST_PLAN.md`** - Comprehensive test plan with validation criteria
- **`README.md`** - This file, explaining the directory contents

### 🧪 Test Scripts
- **`migration_test.sh`** - Main automated test suite with customizable options
- **`quick_test.sh`** - Simple functionality test with timeout handling
- **`troubleshoot.sh`** - Diagnostic script for connection and authentication issues
- **`test_error_reporting.sh`** - Demo of enhanced error reporting features
- **`demo_custom_packages.sh`** - Examples of custom package testing

### 📁 Generated Files
- **`test_results/`** - Directory created by migration_test.sh containing JSON test reports

## Quick Start

1. **Set up environment**:
   ```bash
   export TRUSTIFY_URL="https://atlas.release.devshift.net"
   export AUTH_ENDPOINT="https://auth.redhat.com/auth/realms/EmployeeIDP/protocol/openid-connect"
   export LOCAL_AUTH_SERVER_PORT=8650
   ```

2. **Run basic test**:
   ```bash
   cd /home/jshepher/projects/trustshell/docs/migration
   ./migration_test.sh --help
   ```

3. **Test specific packages**:
   ```bash
   # Test jenkins package only
   ./migration_test.sh --components-only --quick jenkins
   
   # Test multiple packages
   ./migration_test.sh jenkins httpd nginx
   ```

## Test Options

- **`--components-only`** - Test only package search, skip product mapping and OSIDB
- **`--quick`** - Use shorter timeouts for faster execution  
- **`--verbose`** - Show additional debug information
- **`--help`** - Display full usage information

## Common Use Cases

### Security Analyst Testing
```bash
# Test packages related to a specific CVE
./migration_test.sh --quick jenkins httpd nginx postgresql
```

### CI/CD Integration
```bash
# Quick validation in automated pipeline
./migration_test.sh --components-only --quick $PACKAGE_NAME
```

### Comprehensive Migration Validation
```bash
# Full test suite with defaults
./migration_test.sh
```

### Troubleshooting
```bash
# Diagnose connection issues
./troubleshoot.sh

# Test basic functionality
./quick_test.sh
```

## Data Coverage Reference

For detailed data coverage comparison between newtopia-cli and TRUSTIFY:
📊 https://product-security.pages.redhat.com/manifest-box/

## Support

If you encounter issues:
1. Run `./troubleshoot.sh` for diagnostic information
2. Check environment variables are set correctly
3. Ensure OIDC server is running (see MIGRATION_SETUP.md)
4. Try Atlas Stage if Production is slow
