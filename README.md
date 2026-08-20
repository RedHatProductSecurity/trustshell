# TrustShell

## Description
Command Line Tool to work with [Trustify](https://github.com/trustification/trustify/).

## Installation

Directly from GitHub:

```bash
pip install git+https://github.com/RedHatProductSecurity/trustshell.git#egg=trustshell
```

## Configuration

### Required Environment Variables

Set `TRUSTIFY_URL` to point to your Trustify instance:

```bash
export TRUSTIFY_URL="https://trustify.example.com"
```

### Authentication (Optional)

If your Trustify instance requires authentication, also set `AUTH_ENDPOINT`:

Atlas Production:
```bash
export TRUSTIFY_URL="https://atlas.release.devshift.net"
export AUTH_ENDPOINT="https://auth.redhat.com/auth/realms/EmployeeIDP/protocol/openid-connect"
```

Atlas Stage:
```bash
export TRUSTIFY_URL="https://atlas.release.stage.devshift.net"
export AUTH_ENDPOINT="https://auth.stage.redhat.com/auth/realms/EmployeeIDP/protocol/openid-connect"
```

TPA / Amazon Cognito (e.g. Red Hat Trusted Profile Analyzer):

Use your Cognito domain, CLI client ID, and client secret. The **client credentials** flow requires no browser or callback URL (unlike the authorization code flow):

```bash
export TRUSTIFY_URL="https://server-tpa221on420.apps.ps420.tpa.rhocf-dev.net"
export AUTH_ENDPOINT="https://tpa221on420.auth.eu-west-1.amazoncognito.com/oauth2"
export OIDC_CLIENT_ID="1g3hp92dqfrjph3om08g2is0bo"
export OIDC_CLIENT_SECRET="your-client-secret"
```

The Cognito app client must have the **client credentials** grant enabled (not authorization code). Run `trust-purl` or `trust-products`; authentication happens automatically via `client_id` and `client_secret`.

**Security:** Don't commit or share `OIDC_CLIENT_SECRET`. Use environment variables or a secrets manager.

If the app client uses the authorization code flow instead (e.g. browser login), add `export OIDC_AUTH_PATH="authorize"` (and have the admin add `http://localhost:8650/index.html` to Cognito's allowed callbacks).

For local or public Trustify instances without authentication, simply omit `AUTH_ENDPOINT`:

```bash
export TRUSTIFY_URL="http://localhost:8080"
# No AUTH_ENDPOINT needed - authentication will be skipped
```

Product Mapping:
```bash
export PRODDEFS_URL="https://prodsec.pages.example.com/product-definitions/products.json"
export RHEL_RELEASE_GRAPH_URL="https://gitlab.cee.example.com/api/v4/projects/prodsec%2Frhel-release-graph"
export SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt
```

Optional Configuration:
```bash
# Trustify API version (defaults to v3; set to v2 for legacy deployments)
export TRUSTIFY_API_VERSION=v3

# Set custom configuration directory (defaults to ~/.config/trustshell/)
export TRUSTSHELL_SCRATCH="/path/to/custom/config/dir"

# OIDC overrides for non-Keycloak providers (e.g. Amazon Cognito):
# OIDC_CLIENT_ID - app client ID
# OIDC_CLIENT_SECRET - enables client_credentials flow (no browser/callback) when set
# OIDC_AUTH_PATH - auth path for PKCE (Keycloak: "auth", Cognito: "authorize")
```

### Running in a container

**Note:** This section only applies if you need authentication (i.e., if you set `AUTH_ENDPOINT`).

The authentication flows tries to spawn a browser in order to authentication to Single-Sign On (SSO). If running in a 'headless' environment like a container image that won't work. When running in a container it's necessary to run the container image defined in [this Containerfile](src/trustshell/oidc/Containerfile).

One can build and run the container as follows:
```bash
podman build -f src/trustshell/oidc/Containerfile -t oidc-pkce-server .
podman run -d -p 127.0.0.1:8650:8650 -e AUTH_ENDPOINT="https://auth.redhat.com/auth/realms/EmployeeIDP/protocol/openid-connect" oidc-pkce-server
```

It's a security risk to bind the oidc-pkce-server on an external network interface. Allowing access to the oidc-pkce-server could allow an attacker to obtain an access_token and grant them read access to the Trusify server.

When first trying to authenticate in a headless environment you'll be presented with a link to authenticate to SSO which you will need to open in a web browser, eg:

```bash
Open a webbrowser and go to:
https://auth.redhat.com/auth/realms/EmployeeIDP/protocol/openid-connect/auth?response_type=code&client_id=atlas-frontend&scope=openid&redirect_uri=http%3A%2F%2Flocalhost%3A8650%2Findex.html&code_challenge=<snip>&code_challenge_method=S256&state=<snip>
```

Subsequent requests to Trustify will use an access_token stored or refreshed by the oidc-pkce-server. Restaring the oidc-pkce-server process will required re-authentication in the browser on restart.

### Running in 'headless' mode

**Note:** This section only applies if you need authentication (i.e., if you set `AUTH_ENDPOINT`).

If you want to run in 'headless' mode, and have the `oidc-pkce-server` maintain a persistent authentication session. You can run the `oidc-pkce-server` container as mentioned above and set the following environment variable. You will still have to authenticate in the browser each time the `oidc-pkce-server` container is restarted.

```bash
export LOCAL_AUTH_SERVER_PORT=8650
```

## Usage

### Find matching PackageURLs in Trustify:
Each component in Atlas has a PackageURL (purl). This helps remove ambiguity around the type of component.
Before relating a component to a product, you first need to determine the purl of the component:

```console
$ trust-purl qemu
Querying Trustify for packages matching qemu
Found these matching packages in Trustify, including the highest version found:
pkg:oci/quay-builder-qemu-rhcos-rhel8@v3.12.8-1
pkg:rpm/redhat/qemu-kvm@6.2.0-53.module+el8.10.0+22375+ea5e8167.2
```

### Find matching products for purl:
Once you have a PackageURL, you can then relate it to any products using the `trust-products` command. For example:

```console
$ trust-products pkg:oci/quay-builder-qemu-rhcos-rhel8
Querying Trustify for products matching pkg:oci/quay-builder-qemu-rhcos-rhel8
Found these products in Trustify, including the latest shipped artifact
pkg:oci/quay-builder-qemu-rhcos-rhel8
└── pkg:oci/quay-builder-qemu-rhcos-rhel8?tag=v3.12.8-1
    └── cpe:/a:redhat:quay:3:*:el8:*
```

Use the `--latest` flag to include non-latest results. The default is to filter to the latest root components in a CPE.
Latest is calculated by comparing the published date of the product SBOM.

Sometimes you might find a purl which is returned by `trust-purl` but doesn't have results when using `trust-products`. In that case, it usually mean the purl was not in the set of latest SBOMs. However you can check that by doing the `trust-products` query again with `-l` flag to search the entire set of SBOMs, not filtered by latest eg:

```console
$ trust-products -l pkg:oci/quay-builder-qemu-rhcos-rhel8
```

Other times there might be no results because the purl is not linked to any product level SBOMs. You can check which components the purl is found in by searching in debug mode, eg:

```console
$ trust-products -d pkg:oci/quay-builder-qemu-rhcos-rhel8
```

#### JSON output

Use `--output json` (or `-o json`) for machine-readable output. The JSON includes `searched_purl`, `results` (with cpe, ps_update_stream, matched_component, shipped_component, sbom_ids, ps_module), and `affects`:

```console
$ trust-products -o json pkg:oci/quay-builder-qemu-rhcos-rhel8
```

#### SBOM IDs for TPA lookup

Use `--show-sbom-ids` to include SBOM IDs in the text output. This helps with lookup in Trustify Product Analytics (TPA):

```console
$ trust-products --show-sbom-ids pkg:oci/quay-builder-qemu-rhcos-rhel8
```

JSON output always includes `sbom_ids` in each result.

#### Including RPM packages in containers

By default, `trust-products` filters out RPM packages that are found within container images to avoid false positives. However, many modern products (like MTV, OpenShift components) have RPM packages bundled in OCI containers. To include these results, use the `--include-rpm-containers` flag:

```console
$ trust-products --include-rpm-containers pkg:rpm/redhat/harfbuzz
pkg:rpm/redhat/harfbuzz
└── pkg:oci/mtv-must-gather-rhel8
    └── cpe:/a:redhat:migration_toolkit_virtualization:2.10:*:el8:*
```

Or use the short form `-i`:

```console
$ trust-products -i pkg:rpm/redhat/harfbuzz
```

### Prime the Trustify graph:
If components are found with the trust-purl command, but they are not being linked to products with
trust-products, it could be because the Trustify graph cache is not yet primed. To prime the graph
cache run the `trust-prime` command as follows.

```console
$ trust-prime
Status before prime:
graph count: 0
sbom_count: 673
Priming graph ...
```

It can also be run with `--check` to see the graph and sbom counts without actually priming the graph cache.

### CPE to product mapping

It's possible to map CPEs to products using product metadata as demonstrated in the `docs/product-definitions.json` 
file. This allows integration with a bug tracking system like Jira.

The way this mapping works is to match against a ps_update_stream if such a map exists. If not, we try to match 
against ps_modules.

#### RHEL Release Graph Mapping

For RHEL product streams (RHEL 9 and earlier), TrustShell uses an enhanced mapping mechanism that leverages the 
RHEL release graph data from the `rhel-release-graph` repository. This feature addresses a specific issue with 
how packages are distributed in RHEL minor releases.

**Why this feature is needed:**

SBOM data returned by Trustify already contain CPEs with minor versions (e.g., `cpe:/a:redhat:enterprise_linux:9.6::appstream`). 
However, for RHEL 9 and earlier versions, packages are not re-released when a new minor version is created. Instead, 
all packages are pushed into a DNF repository. This means that if a package was only released at the beginning of a RHEL stream (e.g., when RHEL 9 was at version 9.0), and subsequent releases occurred for 9.1, 9.2, etc., that package would not be visible to those later minor release streams when using direct CPE matching.

The RHEL release graph mapping solves this by:
1. Using the release hierarchy from the `rhel-release-graph` repository to understand parent-child relationships 
   between RHEL releases
2. When a CPE matches a parent release node, automatically associating it with all descendant leaf nodes whose 
   CPEs are in active product streams
3. This ensures that packages released in earlier minor versions are correctly associated with later minor version 
   streams

**EUS (Extended Update Support) Streams:**

Another important justification for the RHEL release graph mapping is the handling of EUS streams. When an EUS stream 
is created, it includes only packages that were previously released in the 'main' RHEL stream up to the EUS start date. 
Any packages that are updated or newly released in the 'main' RHEL stream after the EUS start date should **not** be 
included in the EUS stream.

The rhel-release-graph mapping, along with special handling and minor version CPEs, ensures that:
- EUS streams correctly inherit only packages from their parent release that existed before the EUS start date
- Packages released after the EUS start date in the main stream are properly excluded from EUS streams
- The release hierarchy accurately reflects the temporal relationships between main RHEL releases and their EUS variants

**RHEL 10 and later:**

This mapping feature is **not necessary** for RHEL 10 and later versions, as a separate CPE is created for each 
minor release. The direct CPE matching works correctly for these versions.

**Configuration:**

The RHEL release graph data is automatically loaded from the GitLab repository specified by the `RHEL_RELEASE_GRAPH_URL` 
environment variable (see the [Configuration](#configuration) section above). The system caches this data locally and 
only refreshes when the repository is updated.
