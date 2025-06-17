# TrustShell

## Description
Command Line Tool to work with [Trustify](https://github.com/trustification/trustify/).

## Installation

Directly from GitHub:

```bash
pip install git+https://github.com/RedHatProductSecurity/trustshell.git#egg=trustshell
```

## Configuration

Ensure the following environment variables are set:

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

Product Mapping:
```bash
export PRODDEFS_URL="https://prodsec.pages.example.com/product-definitions/products.json"
export SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt
```

### Running in a container

The authentication flows tries to spawn a browser in order to authentication to Single-Sign On (SSO). If running in a 'headless' environment like a container image that won't work. When running in a container it's necessary to run the container image defined in [this Containerfile](src/trustshell/oidc/Containerfile).

One can build and run the container as follows:
```bash
podman build -t oidc-pkce-server .
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

The way this mapping works is to match against a ps_update_steam if such a map exists. If not, we try to match 
against ps_modules.
