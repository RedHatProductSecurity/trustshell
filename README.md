#TrustShell

## Description
Command Line Tool to work with [Trustify](https://github.com/trustification/trustify/).

## Installation

Directly from GitHub:

```commandline
$ pip install git+https://github.com/RedHatProductSecurity/trustshell.git#egg=trustshell
```

## Configuration

Ensure the following environment variables are set:

Atlas Production:
`export TRUSTIFY_URL="https://atlas.release.devshift.net"`
`export AUTH_ENDPOINT="https://auth.redhat.com/auth/realms/EmployeeIDP/protocol/openid-connect"`


Atlas Stage:

`export TRUSTIFY_URL="https://atlas.release.stage.devshift.net"`
`export AUTH_ENDPOINT="https://auth.stage.redhat.com/auth/realms/EmployeeIDP/protocol/openid-connect"`

Product Mapping:
`export PRODDEFS_URL="https://prodsec.pages.example.com/product-definitions/products.json"`
`export SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt`

## Usage

### Find matching PackageURLs in Trustify:
Each component in Atlas has a PackageURL (purl). This helps remove ambiguity around the type of component.
Before relating a component to a product, you first need to determine the purl of the component.
You can do using trustshell, eg:

```commandline
$ trust-purl qemu
Querying Trustify for packages matching qemu
Found these matching packages in Trustify, including the highest version found:
pkg:oci/quay-builder-qemu-rhcos-rhel8@v3.12.8-1
pkg:rpm/redhat/qemu-kvm@6.2.0-53.module+el8.10.0+22375+ea5e8167.2
```

### Find matching products for purl:
Once you have a PackageURL, you can then relate that to any products using the `trust-products` command. For example:

```commandline
$ trust-products pkg:oci/quay-builder-qemu-rhcos-rhel8
Querying Trustify for products matching pkg:oci/quay-builder-qemu-rhcos-rhel8
Found these products in Trustify, including the latest shipped artifact
pkg:oci/quay-builder-qemu-rhcos-rhel8
└── pkg:oci/quay-builder-qemu-rhcos-rhel8?tag=v3.12.8-1
    └── cpe:/a:redhat:quay:3:*:el8:*
```

### Prime the Trusify graph:
If components are found with the trust-purl command, but they are not being linked to products with
trust-products, it could be because the Trustify graph cache is not yet primed. In order to prime the graph
cache run the `trust-prime` command as follows.

```commandline
# trust-prime
Status before prime:
graph count: 0
sbom_count: 673
Priming graph ...
```

It can also be run with `--check` to see the graph and sbom counts without actually priming the garph cache.

### CPE to product mapping

It's possible to map CPEs to products using product metadata as demonstrated in the docs/product-definitions.json file. This allows integration with a bug tracking system like Jira. 

The way this mapping works is to match against a ps_update_steam if such a map exists. If not, we try to match against ps_modules.