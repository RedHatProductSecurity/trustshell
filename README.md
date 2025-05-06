#TrustShell

## Description
Command Line Tool to work with [Trustify](https://github.com/trustification/trustify/).

## Installation

Directly from GitHub:

```commandline
$ pip install git+https://github.com/RedHatProductSecurity/trustshell.git#egg=trustshell
```

## Linting before committing

To ensure code quality and consistency, run the following linting commands before committing your changes:

```commandline
tox -e flake8,black,isort,mypy
```


## Usage

### Find matching PackageURLs in Trustify:

```commandline
$ trust-purl qemu
Querying Trustify for packages matching qemu
Found these matching packages in Trustify, including the highest version found:
pkg:oci/quay-builder-qemu-rhcos-rhel8@v3.12.8-1
pkg:rpm/redhat/qemu-kvm@6.2.0-53.module+el8.10.0+22375+ea5e8167.2
```

### Find matching products for purl:

```commandline
$ trust-products pkg:oci/quay-builder-qemu-rhcos-rhel8
Querying Trustify for products matching pkg:oci/quay-builder-qemu-rhcos-rhel8
Found these products in Trustify, including the latest shipped artifact
pkg:oci/quay-builder-qemu-rhcos-rhel8
└── pkg:oci/quay-builder-qemu-rhcos-rhel8?tag=v3.12.8-1
    └── cpe:/a:redhat:quay:3:*:el8:*
```
