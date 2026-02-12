# Test plan for Atlas and TrustShell

## Overview of difference from NewCLI

### Backing data

NewCLI is backed by data from Deptopia. TrustShell is backed by data from Atlas, which is an internal instance of Trusted Profile Analyzer with Software Bill of Materials from Konflux and SBOMer.
SBOMer is a service which generates SBOMs for Errata Tool Advisories.

**Known data issues:**

- No RHEL content prior to RHEL-9
- No community content
- No pre-release content
- No managed services

#### No RHEL content prior to RHEL-9

Because SBOMer's only source of data is Errata Tool and not all RHEL-8 releases used Errata Tool, we don't have good coverage for RHEL-8 and earlier. See https://redhat-internal.slack.com/archives/C03CFJBGRTK/p1728502286971059

#### No community content

There is no Epel, or Fedora content in Atlas.

#### No pre-release content

For most products in NewCLI we track upcoming releases, for example at the time of writing rhel-10.2 does not have any Errata yet, so it is not included in Atlas, and therefore TrustShell.

#### No managed services

Managed Services do not have advisories so are not included in Atlas.

## Key differences to NewCLI

Search is split from a single command into 2 distinct steps:

1. Search for a Package URL
2. Search for products with that Package URL
3. An editor can be used to adjust affects before adding to OSIDB Flaws.

### Search for a Package URL

This step was added because every component in Atlas is defined with a Package URL. A Package URL (PURL) encapsulates the component type, amongst other things. For example where we previously searched using a term such as `crypto/x509` we now need to translate that to a Package URL before we can find out which products ship that component.

```bash
$ newcli -vvv crypto/x509
```

Now we have to use the `trust-purl` command to translate that to a PURL e.g.:

```bash
$ trust-purl crypto/x509
...
pkg:golang/crypto/x509
pkg:golang/github.com/zmap/zcrypto/x509
```

This allows us to increase the accuracy of the search to include only those products which ship the crypto/x509 package in the golang ecosystem, excluding any in the github.com/zmap namespace for example.

There is a feature in Aegis AI which can translate a NewCLI style component name to a PURL. At the time of writing the Aegis AI is returning an error (https://github.com/RedHatProductSecurity/aegis-ai/issues/476), but this is what a request looks like:

```bash
$ curl --negotiate -u : 'https://aegis.prodsec.redhat.com/api/v1/analysis/component?feature=component-intelligence&component_name=crypto/x509&detail=false' | jq .component_purl
pkg:golang/crypto/x509
```

### Known issues with component-intelligence / TrustShell integration

- For many rpms component-intelligence returns a generic PURL e.g.:

  ```bash
  $ curl --negotiate -u : 'https://aegis.prodsec.redhat.com/api/v1/analysis/component?feature=component-intelligence&component_name=libsoup&detail=false' | jq .component_purl
  pkg:generic/libsoup
  ```

  Search for products with that Package URL returns no results. This is tracked as https://issues.redhat.com/browse/PSDEVOPS-4346. The workaround for now is to use an rpm PURL instead, e.g.:

  ```bash
  $ trust-purl libsoup
  ...
  pkg:deb/ubuntu/libsoup2.4-1
  pkg:generic/libsoup
  pkg:generic/pkgs.devel.redhat.com/git/rpms/libsoup
  pkg:rpm/libsoup3
  pkg:rpm/redhat/libsoup                                 <------ This one
  pkg:rpm/redhat/libsoup-debuginfo
  ...
  ```

### Search for products with that Package URL

Once you have established the PURL, or PURLs you want to search for use the `trust-products` command:

```bash
$ uv run trust-products pkg:golang/crypto/x509
```

```
...
pkg:golang/crypto/x509
└── pkg:oci/platform-operator-bundle?repository_url=registry.redhat.io/ansible-automation-platform/platform-operator-bundle&tag=2.4-1768592150.1
    └── ansible_automation_platform-2.4
        └── ansible_automation_platform-2
pkg:golang/crypto/x509
└── pkg:oci/lvms-operator-bundle?repository_url=registry.redhat.io/lvms4/lvms-operator-bundle&tag=v4.19.1-1755197832
    └── lvms-operator-4.19
        └── lvms-operator-4
...
```

There is a bug with the `--flaw` option described in https://issues.redhat.com/browse/PSDEVOPS-4563


## Example Tests

Use these examples as a template to test your own packages with TrustShell.

### NewCLI search

```bash
$ newcli -e pypi pypdf -vv
ai-inference-server-3.2	pkg:oci/docling-cuda-rhel9?repository_url=registry.redhat.io/rhai/docling-cuda-rhel9	(pypdfium2-4.30.0, pypi)
...
ols-1	pkg:oci/lightspeed-ocp-rag-rhel9?repository_url=registry.redhat.io/openshift-lightspeed/lightspeed-ocp-rag-rhel9	(pypdf-5.9.0, pypi)
ols-1	pkg:oci/lightspeed-rag-tool-rhel9?repository_url=registry.redhat.io/openshift-lightspeed-tech-preview/lightspeed-rag-tool-rhel9	(pypdf-6.0.0, pypi)
ols-1	pkg:oci/lightspeed-service-api-rhel9?repository_url=registry.redhat.io/openshift-lightspeed/lightspeed-service-api-rhel9	(pypdf-6.4.0, pypi)
quay-3.9	pkg:oci/quay-rhel8?repository_url=registry.redhat.io/quay/quay-rhel8	(pypdf3-1.0.6, pypi)
quay-3.10	pkg:oci/quay-rhel8?repository_url=registry.redhat.io/quay/quay-rhel8	(pypdf3-1.0.6, pypi)
quay-3.13	pkg:oci/quay-rhel8?repository_url=registry.redhat.io/quay/quay-rhel8	(pypdf3-1.0.6, pypi)
quay-3.14	pkg:oci/quay-rhel8@v3.14.5-14?repository_url=registry.redhat.io/quay/quay-rhel8	(pypdf3@1.0.6, pypi)
quay-3.15	pkg:oci/quay-rhel8@v3.15.2-10?repository_url=registry.redhat.io/quay/quay-rhel8	(pypdf3@1.0.6, pypi)
quay-3.16	pkg:oci/quay-rhel9?repository_url=registry.redhat.io/quay/quay-rhel9	(pypdf3-1.0.6, pypi)
quay-io-3	pkg:github/quay/quay-service-tool@1767349997	(pypdf3-1.0.6, pypi)
quay-io-3	pkg:github/quay/quay-service-tool@1767349997	(pypdf3-1.0.6, pypi)	(and 1 more deps)
quay-io-3	pkg:github/quay/quay@1767349996	(pypdf2-1.26.0, pypi)
quay-io-3	pkg:github/quay/quay@1767349996	(pypdf2-1.26.0, pypi)	(and 1 more deps)
quay-io-3	pkg:oci/quay-py3@1767349997?repository_url=quay.io/app-sre/quay-py3	(pypdf3-1.0.6, pypi)
quay-io-3	pkg:oci/quay-service-tool@1767349997?repository_url=quay.io/app-sre/quay-service-tool	(pypdf3-1.0.6, pypi)
quay-io-3	pkg:oci/quay-service-tool@1767349997?repository_url=quay.io/app-sre/quay-service-tool	(pypdf3-1.0.6, pypi)	(and 1 more deps)
quay-io-3	pkg:oci/quay@1767349996?repository_url=quay.io/app-sre/quay	(pypdf2-1.26.0, pypi)
quay-io-3	pkg:oci/quay@1767349996?repository_url=quay.io/app-sre/quay	(pypdf2-1.26.0, pypi)	(and 1 more deps)
rhel-ai-3.0	pkg:oci/bootc-cuda-rhel9?repository_url=registry.redhat.io/rhelai3/bootc-cuda-rhel9	(pypdf-4.2.0, pypi)
rhel-ai-3.0	pkg:oci/disk-image-cuda-rhel9?repository_url=registry.redhat.io/rhelai3/disk-image-cuda-rhel9	(pypdf-4.2.0, pypi)
rhoai-2.25	pkg:oci/odh-llama-stack-core-rhel9?repository_url=registry.redhat.io/rhoai/odh-llama-stack-core-rhel9	(pypdf-6.0.0, pypi)
rhoai-3.0	pkg:oci/odh-llama-stack-core-rhel9?repository_url=registry.redhat.io/rhoai/odh-llama-stack-core-rhel9	(pypdf-6.1.3, pypi)
services-ansible-lightspeed-chatbot	pkg:github/ansible/ansible-chatbot-service@1767349999	(pypdf-6.1.3, pypi)
```

### TrustShell search

```bash
$ uv run trust-products pkg:pypi/pypdf
Retrieved 1 items out of 1 total for pkg:pypi/pypdf
[12:59:45] INFO     [12:59:45] trustshell.rhel_releases INFO Found 3 files matching pattern '*-releases.yml': ['rhel10-releases.yml', 'rhel8-releases.yml', 'rhel9-releases.yml']                                                                                      rhel_releases.py:229
[12:59:46] INFO     [12:59:46] trustshell.rhel_releases INFO RHEL release data not modified, using cached version                                                                                                                                                      rhel_releases.py:163
           INFO     [12:59:46] trustshell.rhel_releases INFO Loaded 91 RHEL release nodes                                                                                                                                                                              rhel_releases.py:445
           INFO     [12:59:46] trustshell.product_definitions INFO Loaded RHEL release data from GitLab (branch: main)                                                                                                                                           product_definitions.py:254
pkg:pypi/pypdf
└── pkg:oci/lightspeed-ocp-rag-rhel9?repository_url=registry.redhat.io/openshift-lightspeed/lightspeed-ocp-rag-rhel9&tag=1.0.9-1770087050
    └── ols-1
        └── ols-1
```

**Notes:** 
1. We have a match on only one container from ols-1
2. The quay product stream are missing from this TrustShell example (testing setup)
3. The rhel-ai and rhoai results are missing from this TrustShell examples  (testing setup)
4. It's expected we don't get any Community results (fedora-43)
5. It's expected we don't get any managed services results (quay-io-3, services-ansible-lightspeed-chatbot)



