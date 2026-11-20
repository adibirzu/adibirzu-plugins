# SBOM and supply chain

How to produce a software bill of materials that a consumer can trust: two
formats, validated, reproducible, and attested on release.

## Contents

1. Which formats and why
2. What belongs in the inventory
3. Generating with the bundled script
4. Generating for application code
5. Validating
6. Attesting on release
7. Consuming an SBOM
8. Common mistakes

## 1. Which formats and why

Publish both. Consumers standardize on one or the other, and converting
between them loses detail.

| Format | Use it for | Notes |
|---|---|---|
| CycloneDX 1.7 | Security tooling, vulnerability matching, VEX | JSON, identified by `specVersion: "1.7"` |
| SPDX 2.3 | License compliance, procurement, regulators | JSON, identified by `spdxVersion: "SPDX-2.3"` |

SPDX 3 exists, but SPDX 2.3 is still what most scanners and platform exports
read. Emit 2.3 until your consumers ask for 3.

## 2. What belongs in the inventory

List everything a consumer pulls in or has to trust, not only package
manager dependencies.

- Runtime and build dependencies, with exact versions and package URLs.
- GitHub Actions and container images the pipeline runs, by commit SHA or
  digest. They execute with your token and are part of your supply chain.
- For a plugin marketplace: every plugin it lists, local or remote, with the
  repository it comes from.

Give each component a package URL (purl) where one exists. Vulnerability
databases match on purl, so a component without one is invisible to them.

Do not assert what you have not checked. If you did not verify a license,
record `NOASSERTION`, not a guess.

## 3. Generating with the bundled script

`scripts/generate_sbom.py` inventories a plugin marketplace repository. It
reads `.claude-plugin/marketplace.json` and `.github/workflows/`, and needs
only the Python standard library.

```bash
python3 scripts/generate_sbom.py <repo-root> --spec-version 1.7 --output-dir sbom
```

It writes `sbom/marketplace.cdx.json` and `sbom/marketplace.spdx.json`.

- Local plugins carry a `marketplace:tree-sha256` property: a digest over
  every file path and content in the plugin directory. It changes when any
  file changes.
- Remote plugins carry their repository URL and a `pkg:github/` purl.
- Pinned actions carry the commit SHA as their version.

Output is reproducible. Set `SOURCE_DATE_EPOCH` and the same tree gives
byte-identical files, so a consumer can regenerate and compare:

```bash
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  python3 scripts/generate_sbom.py . --spec-version 1.7 --output-dir sbom
```

## 4. Generating for application code

For a project with package manager dependencies, use the ecosystem's own
generator, which reads the resolved lock file:

```bash
# Python, from the installed environment
cyclonedx-py environment --spec-version 1.7 --output-format JSON \
  --output-file sbom/app.cdx.json

# Python, from a hash-pinned requirements file
cyclonedx-py requirements requirements.txt --spec-version 1.7 \
  --output-format JSON --output-file sbom/app.cdx.json
```

Generate from the lock file or the built artifact, never from a loose
manifest. A manifest says what you asked for. The lock file says what you
got.

## 5. Validating

A file that claims a format is not the same as a file that conforms to it.
Validate in CI with the official libraries, installed from a hash-pinned
lock file.

```python
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

error = JsonStrictValidator(SchemaVersion.V1_7).validate_str(text)
```

```bash
pyspdxtools --infile sbom/marketplace.spdx.json   # parses and validates SPDX 2.3
```

Fail the job on any validation error. Then upload the SBOMs as a build
artifact on every push, pull request and release so each commit has one.

## 6. Attesting on release

An SBOM anyone could have edited proves little. An attestation binds it to
the artifact it describes and to the workflow run that built it, signed with
a short-lived OIDC identity. No signing key is stored anywhere.

```yaml
jobs:
  release:
    permissions:
      contents: read
      id-token: write       # mint the OIDC token used to sign
      attestations: write   # store the attestation
    steps:
      - uses: actions/attest-sbom@<40-character commit SHA>
        with:
          subject-path: dist/<artifact>
          sbom-path: sbom/app.cdx.json
```

Attest only in the job that builds the release artifact, and grant the two
write scopes to that job alone. A consumer verifies with:

```bash
gh attestation verify <artifact> --repo <owner>/<repo>
```

Add build provenance the same way so the consumer can also check which
source commit and workflow produced the artifact.

## 7. Consuming an SBOM

- Verify the attestation before trusting the content.
- Feed the CycloneDX file to your vulnerability scanner and the SPDX file to
  your license review.
- Compare SBOMs between releases. A new component or a changed digest is
  the question to ask before you upgrade.

## 8. Common mistakes

| Mistake | Consequence |
|---|---|
| Generating from a manifest, not a lock file | Versions in the SBOM differ from what shipped |
| Leaving CI actions and images out | The part of the chain with your token is undocumented |
| Guessing licenses | A wrong assertion is a compliance liability |
| No validation step | Consumers' tools reject the file |
| A timestamp that changes every run | Nobody can reproduce or diff the SBOM |
| Attesting from a job with broad permissions | The signing identity is exposed to every step |
