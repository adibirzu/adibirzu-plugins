---
name: secure-coding-cicd
description: Audits and hardens a repository's coding and CI/CD baseline. Covers GitHub Actions pinned to full commit SHAs, OIDC instead of static cloud keys, least-privilege token permissions, no credential persistence, no pull_request_target, CycloneDX 1.7 and SPDX 2.3 SBOMs with attestation, gitleaks, SAST, dependency review, grouped Dependabot updates, tests that cannot hit production by default, a skill scan gate and a living README architecture section. Use when adding or reviewing workflows, preparing a repository for release, answering a supply-chain or security review, or when the user mentions CI hardening, SBOM, pinned actions or secret scanning.
license: MIT
compatibility: The bundled scripts need Python 3.9 or newer and no third-party packages. Secret scanning needs gitleaks 8 or newer.
metadata:
  version: "1.0.0"
  author: adibirzu
---

# Secure coding and CI/CD

A baseline you can check by machine, plus two scripts that do the checking.
Start with the linter. It tells you where the repository stands in seconds.

## Quick start

Paths below are relative to this plugin's root, two levels above this file.

```bash
# 1. Find the gaps. Exit 0 is clean, 1 means findings, 2 is a usage error.
python3 scripts/check_workflows.py <repo-root>

# 2. Same findings as JSON for a script or a review comment.
python3 scripts/check_workflows.py <repo-root> --format json

# 3. Inventory a plugin marketplace as CycloneDX 1.7 and SPDX 2.3.
python3 scripts/generate_sbom.py <repo-root> --spec-version 1.7 --output-dir sbom
```

Both scripts use only the Python standard library, so they run in a CI job
before any dependency is installed.

## How to work

1. Run the linter and read every finding. Do not start editing from memory.
2. Fix findings in the order the checklist gives them. The first five close
   the routes an outside contributor can use to reach your secrets.
3. Add each control with a check that fails without it. A control nobody
   verifies decays.
4. Rerun the linter until it reports `0 findings`, then wire it into CI so
   the baseline cannot regress.
5. Update the README architecture section in the same change.

## The baseline

The full reasoning, examples and verification command for each control are
in [references/cicd-security-checklist.md](references/cicd-security-checklist.md).

| # | Control | Linter rule |
|---|---|---|
| 1 | Every action pinned to a 40-character commit SHA | `unpinned-action` |
| 2 | Top-level `permissions: {}`, scopes granted per job | `missing-top-level-permissions`, `broad-permissions` |
| 3 | `persist-credentials: false` on every checkout | `checkout-persist-credentials` |
| 4 | No `pull_request_target` | `pull-request-target` |
| 5 | Untrusted input reaches `run` only through `env` | `script-injection` |
| 6 | OIDC federation, no static cloud keys | `static-cloud-credential` |
| 7 | Secret scan on staged changes and on full history | checklist |
| 8 | SAST with ruff, bandit and semgrep | checklist |
| 9 | Dependency review and grouped Dependabot updates | checklist |
| 10 | Hash-pinned tool installs | checklist |
| 11 | Tests cannot reach production by default | `prod-url-default` |
| 12 | SBOM in CycloneDX 1.7 and SPDX 2.3, validated and attested | [references/sbom-and-supply-chain.md](references/sbom-and-supply-chain.md) |
| 13 | Skill scan gate before a skill or plugin is installed | `skill-frontmatter`, checklist |
| 14 | Living README architecture section | checklist |

## What the linter does not see

The linter reads workflow YAML line by line. It understands the block style
GitHub documents. Say so when you report results, and check these by hand:

- Steps written in one-line flow style.
- Actions called from inside a composite action or a reusable workflow in
  another repository.
- Whether a pinned SHA belongs to the repository named in `uses`. A SHA from
  a fork resolves too. Confirm it against the upstream release.
- Repository settings: branch protection, required reviews, secret scanning
  and push protection, and the default token permission.

For a deeper static pass on workflows, run a dedicated analyzer such as
zizmor next to this linter. The two overlap on purpose.

## Reporting

Report findings as `file:line: rule message`, grouped by rule, with the fix
for each. State what you ran, what it returned, and what you could not check.
Never say a repository is hardened on the strength of a clean linter run
alone. The settings in the list above need their own evidence.

## Provenance

Original work under the MIT license. Tool and product names belong to their
owners and are named only to say what the baseline interoperates with.
