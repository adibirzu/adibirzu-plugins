# Security policy

## Reporting a vulnerability

Report privately. Do not open a public issue or pull request for a security
problem.

Use GitHub's private reporting form:
<https://github.com/adibirzu/adibirzu-plugins/security/advisories/new>

Include the plugin or file affected, the version or commit, the steps to
reproduce, and what an attacker gains. You will get an acknowledgement within
seven days. Please allow a fix to ship before you publish details.

For a vulnerability in a remote plugin, report it to that plugin's own
repository. The catalog here only points at it.

## Supported versions

Only the latest commit on `main` and the plugin versions listed in
`.claude-plugin/marketplace.json` receive fixes.

## Scope

In scope:

- The marketplace manifest and everything under `plugins/`.
- The CI workflows, the linter and the SBOM generator.
- A catalog entry that points at a source it should not.

Out of scope:

- The content of remote plugin repositories.
- Findings that need a user to install a plugin from somewhere else.

## What installing a plugin means

A plugin can ship skills, commands, agents, hooks and scripts. They run with
the same access your coding agent has. Before you install any plugin, from
this marketplace or another:

1. Read its manifest, hooks and scripts.
2. Scan it with a skill scanner, for example
   `skillspector scan <plugin-dir> --no-llm --recursive`.
3. Prefer a pinned version, and review the diff when you update.

## How this repository protects itself

- Actions are pinned to 40-character commit SHAs and updated by Dependabot.
- Workflows start with `permissions: {}` and grant scopes per job.
- Checkout never persists credentials. No workflow uses `pull_request_target`.
- gitleaks scans every commit in CI. Secret scanning and push protection are
  enabled on the repository.
- CI tools are installed with pip hash checking from a compiled lock file.
- Every run builds and validates a CycloneDX 1.7 and SPDX 2.3 SBOM.
- Merges, releases and force-pushes need the owner's explicit approval.

Run the same checks locally:

```bash
python3 -m unittest discover -s tests -v
python3 plugins/coding-cicd-hardening/scripts/check_workflows.py .
gitleaks detect --source . --redact --no-banner -v
```

## Notice: src/aetherops

The `src/aetherops/` directory is not a plugin. No catalog entry references
it, nothing installs it, and the MIT license of this repository does not
cover it. It is frozen pending an owner decision on its removal. Do not
depend on it, do not package it, and do not send changes to it.
