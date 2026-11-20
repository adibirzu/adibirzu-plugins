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
2. Scan it. Run both commands, because the first is the one that sees hooks
   and scripts outside `skills/`:

   ```bash
   skillspector scan <plugin-dir> --no-llm --recursive
   skillspector scan <plugin-dir>/skills --no-llm --recursive
   ```

3. Prefer a pinned version, and review the diff when you update.

## Known scan findings

The scan verdict for every local plugin is published in the "Plugin scan
status" table in [README.md](README.md). No local plugin currently fails the
scan.

A plugin that scans DO_NOT_INSTALL is not published in this catalog. The
`multillm` plugin was removed on that basis because it also depended on a
gateway package that is not in this repository, so it could not run for
public users.

`just-do-it` is rated CAUTION, score 44, with 5 findings, the most serious
being access to agent configuration directories. That is expected for a tool
that writes agent team configurations, and it deserves the same read before
install.

## How this repository protects itself

- Actions are pinned to 40-character commit SHAs and updated by Dependabot.
- Workflows start with `permissions: {}` and grant scopes per job.
- Checkout never persists credentials. No workflow uses `pull_request_target`.
- gitleaks scans every commit in CI, including the changes made inside merge
  commits. Secret scanning and push protection are enabled on the repository.
- CI tools are installed with pip hash checking from a compiled lock file.
- Every run builds and validates a CycloneDX 1.7 and SPDX 2.3 SBOM.
- Only catalog content lives here. A test fails on any other top-level entry
  and on compiled bytecode inside a plugin.
- Merges, releases and force-pushes need the owner's explicit approval.

Run the same checks locally:

```bash
python3 -m unittest discover -s tests -v
python3 plugins/coding-cicd-hardening/scripts/check_workflows.py .
gitleaks detect --source . --redact --no-banner -v \
  --log-opts="--full-history --all --diff-merges=first-parent"
```
