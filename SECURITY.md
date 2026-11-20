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
status" table in [README.md](README.md). One plugin currently fails.

### multillm: DO_NOT_INSTALL

SkillSpector 2.12.0 with `--no-llm` rates the `multillm` bundle
**DO_NOT_INSTALL**, risk score 100, with 37 findings: 20 external script
fetching, 11 external transmission, 3 session persistence, 1 credential
access, 1 cross-context output and 1 bundled hook. Scanned on 2026-11-20.

What that means in practice:

- Installing it registers a `SessionStart` hook. On every session start the
  hook runs `hooks/start-gateway.sh`, which may create a Python virtual
  environment, run `pip install` with no version or hash pins, and start a
  background process that keeps running after the session ends.
- A second hook, `hooks/check-update.sh`, runs at session start and calls
  the GitHub API to look for a newer version.
- The gateway reads provider API keys from your environment and from a
  local `.env` file, and sends prompts to whichever model backends you
  configure. That is its purpose, and it is also why the scanner reports
  credential access and external transmission.
- The gateway package itself is not in this repository. Without it the
  hook cannot start anything.

The plugin stays listed because existing users depend on it, and its catalog
description carries a warning that points here. Treat it as software you
must read before you run. Do not install it on a machine that holds
credentials you are not prepared to expose to it. A plugin that fails the
scan may only stay in the catalog with that warning, and the tests enforce
it.

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
