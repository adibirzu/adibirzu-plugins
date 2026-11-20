# Contributing

Thanks for helping. This repository is a plugin catalog that other people
install into their coding agents, so every change is held to the checks
below.

## Setup

You need Python 3.9 or newer, git and gitleaks 8 or newer. The tests and the
linter use only the Python standard library.

```bash
python3 -m unittest discover -s tests -v
python3 plugins/coding-cicd-hardening/scripts/check_workflows.py .
```

## How to make a change

1. **Write the failing test first.** Add or change a test in `tests/` that
   fails for the reason you expect, then make it pass. Say which test in the
   pull request.
2. **Keep the change small.** One plugin or one concern per pull request.
3. **Scan before every commit.**
   `gitleaks protect --staged --redact --no-banner`
4. **Run everything before you push.** The commands are in the checklist.
5. **Open the pull request ready for review.** The owner merges. Do not
   merge, release or force-push yourself.

## Adding or updating a plugin

Local plugin, under `plugins/<name>/`:

- `.claude-plugin/plugin.json` with `name`, `version`, `description` and
  `license`. Add `.codex-plugin/plugin.json` at the same version if the
  plugin supports Codex.
- Every `SKILL.md` has frontmatter with a lowercase hyphenated `name` that
  matches its directory and a `description` of 1024 characters or fewer.
- The entry in `.claude-plugin/marketplace.json`, the plugin manifests and
  the README table carry the same version. The tests enforce this.
- Only original work or work whose license allows it. Do not copy text or
  code from a third-party skill into this repository. Reference it and pin
  the version.

Remote plugin, in its own repository:

- The repository is public, owned by `adibirzu`, and has a valid
  `.claude-plugin/plugin.json` on its default branch.
- Verify that before you add or bump the entry, and paste the output in the
  pull request:

  ```bash
  gh api repos/adibirzu/<repo> --jq '{private, default_branch}'
  gh api repos/adibirzu/<repo>/contents/.claude-plugin/plugin.json \
    --jq .content | base64 -d | python3 -m json.tool
  ```

- The catalog version matches the `version` that command prints. If the
  bump is paired with an unreleased upstream version, say so in the pull
  request and do not merge until the upstream release is out.

## Changing CI

- Pin every action to a 40-character commit SHA with the tag in a comment.
  Resolve the SHA from the upstream repository:
  `gh api repos/<owner>/<action>/commits/<tag> --jq .sha`
- Keep `permissions: {}` at the top of every workflow and grant scopes per
  job. Set `persist-credentials: false` on every checkout. Never add
  `pull_request_target`.
- Install tools with `pip install --require-hashes`. After editing
  `.github/ci/requirements.in`, recompile the lock file with the command in
  that file's header.

## Pull request checklist

Copy this into the pull request description and tick each item.

```markdown
- [ ] A test failed before this change and passes now: `<test id>`
- [ ] `python3 -m unittest discover -s tests -v` passes
- [ ] `python3 plugins/coding-cicd-hardening/scripts/check_workflows.py .` reports 0 findings
- [ ] `gitleaks protect --staged --redact --no-banner` was clean on every commit
- [ ] `gitleaks detect --source . --redact --no-banner -v --log-opts="--full-history --all --diff-merges=first-parent"` is clean
- [ ] `skillspector scan <plugin-dir> --no-llm --recursive` and `skillspector scan <plugin-dir>/skills --no-llm --recursive` both ran, and the "Plugin scan status" table in README.md shows the result
- [ ] No plugin is added or kept with a DO_NOT_INSTALL verdict unless its catalog description carries the warning the tests require
- [ ] No secrets, private hostnames, internal addresses or personal data in the diff
- [ ] Versions agree across marketplace.json, plugin.json and the README table
- [ ] Remote plugin entries were verified against their repository (output pasted)
- [ ] README.md is updated: the "Current Marketplace Architecture" diagram and
      trust boundary table reflect this change, or the change does not touch them
- [ ] No third-party text or code was copied in
- [ ] Commits carry the human author only, with no AI co-author trailers
```

## What does not belong here

Only the catalog, the plugins, their tests and the CI files live in this
repository. Do not add application source trees, build output, compiled
bytecode, logs or data. A test fails on any new top-level entry.

## Security

Never report a vulnerability in a public issue or pull request. See
[SECURITY.md](SECURITY.md).
