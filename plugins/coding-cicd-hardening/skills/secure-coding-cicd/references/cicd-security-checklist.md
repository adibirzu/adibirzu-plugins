# CI/CD security checklist

Fourteen controls in priority order. Each has the rule, the reason, a
compliant example and a command that proves it. Controls 1 to 6 are checked
by `scripts/check_workflows.py`. The rest need the commands shown.

## Contents

1. Pin every action to a 40-character commit SHA
2. Default the token to no permissions
3. Do not persist checkout credentials
4. Do not use pull_request_target
5. Keep untrusted input out of run
6. Use OIDC, not static cloud keys
7. Scan for secrets
8. Run SAST
9. Review and update dependencies
10. Hash-pin tool installs
11. Keep tests away from production
12. Publish an SBOM
13. Gate skills and plugins before install
14. Keep the README architecture current

## 1. Pin every action to a 40-character commit SHA

**Rule.** Every `uses:` names a full commit SHA. Keep the release tag in a
trailing comment so people and update bots can read it. Every container
image, on a job, a service or a step, names a sha256 digest.

**Why.** A tag such as `@v4` is a pointer its owner can move. In March 2025
the tags of a widely used action were repointed to a commit that printed CI
secrets into build logs, and every workflow that trusted the tag ran it. A
full SHA cannot be repointed.

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

Resolve the SHA yourself from the upstream repository. Do not copy one from
a blog post or an issue comment.

```bash
gh api repos/actions/checkout/commits/v7.0.1 --jq .sha
```

The same holds for reusable workflows and container images. Pin images by
digest. A job container or a service image is written
`image@sha256:<64 hex>`. A step that runs an image is written
`uses: docker://image@sha256:<64 hex>`.

An image named through `${{ matrix.<axis> }}` is checked against the literal
values of that matrix axis. Any other expression is reported as
`unparsed-construct`, because it cannot be checked.

**Verify.** `python3 scripts/check_workflows.py .` reports no
`unpinned-action` and no `unpinned-image`.

## 2. Default the token to no permissions

**Rule.** Every workflow has a top-level `permissions: {}`. Each job then
lists the scopes it needs. `permissions: read-all` is the loosest acceptable
default.

**Why.** Without the key the token gets the repository default, which may
include write access. A compromised step inherits whatever the token holds.

```yaml
permissions: {}

jobs:
  test:
    permissions:
      contents: read
```

Never use `write-all`. Put a write scope on the one job that needs it, not
at the top where every job receives it.

**Verify.** No `missing-top-level-permissions` or `broad-permissions`.

## 3. Do not persist checkout credentials

**Rule.** Every `actions/checkout` step sets `persist-credentials: false`.

**Why.** By default checkout writes the token into `.git/config`, where
every later step, and any artifact that includes the `.git` directory, can
read it.

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  with:
    persist-credentials: false
```

A job that must push uses a narrowly scoped token in the push step only.

**Verify.** No `checkout-persist-credentials`.

## 4. Do not use pull_request_target

**Rule.** No workflow triggers on `pull_request_target`.

**Why.** That trigger runs in the base repository's context with its secrets
and a write token. If the job then checks out or executes the pull request's
code, a stranger's fork runs with your credentials. Use `pull_request`, which
runs fork code with a read-only token and no secrets.

If you need to comment on or label fork pull requests, split the work: an
unprivileged `pull_request` job produces an artifact, and a separate
`workflow_run` job with the write scope consumes it without running any code
from the fork.

**Verify.** No `pull-request-target`.

## 5. Keep untrusted input out of run

**Rule.** Titles, bodies, branch names, commit messages and author names
never appear as `${{ }}` expressions inside a `run` block. Pass them through
`env` and quote the variable.

**Why.** Expressions are pasted into the script before the shell starts. A
pull request titled with shell syntax then executes as part of your job. The
`script` input of `actions/github-script` is the same kind of sink.

```yaml
- env:
    TITLE: ${{ github.event.pull_request.title }}
  run: echo "$TITLE"
```

**Verify.** No `script-injection`.

## 6. Use OIDC, not static cloud keys

**Rule.** Workflows authenticate to cloud providers with OIDC workload
identity federation. No service account JSON key, access key pair or client
secret is stored as a repository secret.

**Why.** A static key is valid until someone rotates it and works from
anywhere. An OIDC token lives for minutes and is bound to one repository,
branch and workflow by the provider's trust policy.

```yaml
jobs:
  deploy:
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: <cloud-auth-action>@<40-character commit SHA>
        with:
          # role or workload identity provider, never a key
```

Restrict the trust policy on the cloud side to the exact repository and ref.
A policy that trusts every repository in an organization is a shared key
under another name.

The linter flags the usual key inputs on any action, the Azure `creds`
input on `azure/login`, and the standard key variables in any `env` block,
such as `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

**Verify.** No `static-cloud-credential`, and no long-lived cloud key among
the repository secrets.

## 7. Scan for secrets

**Rule.** gitleaks runs on staged changes before every commit and on the
full history in CI. Enable the host's secret scanning and push protection
too.

```bash
# before each commit
gitleaks protect --staged --redact --no-banner

# CI and before each pull request
gitleaks detect --source . --redact --no-banner -v \
  --log-opts="--full-history --all --diff-merges=first-parent"
```

The `--log-opts` line matters. By default gitleaks reads `git log -p`, which
prints no diff for a merge commit, so a secret added while resolving a
conflict is never scanned. `--diff-merges=first-parent` makes it visible.

Install the scanner in CI from a release archive and verify its checksum
before you run it. A scanner you did not checksum is one more unpinned
dependency. In CI, check out with `fetch-depth: 0` so the scan sees
every commit.

A secret that reached a remote is leaked. Rotate it first, then clean up.

## 8. Run SAST

**Rule.** Static analysis runs on every pull request.

| Tool | Catches |
|---|---|
| ruff | Syntax and logic errors, unsafe patterns through its `S` rules |
| bandit | Python security issues such as shell injection and weak hashing |
| semgrep | Cross-language rules, including your own project-specific ones |

Commit the configuration so local and CI runs agree. Fix a finding or
suppress it on the line with a reason. Do not lower the rule set to get to
green.

## 9. Review and update dependencies

**Rule.** Dependency review runs on pull requests and fails on new known
vulnerabilities. Dependabot opens grouped weekly updates for every ecosystem
in use, including `github-actions`.

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    cooldown:
      default-days: 7
    groups:
      github-actions:
        patterns: ["*"]
```

Grouping gives one pull request per ecosystem instead of a queue nobody
reads. The cooldown skips releases younger than a week, which is when most
hijacked releases are found and withdrawn. Dependabot keeps SHA pins and
their version comments current, so pinning does not mean stale.

## 10. Hash-pin tool installs

**Rule.** CI installs Python tools with `pip install --require-hashes` from
a compiled lock file. Other ecosystems use their lock file with integrity
checks enforced.

```bash
uv pip compile --universal --generate-hashes requirements.in -o requirements.txt
python3 -m pip install --require-hashes -r requirements.txt
```

## 11. Keep tests away from production

**Rule.** No test reaches a production URL unless a person opts in for that
run. A test never falls back to a real host when its variable is unset.

```python
# Wrong: an unset variable silently points the suite at a live service.
BASE = os.environ.get("API_URL", "https://<real service host>")

# Right: default to a local or reserved host. Live runs are an explicit opt-in.
BASE = os.environ.get("API_URL", "http://127.0.0.1:8000")
LIVE = os.environ.get("ALLOW_LIVE_TESTS") == "1"
```

Reserved names that are always safe as defaults: `localhost`, loopback
addresses, and the `.test`, `.example`, `.invalid` and `.localhost` domains.
Add a guard that fails the suite when a production URL is configured and the
opt-in is not set. Unit tests should not open network connections at all.

**Verify.** No `prod-url-default`.

## 12. Publish an SBOM

Generate CycloneDX 1.7 and SPDX 2.3, validate both with the official
validators, and attest them on release. See
[sbom-and-supply-chain.md](sbom-and-supply-chain.md).

## 13. Gate skills and plugins before install

**Rule.** Scan every agent skill and plugin before it is installed or
listed, the same way you would review a dependency. A skill is instructions
plus code that run with your agent's access.

```bash
skillspector scan <plugin-dir> --no-llm --recursive         # whole bundle: hooks, scripts, commands
skillspector scan <plugin-dir>/skills --no-llm --recursive  # each skill on its own
python3 scripts/check_workflows.py <plugin-dir>             # frontmatter and hygiene
```

Run both scans. The bundle scan is the one that sees hooks and scripts
outside `skills/`. The second finds each skill and rates it separately.

SkillSpector is one scanner. Any scanner that reports prompt injection,
hidden instructions, exfiltration and unsafe tool use will do. Treat a
do-not-install verdict as a block. If the owner waives it, record the
waiver with the exact commit and archive hash it covers. A waiver never
carries to a newer version.

Third-party skills keep their own license. Do not copy their text into a
repository under a different license. Reference them and pin the version.

## 14. Keep the README architecture current

**Rule.** The README has an architecture section with a diagram and the
trust boundaries. Any change to components, data flow, trust boundaries or
CI gates updates that section in the same pull request.

**Why.** The diagram is what a reviewer uses to decide what a change can
reach. An outdated diagram is worse than none, because people trust it.

Add the item to the pull request checklist, and where you can, add a test
that fails when the README and the source of truth disagree, for example a
version table that must match a manifest.
