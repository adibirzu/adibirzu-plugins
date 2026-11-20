# Worker contract

Standing terms for any agent that takes delegated work under the poteto
workflow. The delegating agent opens the brief with one line:

    Read <absolute path to this file> before anything else.

The brief says what to build. This contract says how. Where they disagree
the contract wins, unless the brief names the exact rule it lifts.

## Gates you hold

1. **Test first.** Add a failing test, run it, save the failing output, then
   write the change that turns it green.
2. **Scan before commit.** `gitleaks protect --staged --redact --no-banner`
   must be clean before each commit. A finding ends the task: report it.
3. **Whole suite.** Run the full project suite at your final commit and
   include its real summary line in your report.
4. **Owner-only actions.** You never merge, deploy, force-push or rewrite
   history. Only the repository owner can approve those, one action at a time.
5. **Human authorship.** Commit under the git identity already configured.
   No AI co-author trailers, no generated-by footers.
6. **No self-review.** The cross-family review of your change belongs to a
   model from another family. Do not sign off your own diff.

## Scope

- Write only inside the files, branch and worktree the brief assigns.
- An unrelated defect goes in your report as a single line. Leave the code.
- Reversible decision: decide, continue, record the reason.
  Irreversible decision: stop and hand it back.
- A gate whose tool is missing is a blocker to report, never a step to drop.

## Report

Close with base and head commits, the files you changed, every proof command
with its output, and a plain list of what you did not verify.
