# Crew gates

Seven gates hold for every change, at every stage. Each entry gives the rule,
the proof a reviewer can rerun, and what to do when the gate fails.

Where a stage playbook or an upstream skill calls a test or review step
optional, these gates still apply. Project rules that are stricter than a
gate win. Nothing here loosens a project's own approval or security rules.

## Contents

1. Failing test before the fix
2. Cross-family review before a pull request
3. Secret scan before every commit and pull request
4. Full project suite green before a pull request
5. Owner authorization for merge, deploy and force-push
6. No AI co-author trailers
7. Model tier routing

## 1. Failing test before the fix

**Rule.** A test that captures the wanted behavior exists and fails before
the change that makes it pass.

**Why.** A test written after the fix proves only that the test agrees with
the code. A test that failed first proves the code changed the behavior.

**Proof.**

```bash
# at base, with only the new test added
<project test command>        # expect: the new test fails for the right reason
# at head
<project test command>        # expect: the same test passes
```

Keep both outputs. For a bug, the failing test is the reproduction of the
real trigger, not a simplified cousin of it. For a refactor, the equivalent
is a characterization test that passes before and after.

**On failure.** If the test passes at base, it does not test the change.
Rewrite it. If you cannot make it fail for the right reason, you do not yet
understand the change. Go back to the interrogate stage.

## 2. Cross-family review before a pull request

**Rule.** Before a pull request opens, a model from a different family than
the author reviews the diff and gives a verdict tied to the head commit.

**Why.** Models from one family share blind spots. Agreement inside a family
is weak evidence. A different family reading the diff cold catches what the
author's family repeats.

**Proof.** Record the reviewer's provider and model, the commit it reviewed
and its findings. Give it the diff and the goal, not your conclusion.

```bash
git diff <base>...HEAD > /tmp/change.diff
git rev-parse HEAD            # the verdict is valid for this commit only
```

**On failure.** Fix each real finding test-first under gate 1, then ask for a
fresh review of the new head. Judge each finding on its merits and say which
you declined and why. Cap the loop at three rounds, then report what is left.
Agreement between reviewers is not proof the code works. Gate 4 is.

## 3. Secret scan before every commit and pull request

**Rule.** Staged changes are scanned before every commit. The whole history
is scanned before every pull request.

**Why.** A secret pushed to a remote is compromised, even if a later commit
deletes it. The only cheap moment to catch it is before the commit exists.

**Proof.**

```bash
gitleaks protect --staged --redact --no-banner     # before every commit
gitleaks detect --source . --redact --no-banner -v # before every pull request
```

Always pass `--redact` so a finding never prints the secret into a log.

**On failure.** Stop. Do not commit, and do not push. Unstage the file and
remove the value. If the secret already reached a remote, treat it as leaked:
tell the owner, rotate it, then clean up. Rewriting history is a gate 5
action and needs the owner's yes. Never silence a true finding with an
allowlist entry.

## 4. Full project suite green before a pull request

**Rule.** The project's own full test suite passes at the exact head that
the pull request will carry.

**Why.** A targeted test shows the change works. Only the full suite shows
it broke nothing else.

**Proof.** Run the command the project documents and keep the summary line.

```bash
<full project suite command>  # at HEAD, after the last commit
```

**On failure.** A failure the change caused blocks the pull request. A
failure the base already has is reported in one line with the base output
that shows it. Never weaken, skip or delete a test to get to green.

## 5. Owner authorization for merge, deploy and force-push

**Rule.** Merging, deploying, force-pushing and rewriting history each need
an explicit yes from the owner for that specific action.

**Why.** These actions are hard or impossible to undo and reach beyond the
branch. Review confidence is not authority.

**Proof.** Quote the owner's approval in the task record next to the action
it covers.

**On failure.** Without a yes, stop at an open pull request that is ready for
review. Approval for one merge does not carry to the next, and approval to
merge is not approval to deploy. Opening a pull request, pushing a feature
branch and commenting on a ticket do not need this gate.

## 6. No AI co-author trailers

**Rule.** Commits carry the human author configured in git and no AI
co-author trailers or generated-by lines.

**Why.** The human who approves a change is accountable for it. Authorship
metadata should say who that is, and nothing else.

**Proof.**

```bash
git log <base>..HEAD --format='%an <%ae>%n%(trailers)' | sort -u
```

Expect one human identity and no `Co-authored-by` lines naming a model.

**On failure.** Amend commits that have not been pushed. For pushed commits,
tell the owner. Rewriting pushed history is a gate 5 action.

## 7. Model tier routing

**Rule.** Each role runs on the model tier the team's routing table assigns
to it, and the author and reviewer of one change differ in family.

**Why.** Spending the strongest model on mechanical edits wastes budget.
Spending the cheapest on a design decision wastes the project.

| Model tier | Use for |
|---|---|
| Assembly | Mechanical edits, renames, running checks |
| Build | Implementation to a settled design, bug fixes |
| Judgment | Interrogation, design, root cause analysis |
| Review | Gate 2 verdicts and security reads, from another family |

**Proof.** The task record names the provider and model used for each role.

**On failure.** If the assigned model is unavailable, fall back to the
nearest model in the same tier and say so. Do not let the author's family
fill the review seat because the other family is out of quota. Wait or
report the block instead.

## Gate record

Copy this into the pull request or task record and fill it in.

```text
Base / head:        <sha> / <sha>
1 Failing test:     <test id>  failed at <sha>, passes at <sha>
2 Review:           <provider/model>  verdict at <sha>, <n> findings fixed
3 Secret scan:      protect clean on every commit, detect clean at <sha>
4 Full suite:       <command>  <summary line>
5 Authorization:    not requested (pull request left open for the owner)
6 Trailers:         none
7 Routing:          author <family>, reviewer <family>
Not verified:       <anything skipped and why>
```
