---
name: poteto-workflow
description: Runs engineering work through four stages (interrogate, arena, swarm, show-me-your-work) under seven hard crew gates. The gates are a failing test before the fix, review by a different model family, gitleaks before every commit and pull request, the full suite green, owner approval for merge, deploy and force-push, no AI co-author trailers, and tiered model routing. Use for a feature, bug fix, refactor or review, or when the user says poteto, crew gates or gated workflow.
license: MIT
compatibility: Needs git and gitleaks 8 or newer. The review gate needs access to a second model family.
metadata:
  version: "1.0.0"
  author: adibirzu
---

# Poteto workflow

A change moves through four stages. Seven crew gates hold at every stage.
The stages scale down for small work. The gates never do.

```
interrogate -> arena -> swarm -> show-me-your-work
     |           |        |              |
     +-----------+--------+--------------+--- crew gates apply throughout
```

## Start here

1. Restate the goal in one sentence and name the smallest change that meets it.
2. Pick the stages the work needs from the table below.
3. Read [references/crew-gates.md](references/crew-gates.md) before the first commit.
4. If you hand any part to another agent, put the contract in
   [worker.md](worker.md) at the top of its brief.

| Work | Interrogate | Arena | Swarm | Show your work |
|---|---|---|---|---|
| One-file fix with a known cause | one question: is the cause proven | skip | skip | required |
| Feature inside one module | required | only for a real fork | skip | required |
| Cross-cutting change or migration | required | required for each fork | required | required |
| Review of someone else's change | required | skip | optional | required |

## Stage 1: interrogate

Attack the plan before any code exists. The goal is to find the wrong
assumption while it is still cheap.

- Write the premise down: what must be true for this plan to work.
- Ask what evidence supports each part and what would disprove it.
- Run the cheapest disproof first. A command beats an argument.
- For a bug, reproduce it and keep the failing reproduction. It becomes the
  failing test that gate 1 needs.
- Have a second reader, on a different model family when one is available,
  argue the opposite position.

Exit when the plan has survived a real attempt to break it, and the open
risks are written down with an owner for each.

## Stage 2: arena

Use the arena when two or more approaches are plausible and the choice is
expensive to reverse. Skip it when one approach is plainly right.

- State the rubric before building anything. Name what is measured and how.
- Build each contender as a small throwaway prototype on its own branch.
- Run the same check against every contender and record the raw output.
- Pick one winner and say why in terms of the rubric.
- Delete the losers. Do not merge two contenders into a hybrid nobody tested.

Exit with one chosen approach and the measurements that chose it.

## Stage 3: swarm

Fan out when the work splits into units that do not share state.

- Draw the boundaries before assigning anything. No two workers may hold
  write access to the same path or branch. If two units overlap, redraw them.
- Give each worker its own worktree, a brief with the goal, the files in
  scope, the check that proves its unit, and the contract in `worker.md`.
- Each unit lands with its own failing-then-passing test.
- Accepting a unit makes it yours. Read its diff and rerun its check
  yourself first. A worker's summary is a claim, not a result.
- Integrate one unit at a time and run the suite between units.

Exit when every unit is integrated and the full suite passes at the
integrated head.

## Stage 4: show-me-your-work

Leave a record a reviewer can rerun on their own.

- Base and head commits, and the files in scope.
- Every proof command with its real output: the failing run, the passing
  run, the secret scan, the review verdict.
- What was not verified and why.
- Each number with what it measured and what limits it.

Keep long logs in a file and link to them. A claim without a command and its
output is a guess, so label it as one.

## Crew gates

| # | Gate | Proof |
|---|---|---|
| 1 | Failing test before the fix | The test fails at base and passes at head |
| 2 | Cross-family review before a pull request | Verdict from a model family other than the author's, bound to the head commit |
| 3 | Secret scan before every commit and pull request | Clean `gitleaks protect --staged` and `gitleaks detect` runs |
| 4 | Full project suite green before a pull request | The project's own suite passes at head |
| 5 | Owner authorization for merge, deploy and force-push | An explicit yes from the owner for that action |
| 6 | No AI co-author trailers | `git log` shows only the human author |
| 7 | Model tier routing | Each role runs on the tier the routing table assigns |

Commands, failure handling and the reasoning behind each gate are in
[references/crew-gates.md](references/crew-gates.md).

A gate that cannot run is a blocker to report. It is never a step to skip.
If a tool is missing, say so and stop before the action the gate protects.

## Model tier routing

Route by the kind of thinking a role needs, not by habit. Keep the mapping in
one place the whole team reads, and change it there.

| Tier | Roles | Guidance |
|---|---|---|
| Assembly | Mechanical edits, renames, boilerplate, running checks | Fast and cheap model, approach already decided |
| Build | Implementation to a settled design, bug fixes | Strong coding model at medium to high effort |
| Judgment | Interrogation, design, root cause analysis | Strongest reasoning model available |
| Review | Gate 2 verdicts, security reads | A different family from the author of the change |

The author and the reviewer of one change must come from different model
families. A reviewer never audits work it built.

## Optional integrations

Everything above works with plain git and gitleaks. Two integrations add
enforcement and deeper stage playbooks. Neither is bundled with this plugin.

- **Orca harness.** The `orca-harness-poteto` Orca plugin can enforce part of
  this workflow in the terminal: it blocks merge, deploy and force-push
  commands until they are unlocked, injects the worker contract into agent
  kickoffs, and shows a scorecard for the test-first, secret scan and review
  gates. Install it separately in Orca. This skill is the policy and that
  plugin is one way to enforce it.
- **Local pstack.** If your station has a pinned copy of pstack, for example
  under `~/.pstack/<commit>/skills`, you can use its `interrogate`, `arena`,
  `swarm` and `show-me-your-work` skills as the detailed playbooks for the
  four stages. pstack is third-party work, not bundled here and not covered
  by this plugin's license. Pin it to a commit, scan it before installing,
  and record any scanner waiver next to the pinned copy with the commit and
  archive hash it applies to. Where pstack marks a test or review step as
  optional, the crew gates here still apply.

## Provenance

All text in this plugin is original and MIT licensed. The stage names follow
the vocabulary of the pstack project so the two can be used together. This
plugin is not affiliated with or endorsed by the pstack authors and contains
none of their material.
