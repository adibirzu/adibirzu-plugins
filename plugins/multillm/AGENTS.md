# MultiLLM Plugin — Agent & Command Reference

Use this plugin to route work through the local MultiLLM gateway. Agents auto-detect when to invoke based on task phase.

## Agents (8)

| Agent | Phase | Auto-Triggers When |
|-------|-------|-------------------|
| **work-orchestrator** | Any | Phase detection + auto-routing; high-risk changes; uncertainty |
| **task-planner** | Planning | Complex tasks needing decomposition; multi-step work; "plan this" |
| **arch-council** | Planning | Architecture decisions; tradeoffs; competing designs; migrations |
| **code-reviewer** | QA | Code written/modified; PR review; "is this correct" |
| **security-reviewer** | QA | Auth, crypto, secrets, IAM, compliance changes |
| **session-manager** | Lifecycle | Session start (recover context); session end (checkpoint) |
| **local-summarizer** | Any | Large files (>200 lines); logs; token-saving exploration |
| **cross-llm** | Reference | All cross-LLM collaboration patterns and tools |

## Commands (11)

| Command | Purpose |
|---------|---------|
| `/llm-orchestrator` | Unified entry — auto-routes to the right agent/tool |
| `/llm-ask <model> <prompt>` | Send prompt to any backend model |
| `/llm-council <prompt>` | Query 2-5 models in parallel |
| `/llm-review <code>` | Second opinion from another LLM |
| `/llm-memory <action>` | Search, store, list, delete shared memories |
| `/llm-context <action>` | Share/retrieve context between sessions |
| `/llm-usage [window]` | Token usage, costs, sessions |
| `/llm-usage-hourly [window]` | Short-window hourly stats |
| `/llm-discover` | Discover models from all backends |
| `/llm-settings` | View/update gateway settings |
| `/llm-dashboard` | Open dashboard + show status |

## Skills

| Skill | Purpose |
|-------|---------|
| `llm-orchestrator` | Control plane for cross-model routing, SOPs, model profiles |
| `llm-dashboard` | Real-time gateway dashboard |

## Phase-Based Routing

The work-orchestrator auto-detects the task phase and routes:

- **Planning:** "how should we...", "design", "plan" → task-planner or arch-council
- **Execution:** Security-sensitive changes → security-reviewer; high-risk → second opinion
- **QA:** "review", "check", "validate" → code-reviewer; security → security-reviewer

## Checkpoint Discipline

All agents store findings to shared memory automatically. This ensures:
- Other sessions (Codex, Gemini CLI) can find prior decisions
- Repeated questions get answered from memory
- Cross-device work has continuity

## Codex Patterns

- Ask Claude for architectural analysis, then implement locally in Codex
- Store durable notes in shared memory so both tools can search them later
- Pull shared context before resuming work on another machine
- Prefer a shared `MULTILLM_HOME` path for consolidated usage, memory, and sessions
- Use the `work-orchestrator` for automatic cross-LLM help
- Use `session-manager` to checkpoint before ending and recover when starting
