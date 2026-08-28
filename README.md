# adibirzu-plugins

Claude Code plugin marketplace by [adibirzu](https://github.com/adibirzu) for production engineering, multi-model workflows, and OCI cloud operations.

## Plugins

| Plugin | Description | Version |
|--------|-------------|---------|
| [prod-ready](https://github.com/adibirzu/claude-prod-ready-plugin) | Pre-production security audit, dependency hardening, CI/CD validation, and Docker readiness checks | 1.0.0 |
| [rlm](https://github.com/adibirzu/rlm-plugin) | Budgeted recursive analysis with evidence ledgers and selective verification | 3.2.0 |
| [multillm](https://github.com/adibirzu/multillm) | Multi-LLM gateway with model discovery, session tracking, usage controls, fusion, and cross-LLM memory | 0.9.0 |
| [oci-administrator](https://github.com/adibirzu/oci-skills) | Safety-first OCI administration, Terraform, platform engineering, storage, disaster recovery, Bastion, database, and landing-zone workflows | 2.0.0-rc.3 |
| [just-do-it](plugins/just-do-it) | Portable PRD delivery and clean least-privilege agent-team generation across major coding harnesses | 1.5.0 |

## Installation

Add this marketplace to Claude Code:

```bash
/plugin marketplace add adibirzu/adibirzu-plugins
```

Then install individual plugins:

```bash
/plugin install prod-ready@adibirzu-plugins
/plugin install rlm@adibirzu-plugins
/plugin install multillm@adibirzu-plugins
/plugin install oci-administrator@adibirzu-plugins
/plugin install just-do-it@adibirzu-plugins
```

Refresh the catalog and an installed OCI plugin after a release:

```text
/plugin marketplace update adibirzu-plugins
/plugin update oci-administrator@adibirzu-plugins
/plugin update just-do-it@adibirzu-plugins
/reload-plugins
```

## MultiLLM Notes

The `multillm` plugin now includes:

- Claude and Codex usage guides for the same gateway and MCP toolset
- richer usage math in the dashboard summaries, including per-request and per-session calculations
- hourly usage checks in addition to 24h and 7d summaries
- a portable `MULTILLM_HOME` setup so multiple devices can point at one synced data directory
- built-in orchestration patterns so Claude/Codex can pull in council, second-opinion, and context-sharing help more consistently

For multi-device usage consolidation, set `MULTILLM_HOME` to the same synced directory on each device before starting the gateway:

```bash
export MULTILLM_HOME="$HOME/Library/Mobile Documents/com~apple~CloudDocs/.multillm"
```

## License

MIT
