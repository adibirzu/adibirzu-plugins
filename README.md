# adibirzu-plugins

Claude Code plugin marketplace by [adibirzu](https://github.com/adibirzu).

## Plugins

| Plugin | Description | Version |
|--------|-------------|---------|
| [prod-ready](https://github.com/adibirzu/claude-prod-ready-plugin) | Pre-production security audit, dependency hardening, CI/CD validation, and Docker readiness checks | 1.0.0 |
| [rlm](https://github.com/adibirzu/rlm-plugin) | Recursive, evidence-backed analysis for repositories and large document sets | 3.1.0 |
| [multillm](https://github.com/adibirzu/multillm) | Multi-LLM gateway with 16+ backends, model discovery, session tracking, usage dashboard, and cross-LLM memory | 0.5.1 |

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
```

## License

MIT
