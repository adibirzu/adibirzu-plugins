---
description: Share or retrieve working context between Claude and Codex sessions
allowed-tools: Bash
---

Use this command to move active task context between Claude, Codex, or another MCP client.

If the user wants to share context, send a memory entry that names the source and target clearly:
```bash
curl -s -X POST http://localhost:8080/api/memory \
  -H 'Content-Type: application/json' \
  -d '{
    "title": "Shared context: SOURCE to TARGET",
    "content": "CONTEXT",
    "project": "PROJECT",
    "category": "context",
    "source_llm": "SOURCE"
  }'
```

If the user wants to retrieve context for another tool or device:
```bash
curl -s 'http://localhost:8080/api/memory/search?q=SOURCE%20TARGET%20PROJECT&limit=10' | python3 -c "
import sys, json
results = json.load(sys.stdin)
if not results:
    print('No shared context found.')
else:
    for r in results:
        print(f'[{r[\"id\"]}] {r[\"title\"]}')
        print(r['content'])
        print()
"
```

Prefer storing:

- current task state
- decisions already made
- pending risks or TODOs
- target files and commands needed to resume work
