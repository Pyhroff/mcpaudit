# mcpaudit Threat Model

## Security objective

Detect security-relevant changes and attacker-controlled influence at the MCP tool boundary before those inputs can cause unsafe model-driven actions.

## Assets

- Model-visible tool names and descriptions
- Tool input schemas and declared authority
- Tool outputs consumed by an agent
- Approved tool manifests
- CI enforcement decisions and scan reports

## Trust boundaries

```
MCP server ──tool metadata──> model/agent context
     │                              │
     └────tool output───────────────┘
                    │
                    ▼
                mcpaudit
                    │
          static + controlled dynamic
                    │
                    ▼
             finding / gate
```

The scanner treats tool metadata and tool output as potentially untrusted. A clean result is not a sandbox guarantee.

## Threats in scope

| Threat | Example | Detection |
|---|---|---|
| Tool poisoning | Hidden model-directed instructions in descriptions | `description_scan` |
| Excessive authority | Broad filesystem/command/network parameters | `permission_scope` |
| Rug pull | Tool manifest changes after approval | `rug_pull` |
| Confused deputy | Untrusted tool output influences a model action | Opt-in dynamic experiment |

## Out of scope

- Proving the MCP server itself is malware-free
- Complete authorization analysis of the surrounding application
- Provider/model safety guarantees
- Network isolation or sandboxing
- Universal exploitability claims from static findings

## Security assumptions

1. The scanner can observe the MCP tool surface.
2. Approved manifests represent a trusted review point.
3. Dynamic experiments run only against authorized test targets.
4. Findings are evidence for review, not proof of compromise.

## Severity philosophy

Severity should represent the security consequence of the observed surface, not merely pattern rarity. Dynamic evidence is stronger than a static heuristic, but remains bounded by the selected model, prompt, fixture, and target.

## Safe research boundary

Use mcpaudit only against MCP servers and models you own or are explicitly authorized to test. The bundled dynamic experiments are intended for controlled research and regression testing.
