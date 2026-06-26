# Corv integrations

Ready-to-use instructions that teach AI agents to drive Corv. These are plain
documentation - they are **not** part of the compiled tool and have no effect
on `go install`. Copy the one you need into your agent.

## Claude / Claude Code

Copy the skill into your skills directory:

```bash
# personal (works everywhere)
cp -r integrations/claude/corv-ssh ~/.claude/skills/

# or per-project
cp -r integrations/claude/corv-ssh .claude/skills/
```

Claude loads it automatically and uses it when a task involves running
something on a remote host.

## Codex

Copy the instructions into the project Codex is working in:

```bash
cp integrations/codex/AGENTS.md ./AGENTS.md
```

(If the project already has an `AGENTS.md`, paste the Corv section into it.)

## Other agents

The same guidance works for any agent - point it at
[`codex/AGENTS.md`](codex/AGENTS.md) as a system prompt or instruction file.
