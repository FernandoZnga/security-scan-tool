# Claude Code and Codex skills

This repository is a starter layout for authoring project skills for Claude Code
and OpenAI Codex. Each tool discovers skills from its own project directory:

- Claude Code: `.claude/skills/`
- Codex: `.agents/skills/`

## Structure

```text
.
├── .agents/
│   └── skills/
│       └── security-scan/
│           └── SKILL.md
└── .claude/
    └── skills/
        └── security-scan/
            └── SKILL.md
```

Each skill lives in its own directory and starts with a `SKILL.md` containing
YAML frontmatter (`name` and `description`) followed by the skill instructions.
The starter `security-scan` skill is present in both locations so it can be
discovered by either tool; keep the two copies in sync when updating it.

As a skill grows, add supporting files beside `SKILL.md`, for example:

```text
security-scan/
├── SKILL.md
├── references/  # Longer guidance loaded when needed
├── scripts/     # Helper scripts the skill can run
└── assets/      # Templates and other supporting files
```

Use precise skill descriptions so the assistant can determine when to invoke
them. Keep `SKILL.md` focused and move detailed reference material into
`references/`.
