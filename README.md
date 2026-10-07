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

## OWASP Top 10:2025

The latest published edition is **OWASP Top 10:2025**, superseding the 2021
edition. See the [official OWASP Top 10:2025 release](https://github.com/OWASP/Top10/tree/master/2025/docs/en).

| OWASP position | Category | Description | Practical example |
| --- | --- | --- | --- |
| A01:2025 | Broken Access Control | Users can access or modify resources beyond their permissions. | Changing an account ID reveals another user's data. |
| A02:2025 | Security Misconfiguration | Insecure settings or unnecessary features expose an application. | A production server exposes its debug console. |
| A03:2025 | Software Supply Chain Failures | Compromised or vulnerable software dependencies and delivery processes put applications at risk. | A malicious dependency is added to a build. |
| A04:2025 | Cryptographic Failures | Weak or missing cryptography exposes sensitive information. | Passwords are stored using an unsalted fast hash. |
| A05:2025 | Injection | Untrusted input is interpreted as a command or query. | Crafted input makes a SQL query return every account. |
| A06:2025 | Insecure Design | Missing or ineffective security controls in design create risks. | A checkout flow allows unlimited discount use. |
| A07:2025 | Authentication Failures | Weak authentication or session handling lets attackers impersonate users. | Unrestricted login attempts enable credential stuffing. |
| A08:2025 | Software or Data Integrity Failures | Software or data is trusted without verifying its integrity. | An application installs an unsigned update. |
| A09:2025 | Security Logging and Alerting Failures | Missing or ineffective logging and alerts delay detection and response. | Repeated failed logins trigger no alert. |
| A10:2025 | Mishandling of Exceptional Conditions | Unexpected errors or states are handled insecurely. | A failed payment leaves an order marked as paid. |

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
