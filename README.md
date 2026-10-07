# Security Scan Skills

[![Claude Code](https://img.shields.io/badge/Claude_Code-supported-6B4FBB?logo=anthropic&logoColor=white)](https://www.anthropic.com/claude-code)
[![OpenAI Codex](https://img.shields.io/badge/OpenAI_Codex-supported-111111?logo=openai&logoColor=white)](https://openai.com/codex/)
[![License: MIT](https://img.shields.io/badge/License-MIT-2E7D32.svg)](LICENSE)

This repository packages a reusable, read-only security-audit skill for AI
coding assistants. It guides an assistant through scanning an authorized
codebase, validating likely findings in context, and returning a severity-ranked
report. It is an instruction and pattern library, not a standalone scanner.

The skill is packaged for both Claude Code and OpenAI Codex:

- Claude Code: `.claude/skills/security-scan/`
- Codex: `.agents/skills/security-scan/`

## Coverage

The audit detects the project's technology stack, then checks applicable areas:

| Scope | Coverage |
| --- | --- |
| `secrets` | API keys, tokens, credentials, private keys, and committed secret files |
| `injection` | SQL/NoSQL injection, XSS, command injection, SSRF, deserialization, path traversal, XXE, SSTI, and open redirects |
| `auth` | JWT and password handling, sessions, access control, and insecure randomness |
| `config` | CORS, security headers, debug endpoints, TLS, Docker, Kubernetes, and Terraform |
| `deps` | Available native advisory scanners plus dependency-manifest heuristics |
| `ai` | AI credentials, prompt injection, unsafe model output, and excessive agent permissions |
| `mobile` | Android, iOS, and Flutter storage, transport, certificate, and crypto risks |
| `data` | PII in logs, sensitive URLs, plaintext HTTP, weak crypto, and information leaks |

The default `all` scope runs every applicable module. Mobile checks run only when
the project contains Android, iOS, or Flutter indicators. Detection patterns,
severity guidance, and reference mappings live in each skill's `patterns.md`.
The current library maps to OWASP Top 10:2021, OWASP LLM Top 10, and OWASP
Mobile Top 10 / MASVS.

## Use

Ask the assistant to run a security scan, optionally naming a scope and path.
For example:

```text
Run a full security scan of this repository.
Scan only for secrets in src/.
Run the dependency scan for the project.
```

Supported scopes are `all`, `secrets`, `injection`, `auth`, `config`, `deps`,
`ai`, `mobile`, and `data`. If no scope or path is specified, the skill scans
the project root using the `all` scope.

## Install in Your Project

From the root of a clone of this repository, set `TARGET` to the path of the
project you want to scan. Copy the complete skill directory so its `SKILL.md`
and required `patterns.md` stay together.

For Claude Code, run:

```sh
TARGET="/path/to/your/project"
mkdir -p "$TARGET/.claude/skills"
cp -R .claude/skills/security-scan "$TARGET/.claude/skills/"
```

Then open that project in Claude Code and invoke the skill, for example:

```text
/security-scan secrets src/
```

For OpenAI Codex, run this instead:

```sh
TARGET="/path/to/your/project"
mkdir -p "$TARGET/.agents/skills"
cp -R .agents/skills/security-scan "$TARGET/.agents/skills/"
```

Then open that project in Codex and invoke the skill, for example:

```text
$security-scan secrets src/
```

If Codex does not detect the newly copied skill, restart or refresh its
session.

## Safety and Reporting

- Scans are read-only: the skill reports issues and does not patch or refactor
  project code.
- Scan only code the user owns or is authorized to assess.
- Secret values are redacted in findings; exposed credentials should be rotated
  and removed from repository history.
- Matches are triaged for context, framework protections, false positives, and
  duplicates before they are reported.
- The report groups findings by severity and includes priorities, positive
  security practices, and general recommendations.

## Repository Layout

```text
.
├── .agents/skills/security-scan/
│   ├── SKILL.md
│   └── patterns.md
└── .claude/skills/security-scan/
    ├── SKILL.md
    └── patterns.md
```

Each `SKILL.md` contains the workflow and frontmatter used to identify and invoke
the skill. Its companion `patterns.md` contains the detection rules and
reference material. Keep both platform copies in sync when making changes.
