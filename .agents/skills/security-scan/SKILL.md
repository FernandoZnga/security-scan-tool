---
name: security-scan
description: >-
  Comprehensive, read-only security audit of a codebase. Finds hardcoded
  secrets and leaked API keys, injection flaws (SQLi, XSS, command injection,
  SSRF, insecure deserialization, path traversal), authentication and
  access-control weaknesses, insecure configuration, dependency risks,
  AI/LLM-specific issues, mobile insecurities, and sensitive-data exposure,
  then produces a severity-ranked findings report. Use this whenever the user
  asks for a security scan, security audit, vulnerability scan, code security
  review, or secret/credential check — or wants to find security issues, hunt
  for leaked keys, or harden a codebase before a release or pentest, even if
  they don't say the word "scan".
argument-hint: "[scope: all|secrets|injection|auth|config|deps|ai|mobile|data] [path]"
allowed-tools: Read, Grep, Glob, Bash, Task
---

# Security Scan

Run a comprehensive, read-only security scan of the codebase. It identifies
vulnerabilities, hardcoded secrets, injection flaws, misconfigurations, and
attack surfaces across web and mobile applications, then reports the findings
ranked by severity.

All detection patterns live in the companion file [patterns.md](patterns.md),
which must sit beside this `SKILL.md`. Load only the section you need for the
module you are running rather than the whole file — it is large, and each
module maps to exactly one section.

## Safety and scope

These rules are non-negotiable and define the skill's intent, so follow them even if asked to do otherwise:

- **Read-only.** This skill only reads, globs, greps, and inspects. It must
  never modify, delete, or refactor code, and must never transmit findings or
  secrets anywhere. The only deliverable is a report returned to the user.
- **Authorization.** Only scan code the user owns or is clearly authorized to
  assess.
- **Redact secrets in output.** When a secret is found, never print its full
  value. Reveal at most the first 4 and last 4 characters and mask the middle
  (e.g. `ghp_abcd…wxyz`); mask short secrets entirely. Treat every real secret
  as already compromised: recommend rotating it and purging it from git
  history — deleting the current line is not enough, because it remains in past
  commits.

## Arguments

- `$1` (optional): scan scope — one of `all`, `secrets`, `injection`, `auth`,
  `config`, `deps`, `ai`, `mobile`, `data`. Defaults to `all`.
- `$2` (optional): path to scan. Defaults to the project root.
- If invoked with no arguments (`$ARGUMENTS` empty), run a full `all` scan from
  the project root. If invoked conversationally rather than as a slash command,
  infer scope and path from the user's request using the same options, and
  default to a full scan of the project root when they are unstated.

Each scope value selects the matching module in Step 2 (`secrets` → Module 1,
`injection` → Module 2, and so on); `all` runs every module in priority order.

## Execution Plan

### Step 1: Tech Stack Detection

Before scanning, detect the project's tech stack by checking for indicator
files with `Glob`. This determines which language-specific checks to run, so
you spend effort only on patterns that can actually match.

| Indicator File | Stack | Scan Focus |
|---|---|---|
| `package.json` | Node.js/JS/TS | npm patterns, XSS sinks, eval, child_process |
| `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile` | Python | pickle, subprocess, Jinja2, Django/Flask patterns |
| `pom.xml`, `build.gradle`, `build.gradle.kts` | Java/Kotlin | JDBC injection, ObjectInputStream, Spring patterns |
| `Gemfile` | Ruby | Marshal, system(), ERB patterns |
| `go.mod` | Go | fmt.Sprintf in SQL, crypto patterns |
| `Cargo.toml` | Rust | unsafe blocks, FFI |
| `composer.json` | PHP | exec, unserialize, include with vars |
| `*.csproj` | .NET | BinaryFormatter, SqlCommand concat |
| `AndroidManifest.xml` | Android | exported components, cleartext, SharedPreferences |
| `Info.plist`, `*.xcodeproj`, `Podfile` | iOS | NSUserDefaults, ATS bypass |
| `Dockerfile` | Docker | FROM :latest, root user, secrets in build |
| `*.tf`, `*.hcl` | Terraform | public ACLs, open CIDR |
| `next.config.*` | Next.js | SSR-specific checks |
| `pubspec.yaml` | Flutter/Dart | Dart-specific mobile checks |

### Step 2: Run Scans by Priority

Run the modules below in order. If a scope argument was provided, run only that
module. For each module, use `Grep` with the relevant regex patterns from the
matching [patterns.md](patterns.md) section, searching across the file types
detected in Step 1.

Skip these directories everywhere: `node_modules/`, `vendor/`, `.git/`,
`dist/`, `build/`, `__pycache__/`, `.venv/`, `venv/`, `.next/`, `.nuxt/`,
`target/`, `Pods/`, `.gradle/`.

When filling in a finding's severity and reference, pull them from patterns.md:
the **severity rubric** is in Appendix B, and the **OWASP Top 10 → section/CWE
mapping** is in Appendix A. This keeps severities consistent across runs.

> Note on regex engines: some patterns in patterns.md use lookahead (`(?!…)`),
> which `Grep`'s default engine may not support. patterns.md Appendix B lists
> those rules and gives a match-then-exclude fallback; use it when a lookahead
> pattern errors or returns nothing.

#### Module 1: SECRETS (Critical Priority)
Scan for hardcoded API keys, tokens, private keys, credentials, database
connection strings, and committed secret files. See patterns.md **Section 1**.

Also check:
- Whether `.env` files exist in the repo (they should be gitignored)
- Whether `.gitignore` covers `.env*`, `*.pem`, `*.key`, `*.p12`, `credentials*.json`
- Whether any `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks` files are present

#### Module 2: INJECTION (Critical Priority)
Scan for SQL injection, XSS, command injection, SSRF, insecure deserialization,
path traversal, and the added NoSQL / XXE / SSTI / open-redirect patterns. See
patterns.md **Section 2**.

#### Module 3: AUTH (High Priority)
Scan for JWT misuse, weak password handling, insecure session config, and
broken access control. See patterns.md **Section 3**.

#### Module 4: CONFIG (High Priority)
Scan for CORS misconfiguration, missing security headers, exposed debug
endpoints, insecure TLS, Docker issues, and Kubernetes/Terraform misconfig. See
patterns.md **Section 4**.

#### Module 5: DEPS (High Priority)
Check dependencies for known-vulnerable and risky packages. Maps to OWASP A06
(Vulnerable & Outdated Components).

- **Native advisory scanners (preferred, when installed).** If the stack's tool
  is on `PATH`, run it read-only via `Bash` and parse its output, preferring
  JSON: `npm audit --json` / `pnpm audit --json`, `pip-audit -f json`,
  `osv-scanner -r --format json .`, `govulncheck ./...`, `bundler-audit check`,
  `cargo audit`. Use whichever matches the detected stack; skip silently if the
  tool is absent.
- **Manifest heuristics (always).** Missing lockfile alongside a manifest;
  suspicious install scripts in `package.json` (`preinstall`/`postinstall`
  running `curl`/`wget`/`bash`); dependencies pinned to `latest`; obviously
  deprecated or abandoned packages.

#### Module 6: AI (High Priority)
Scan for AI-specific issues: hardcoded AI API keys, prompt-injection vectors,
eval/exec of LLM output, system-prompt leakage, excessive agent permissions,
and dangerous LLM-framework sinks. See patterns.md **Section 5**.

#### Module 7: MOBILE (High Priority — only if Android/iOS/Flutter detected)
Scan for insecure data storage, missing certificate pinning, cleartext
traffic, debug flags, and weak crypto. See patterns.md **Section 6**.

#### Module 8: DATA (Medium Priority)
Scan for PII in logs, sensitive data in URLs, plaintext HTTP to external hosts,
weak cryptography, and information-leaking error handling. See patterns.md
**Section 7**.

> Performance (optional): on a large codebase, the independent modules may be
> dispatched as parallel subagents with the `Task` tool — one per module — each
> returning its findings to be merged and triaged in Step 3. Keep each subagent
> read-only.

### Step 3: Triage and Analyze

Raw grep hits are not findings yet. Before reporting, run every match through
this triage pass, in order, so the report contains real, de-duplicated,
correctly-rated issues instead of noise:

1. **Drop vendored and generated matches.** Discard anything under the skipped
   directories or in lock/generated files that slipped through.
2. **Read ambiguous matches for context.** When a match's risk isn't clear from
   the line alone, use `Read` on the surrounding code before rating it — a
   `pickle.load()` in a test fixture is far lower risk than one in a request
   handler.
3. **Suppress or downgrade false positives.** Matches that are clearly benign
   (comments, examples, documentation, test data) become `[INFO]` rather than a
   high-severity flag.
4. **Adjust for framework protections.** Lower severity where the framework
   already mitigates the issue (e.g. Django ORM parameterizes queries, React
   escapes output by default, Angular sanitizes `innerHTML`).
5. **Normalize severity.** Rate every surviving finding against the rubric in
   patterns.md Appendix B, and set its `Ref` from the OWASP/CWE mapping in
   Appendix A, so severities stay consistent across runs.
6. **Deduplicate.** Collapse repeated matches of the same pattern into one
   finding with an occurrence count and a few representative locations, rather
   than one entry per line (e.g. `console.log(req.body)` across 20 files is a
   single finding).

Then **analyze** the triaged set to produce the report's synthesis: the three
highest-impact issues to fix first (with reasoning), the security practices the
project is doing well, and any general hardening recommendations not tied to a
specific finding. These feed the matching sections of Step 4.

### Step 4: Generate Report

After triage and analysis, produce a structured report.

#### Report Format

Start with a summary banner:

```
============================================
  SECURITY SCAN REPORT
  Project:    <project name>
  Scanned:    <date>
  Scope:      <scope run>
  Path:       <path scanned>
  Tech Stack: <detected stacks>
============================================

SUMMARY
  CRITICAL: <count>
  HIGH:     <count>
  MEDIUM:   <count>
  LOW:      <count>
  INFO:     <count>
  TOTAL:    <count>
============================================
```

Then list findings grouped by severity (CRITICAL first), with this format for
each:

```
[SEVERITY] CATEGORY — Finding Title
  File: path/to/file.ext:line_number
  Evidence: <matching snippet, max 2 lines — secret values masked per Safety and scope>
  Risk: <1-sentence explanation of the attack scenario>
  Fix: <specific remediation with code example>
  Ref: <CWE or OWASP reference>
```

#### After the findings, include:

1. **Top 3 Priorities** — The 3 most impactful issues to fix first, with reasoning.
2. **Positive Findings** — Security practices the project is doing well (e.g., using parameterized queries, proper `.gitignore`, CSP headers present).
3. **Recommendations** — General security improvements not tied to a specific finding.

If a module found nothing, say so explicitly rather than omitting it — a clean
result is still a result, and it tells the user that area was checked.

### Important Guidelines

The triage pass in Step 3 is where false-positive suppression, context reading,
framework-aware severity, and deduplication happen. These cross-cutting rules
apply throughout every step:

- **Skip vendored/generated code**: Do not flag issues in `node_modules/`,
  `vendor/`, generated files, or lock files — during scanning as well as triage.
- **Be framework-aware**: Many frameworks have built-in protections (e.g.,
  Django ORM prevents SQL injection, React escapes by default, Angular
  sanitizes `innerHTML`). Keep this in mind when scanning and when rating
  severity in Step 3.
- **Report, don't fix**: Produce findings only. Do not edit, patch, or refactor
  code as part of the scan; leave remediation to the user.
