# Security Scan Pattern Library

*SAST regex ruleset: secrets, injection, auth, config, AI, mobile, data exposure*

---

**Purpose.** This is a *defensive* static-analysis (SAST) ruleset — regexes that flag leaked secrets and risky code so an owner can remediate them. Patterns are detection signatures, not exploits.

> **⚠ Regex-engine compatibility — read before running.**
> Several patterns use negative lookahead `(?!...)`. This works in PCRE/PCRE2, Python `re`, and JavaScript, but **silently fails in RE2-based engines** (Go `regexp`, ripgrep's default engine, Rust `regex`). If your scanner uses any of those, those rules will either error or match nothing. Affected rules: **2.5** (yaml.load), **7.3** (plaintext HTTP to external hosts), **6.3** (Flutter cleartext). Either run ripgrep with `--pcre2`, or use the RE2-safe alternatives noted inline. The full inventory is in **Appendix B**.

> **Legend.** `[NOTE]` = guidance only.

> **Copy-safety note (Markdown specifics).** Every regex lives inside a code span (`` `like this` ``) or a fenced code block, so backslashes, `*`, `_`, `{`, `<`, etc. are all literal — copy a pattern exactly as shown and it will work. One Markdown rule to know: a literal `|` cannot sit inside a table cell (it is the column separator), so any pattern that uses alternation (`a|b`) is shown in a **code block**, never a table. A `\|` *inside a fenced code block* is intentional — it matches a literal pipe (e.g. a shell `curl | sh`) and must be kept as written.

---

## Section 1: SECRETS

### 1.1 High-Confidence API Keys (Specific Formats)

These have distinctive prefixes/formats with very low false-positive rates.

| Secret Type | Regex | Severity |
|---|---|---|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` | CRITICAL |
| AWS Temporary Key | `ASIA[0-9A-Z]{16}` | CRITICAL |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` | CRITICAL |
| GitHub OAuth | `gho_[A-Za-z0-9]{36}` | CRITICAL |
| GitHub App | `ghu_[A-Za-z0-9]{36}` | CRITICAL |
| GitHub Server | `ghs_[A-Za-z0-9]{36}` | CRITICAL |
| GitHub Refresh | `ghr_[A-Za-z0-9]{36}` | CRITICAL |
| Slack Bot Token | `xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}` | CRITICAL |
| Slack User Token | `xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32}` | CRITICAL |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` | HIGH |
| Stripe Live Secret | `sk_live_[0-9a-zA-Z]{24,}` | CRITICAL |
| Stripe Live Pub | `pk_live_[0-9a-zA-Z]{24,}` | LOW |
| Stripe Restricted | `rk_live_[0-9a-zA-Z]{24,}` | CRITICAL |
| SendGrid Key | `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}` | CRITICAL |
| Twilio API Key | `SK[0-9a-fA-F]{32}` | HIGH |
| Square Access | `sq0atp-[0-9A-Za-z\-_]{22}` | CRITICAL |
| Square OAuth | `sq0csp-[0-9A-Za-z\-_]{43}` | CRITICAL |
| Mailgun Key | `key-[0-9a-zA-Z]{32}` | HIGH |
| npm Token | `npm_[A-Za-z0-9]{36}` | CRITICAL |
| PyPI Token | `pypi-[A-Za-z0-9_-]{50,}` | CRITICAL |
| Shopify Access | `shpat_[a-fA-F0-9]{32}` | HIGH |
| Discord Bot | `[MNO][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38}` | CRITICAL |
| Facebook Token | `EAACEdEose0cBA[0-9A-Za-z]+` | HIGH |
| OpenAI Key | `sk-[A-Za-z0-9]{20,}` | CRITICAL |
| OpenAI Project Key | `sk-proj-[A-Za-z0-9\-_]{40,}` | CRITICAL |
| OpenAI Service Acct | `sk-svcacct-[A-Za-z0-9\-_]{40,}` | CRITICAL |
| Anthropic Key | `sk-ant-[A-Za-z0-9\-_]{40,}` | CRITICAL |
| HuggingFace Token | `hf_[A-Za-z0-9]{34}` | HIGH |
| GitLab PAT | `glpat-[0-9A-Za-z\-_]{20}` | CRITICAL |
| GitHub fine-grained PAT | `github_pat_[0-9A-Za-z_]{82}` | CRITICAL |
| Google OAuth access token | `ya29\.[0-9A-Za-z\-_]+` | HIGH |
| AWS Secret Access Key (contextual) | `aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+]{40}` | CRITICAL |
| Azure Storage key | `AccountKey\s*=\s*[A-Za-z0-9+/]{86}==` | CRITICAL |
| Azure SAS token | `sig=[A-Za-z0-9%]{43,}%3D` | HIGH |
| Telegram Bot Token | `[0-9]{8,10}:[A-Za-z0-9_-]{35}` | HIGH |
| DigitalOcean PAT | `dop_v1_[a-f0-9]{64}` | CRITICAL |
| Cloudflare API token | `[A-Za-z0-9_-]{40}` (context: `CF_API_TOKEN`) | HIGH |
| Notion integration token | `secret_[A-Za-z0-9]{43}` | HIGH |
| Stripe webhook secret | `whsec_[A-Za-z0-9]{32,}` | HIGH |
| Twilio Account SID | `AC[0-9a-fA-F]{32}` | MEDIUM |
| Raw JWT literal | `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` | MEDIUM |

**Webhook URLs** — severity HIGH. The Discord pattern uses a literal `|` (alternation), so both are shown here in a code block rather than a table cell, keeping the pipe intact:

```
Slack:   https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+
Discord: https://(canary\.|ptb\.)?discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+
```

### 1.2 Private Keys

Search for these exact strings. Severity: CRITICAL.

```
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN DSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
-----BEGIN PRIVATE KEY-----
-----BEGIN ENCRYPTED PRIVATE KEY-----
PuTTY-User-Key-File-                  # .ppk
```

### 1.3 Database Connection Strings

| Type | Regex | Severity |
|---|---|---|
| PostgreSQL | `postgres(ql)?://[^:]+:[^@]+@[^\s]+` | CRITICAL |
| MySQL | `mysql://[^:]+:[^@]+@[^\s]+` | CRITICAL |
| MongoDB | `mongodb(\+srv)?://[^:]+:[^@]+@[^\s]+` | CRITICAL |
| Redis (auth) | `redis://:[^@]+@[^\s]+` | CRITICAL |
| MSSQL | `Server=.*Password=` | CRITICAL |
| JDBC | `jdbc:\w+://[^:]+:[^@]+@` | CRITICAL |
| AMQP / RabbitMQ | `amqp://[^:]+:[^@]+@[^\s]+` | CRITICAL |
| Generic driver URI | `\w+://[^:/\s]+:[^@/\s]+@[^\s/]+` | HIGH |

### 1.4 Generic Secret Patterns (Context-Dependent)

Use these with contextual keywords. Medium confidence — verify with `Read` before flagging as HIGH.

```
(api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9]{16,}["']
(secret[_-]?key|secretkey)\s*[:=]\s*["'][A-Za-z0-9]{16,}["']
(access[_-]?token|accesstoken)\s*[:=]\s*["'][A-Za-z0-9]{16,}["']
(client[_-]?secret|clientsecret)\s*[:=]\s*["'][A-Za-z0-9]{16,}["']
(encryption[_-]?key|encryptionkey)\s*[:=]\s*["'][A-Za-z0-9]{16,}["']
(jwt[_-]?secret|JWT_SECRET)\s*[:=]\s*["'][^"']{8,}["']
(auth[_-]?token|bearer)\s*[:=]\s*["'][A-Za-z0-9._\-]{20,}["']
(password|passwd|pwd)\s*[:=]\s*["'][^"'\s]{6,}["']
```

### 1.5 Password in URL

```
[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}
```

### 1.6 Env Fallback with Hardcoded Default

```
(os\.environ|process\.env|ENV)\[?.*\]?\s*\|\|\s*["'][A-Za-z0-9]{16,}
\.get\s*\(\s*["']\w+["']\s*,\s*["'][A-Za-z0-9]{16,}["']\)
getenv\s*\(\s*["']\w+["']\s*,\s*["'][A-Za-z0-9]{16,}["']\)
```

### 1.7 Files That Should Never Be Committed

Check for existence of these via Glob:
```
**/.env
**/.env.local
**/.env.production
**/.env.staging
**/*.pem
**/*.key
**/*.p12
**/*.pfx
**/*.jks
**/*.keystore
**/id_rsa
**/id_dsa
**/id_ecdsa
**/id_ed25519
**/.netrc
**/.htpasswd
**/.pgpass
**/credentials.json
**/service-account*.json
**/.dockercfg
**/.aws/credentials
**/.git-credentials
**/terraform.tfstate         # (state files embed plaintext secrets)
**/terraform.tfstate.backup
**/*.ppk                     # PuTTY private key
**/*.ovpn                    # OpenVPN profile (may embed keys)
**/wp-config.php             # WordPress DB creds
**/secrets.yml
**/secrets.yaml
**/*.kdbx                    # KeePass DB
```

---

## Section 2: INJECTION

### 2.1 SQL Injection

File types: `*.py, *.js, *.ts, *.java, *.php, *.rb, *.go, *.cs`

**Python:**
```
(execute|executemany)\s*\(\s*f["']
(execute|executemany)\s*\(.*\.format\(
(execute|executemany)\s*\(.*%\s*\(?                # %-formatting
(raw|extra)\(.*%s.*%
```

**JavaScript/TypeScript:**
```
(query|execute)\s*\(\s*['"`].*\+\s*
(query|execute)\s*\(\s*`.*\$\{
\.raw\s*\(\s*`.*\$\{
sequelize\.query\s*\(\s*`.*\$\{
```

**Java:**
```
(executeQuery|executeUpdate|execute)\s*\(.*\+
Statement.*execute.*\+
createQuery\(.*\+
```

**C# / .NET** (was missing despite `*.cs` in scope):
```
new\s+SqlCommand\s*\(\s*\$?["'].*\+
new\s+SqlCommand\s*\(\s*\$["'].*\{
CommandText\s*=\s*\$?["'].*\+
FromSqlRaw\s*\(\s*\$?["'].*(\+|\{)
ExecuteSqlRaw\s*\(\s*\$?["'].*(\+|\{)
```

**PHP:**
```
(mysql_query|mysqli_query)\s*\(.*\$
```

**Go:**
```
(Query|Exec|QueryRow)\(.*fmt\.Sprintf
```

### 2.2 Cross-Site Scripting (XSS)

File types: `*.js, *.ts, *.jsx, *.tsx, *.vue, *.html, *.php, *.erb, *.ejs`

```
\.innerHTML\s*=
\.outerHTML\s*=
document\.write\s*\(
document\.writeln\s*\(
dangerouslySetInnerHTML
v-html\s*=
bypassSecurityTrust
\{\{\{.*\}\}\}
\{!!.*!!\}
\|safe
<%\-.*%>
html_safe
\.insertAdjacentHTML\s*\(
\$\(.*\)\.(html|append|prepend)\s*\( #  jQuery sinks
(location|location\.href)\s*=\s*.*(req|request|params|query)
```

### 2.3 Command Injection

File types: `*.py, *.js, *.ts, *.java, *.rb, *.php, *.go, *.cs`

**Python:**
```
os\.system\s*\(
os\.popen\s*\(
subprocess\..*shell\s*=\s*True
commands\.(getoutput|getstatusoutput)\s*\(
```

**JavaScript/Node.js:**
```
child_process.*exec\s*\(
exec\s*\(\s*['"`].*\$\{
execSync\s*\(
eval\s*\(
new\s+Function\s*\(
```

**Java:**
```
Runtime\.getRuntime\(\)\.exec\s*\(.*\+
ProcessBuilder.*\+
```

**Ruby:**
```
system\s*\(.*\#\{
`.*\#\{
IO\.popen\s*\(
```

**PHP:**
```
(exec|system|passthru|shell_exec|popen|proc_open)\s*\(.*\$
```

**Go:**
```
exec\.Command\s*\(\s*"(sh|bash|cmd)"
exec\.Command[^)]*\+
```

**C# / .NET:**
```
Process\.Start\s*\(.*\+
ProcessStartInfo[^)]*(Arguments|FileName)\s*=\s*.*\+
```

### 2.4 SSRF

```
(fetch|axios\.\w+|http\.get|https\.get)\s*\(.*req\.(query|body|params)
requests\.(get|post|put|delete)\s*\(.*req\.(args|form|json|data)
new\s+URL\s*\(.*request\.getParameter
urllib\.request\.urlopen\s*\(.*(request|input|param)
http\.Get\s*\(.*(r\.URL|request|param)                 # Go
```

### 2.5 Insecure Deserialization

> `[NOTE]` The `yaml.load` rule below uses negative lookahead — **RE2-safe rewrite in Appendix B**.

```
pickle\.(load|loads)\s*\(
yaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)
yaml\.unsafe_load\s*\(
ObjectInputStream\s*\(
BinaryFormatter
Marshal\.load\s*\(
unserialize\s*\(.*\$
TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects)   # Newtonsoft RCE
new\s+org\.yaml\.snakeyaml\.Yaml\s*\(\s*\)                    # SnakeYAML default
JSON\.parseObject\s*\(.*,\s*\w+\.class                       # fastjson
jsonpickle\.decode\s*\(
```

### 2.6 Path Traversal

```
(open|readFile|readFileSync|createReadStream)\s*\(.*req\.(query|body|params)
os\.path\.join\s*\(.*request\.(GET|POST|args|form)
fs\.\w+\s*\(.*req\.(query|body|params)
new\s+File\s*\(.*request\.getParameter
(include|require|include_once|require_once)\s*\(.*\$_(GET|POST|REQUEST)
(res\.sendFile|send_file)\s*\(.*(req|request|params|query)
```

### 2.7 NoSQL Injection

File types: `*.js, *.ts, *.py`

```
\.find\s*\(\s*\{[^}]*req\.(body|query|params)
\.(findOne|updateOne|deleteOne)\s*\(\s*\{[^}]*req\.
\$where\s*:\s*.*(req|request|input)
db\.\w+\.find\s*\(\s*request\.(json|args|form)
```

### 2.8 XXE — XML External Entity

File types: `*.java, *.cs, *.py, *.php`

```
DocumentBuilderFactory(?![^;]*setFeature)          # Java, no hardening (lookahead — RE2 note)
SAXParserFactory(?![^;]*setFeature)
XMLReader(?![^;]*setFeature)
etree\.(parse|fromstring)\s*\(                      # Python lxml w/o resolve_entities=False
new\s+XmlDocument\s*\(\s*\)                         # .NET (XmlResolver not nulled)
libxml_disable_entity_loader\s*\(\s*false\s*\)      # PHP, explicitly unsafe
simplexml_load_(string|file)\s*\(.*LIBXML_NOENT     # PHP, entities enabled
```

### 2.9 SSTI — Server-Side Template Injection

File types: `*.py, *.js, *.php, *.rb`

```
render_template_string\s*\(.*(request|\+|%|f["'])   # Flask/Jinja2
Template\s*\(.*(request|input|param).*\)\.render
new\s+Function\s*\(.*\btemplate\b                   # JS template eval
\{\{.*\|.*safe.*\}\}.*(request|user)
```

### 2.10 Open Redirect

File types: `*.py, *.js, *.ts, *.java, *.php`

```
(redirect|sendRedirect)\s*\(.*(req\.(query|body|params)|request\.(args|GET|getParameter))
res\.redirect\s*\(\s*req\.
window\.location\s*=\s*.*(req|request|params|query)
header\s*\(\s*["']Location:\s*["']?\s*\.\s*\$_(GET|POST|REQUEST)
```

---

## Section 3: AUTH

### 3.1 JWT Misuse

```
algorithm.*none
jwt\.decode\(.*verify\s*=\s*False
jwt\.decode\(.*algorithms\s*=\s*\[["']none
jwt\.decode\(.*options.*ignoreExpiration.*true
jwt\.encode\(.*["'](secret|password|123|key|changeme)["']
JWT_SECRET\s*[:=]\s*["'](secret|password|changeme|key123)
localStorage\.setItem\(.*token
sessionStorage\.setItem\(.*token
verify\s*\(.*\{\s*algorithms\s*:\s*\[\s*\]\s*\}      # empty alg list
```

### 3.2 Weak Password Handling

> `[NOTE]` Overlaps with 7.4 (weak crypto). Keep one canonical rule-set and tag it to both CWE-327 and CWE-916.

```
(md5|MD5)\(.*password
(sha1|SHA1)\(.*password
sha256\(.*password
MIN_PASSWORD_LENGTH\s*=\s*[1-7]
password\s*==\s*["'][^"']+["']                       # plaintext compare
hashlib\.(md5|sha1)\s*\(
```

### 3.3 Insecure Session/Cookie Config

```
(httponly|HttpOnly)\s*[:=]\s*(false|False|0)
(secure|Secure)\s*[:=]\s*(false|False|0)
samesite\s*[:=]\s*["']none["']
```

### 3.4 Broken Access Control

```
(isAdmin|is_admin|role|userRole).*localStorage
req\.(body|query|params)\.(role|admin|isAdmin)
\.findByIdAndUpdate\(req\.params
\.findByIdAndDelete\(req\.params
@(app\.route|GetMapping|PostMapping)(?![^)]*auth)    # route w/o auth (lookahead note)
```

### 3.5 Insecure Randomness

Security tokens/IDs built from non-cryptographic RNGs. File types: `*.py, *.js, *.ts, *.java, *.go, *.php`

```
Math\.random\s*\(\s*\).*(token|secret|password|otp|nonce|session)
random\.(random|randint|choice)\s*\(.*(token|secret|password|otp|key)
new\s+Random\s*\(\s*\)                                # Java java.util.Random for security
mt_rand\s*\(|\brand\s*\(                              # PHP non-crypto
```

### 3.6 Timing-Unsafe Secret Comparison

Comparing tokens/HMACs with `==` leaks via timing. File types: `*.py, *.js, *.ts, *.java`

```
(token|hmac|signature|digest|secret)\s*==\s*
if\s+.*(token|signature|hmac).*===
\.equals\s*\(.*(token|signature|hmac)                 # use constant-time compare instead
```

---

## Section 4: CONFIG

### 4.1 CORS Misconfiguration

```
Access-Control-Allow-Origin.*\*
(cors|CORS).*origin.*\*
(cors|CORS).*origin.*true
CORS_ALLOW_ALL_ORIGINS\s*=\s*True
CORS_ORIGIN_ALLOW_ALL\s*=\s*True
cors\(\)
@CrossOrigin
Access-Control-Allow-Credentials.*true               # dangerous with wildcard origin
```

### 4.2 Debug Mode Enabled

```
DEBUG\s*=\s*True
app\.debug\s*=\s*True
FLASK_DEBUG\s*=\s*1
FLASK_ENV\s*=\s*development
android:debuggable="true"
consider_all_requests_local\s*=\s*true               # Rails
NODE_ENV\s*[:=]\s*["']?development
```

### 4.3 Dangerous CSP/Headers

```
Content-Security-Policy.*unsafe-inline
Content-Security-Policy.*unsafe-eval
X-Frame-Options.*ALLOWALL
Content-Security-Policy.*\*                            # wildcard source
```

### 4.4 Exposed Debug/Admin Endpoints

```
(route|path|get|post)\s*\(\s*["']/?(debug|_debug|phpinfo|server-info|server-status)
/actuator
/graphiql
/swagger|/api-docs
/h2-console
/actuator/env|/actuator/heapdump   # (secret/heap exposure)
/\.git/                     # exposed VCS
/console|/_debug_toolbar
```

### 4.5 Insecure TLS

```
verify\s*=\s*False
CERT_NONE
rejectUnauthorized\s*[:=]\s*false
InsecureSkipVerify\s*[:=]\s*true
TrustAllCerts|AllowAllHostnames
(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)
ssl\._create_unverified_context\s*\(       # Python
```

### 4.6 Docker Security

File types: `Dockerfile, docker-compose.yml, docker-compose.yaml`

```
FROM.*:latest
USER\s+root
RUN.*chmod\s+777
COPY.*\.env
(ARG|ENV).*(PASSWORD|SECRET|KEY|TOKEN)
--privileged
RUN.*(curl|wget).*\|.*sh
EXPOSE\s+(22|23|3389|5900)\b
ADD\s+https?://                              # remote ADD over network
```

### 4.7 Kubernetes / Terraform

File types: `*.yaml, *.yml, *.tf, *.hcl`

```
privileged:\s*true
hostNetwork:\s*true
hostPID:\s*true
allowPrivilegeEscalation:\s*true
runAsUser:\s*0
(acl|access)\s*=\s*["']public
cidr_blocks\s*=\s*\[["']0\.0\.0\.0/0["']\]
automountServiceAccountToken:\s*true
readOnlyRootFilesystem:\s*false
acl\s*=\s*["']public-read                     # public S3 bucket
(encrypted|storage_encrypted)\s*=\s*false     # unencrypted volume/RDS
```

---

## Section 5: AI-SPECIFIC

> `[NOTE]` Mapped to the **OWASP Top 10 for LLM Applications (2025)**: 5.2 → LLM01 Prompt Injection · 5.3 → LLM05 Improper Output Handling · 5.4/5.5 → LLM06 Excessive Agency.

### 5.1 Hardcoded AI API Keys

```
openai\.api_key\s*=\s*["']sk-
anthropic\.api_key\s*=\s*["']sk-ant-
(OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*[:=]\s*["']sk-
(HUGGING_FACE_TOKEN|HF_TOKEN)\s*[:=]\s*["']hf_
```

### 5.2 Prompt Injection Vectors

```
f["'].*system.*\{.*user_input
f["'].*\{.*request\.(body|query|params)
(messages|prompt).*\+\s*.*input
```

### 5.3 Executing LLM Output

```
eval\(.*completion|response|output|result.*\)
exec\(.*completion|response|output|result.*\)
innerHTML.*completion|response|output
subprocess\..*(completion|response|output|llm_)
```

### 5.4 Excessive Agent Permissions

```
(tools|functions).*\b(exec|eval|system|rm|delete|drop|sudo)\b
```

### 5.5 Dangerous LLM-Framework Sinks

File types: `*.py, *.js, *.ts`

```
PythonREPLTool|PythonAstREPLTool
\bShellTool\b|load_tools\(\s*\[[^]]*shell
\bPALChain\b|\bLLMMathChain\b
allow_dangerous_code\s*=\s*True
allow_dangerous_deserialization\s*=\s*True
create_pandas_dataframe_agent        # executes arbitrary code by design
```

---

## Section 6: MOBILE

> `[NOTE]` Mapped to **OWASP Mobile Top 10 / MASVS**: 6.x cleartext → M5 Insecure Communication · insecure storage → M9 · trust-all / weak crypto → M3/M10.

### 6.1 Android

File types: `*.java, *.kt, AndroidManifest.xml, *.gradle`

```
android:usesCleartextTraffic="true"
android:allowBackup="true"
android:exported="true"
SharedPreferences.*MODE_WORLD_READABLE
SharedPreferences.*MODE_WORLD_WRITEABLE
getSharedPreferences.*(password|token|secret|key)
TrustAllCerts|AllowAllHostnames
X509TrustManager.*checkServerTrusted.*\{\s*\}
ALLOW_ALL_HOSTNAME_VERIFIER
SecureRandom.*setSeed
addJavascriptInterface\s*\(               # JS bridge RCE surface
setJavaScriptEnabled\s*\(\s*true\s*\)
setAllowFileAccess\s*\(\s*true\s*\)
<provider[^>]*android:exported="true"      # exported content provider
```

### 6.2 iOS

File types: `*.swift, *.m, *.plist`

```
NSAllowsArbitraryLoads.*true
NSExceptionAllowsInsecureHTTPLoads
NSUserDefaults.*(password|token|secret|key)
UserDefaults\.standard\.set.*(password|token|secret)
CCCrypt.*kCCAlgorithmDES
kSecAttrAccessibleAlways                   # keychain always-readable
UIPasteboard\.general.*(password|token|secret)
\.allowsArbitraryLoadsInWebContent.*true   # WKWebView ATS bypass
```

### 6.3 Flutter/Dart

File types: `*.dart`

> `[NOTE]` Second rule uses lookahead — **RE2-safe rewrite in Appendix B**.

```
SharedPreferences.*(password|token|secret|key)
http://(?!localhost|127\.0\.0\.1)
badCertificateCallback\s*=\s*\(.*=>\s*true   # accepts any cert
```

---

## Section 7: DATA EXPOSURE

### 7.1 PII in Logs

```
(log|logger|console)\.\w+\(.*password
(log|logger|console)\.\w+\(.*secret
(log|logger|console)\.\w+\(.*token
(log|logger|console)\.\w+\(.*credit.?card
(log|logger|console)\.\w+\(.*ssn
(log|logger|console)\.\w+\(.*api.?key
(log|logger|console)\.\w+\(.*req\.body
print\(.*password|token|secret|api.?key
```

### 7.2 Sensitive Data in URLs

```
\?(.*&)*(password|token|secret|api_key|apikey)=
```

### 7.3 Plaintext HTTP to External Hosts

> `[NOTE]` Uses lookahead — **RE2-safe rewrite in Appendix B**.

```
http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)
```

### 7.4 Weak Cryptography

```
(md5|sha1|MD5|SHA1)\s*[.(]
(DES|RC4|Blowfish)\b
\bECB\b
Cipher\.getInstance\s*\(\s*["']AES["']\s*\)          # defaults to ECB
IvParameterSpec\s*\(\s*["'][^"']+["']                # hardcoded IV
(salt|SALT)\s*[:=]\s*["'][^"']+["']                  # hardcoded salt
```

### 7.5 Error Handling (Information Leakage)

```
except:\s*$
except\s+Exception\s*:.*pass
catch\s*\(\s*\)\s*\{[\s]*\}
(res|response)\.(send|json)\(.*err\.(stack|message)
traceback\.(print_exc|format_exc)
printStackTrace\s*\(\s*\)                              # Java leak
```

### 7.6 Missing Subresource Integrity (SRI)

File types: `*.html, *.ejs, *.erb, *.vue`

```
<script[^>]*src=["']https?://(?!localhost)[^"']+["'](?![^>]*integrity=)
<link[^>]*href=["']https?://[^"']+\.css["'](?![^>]*integrity=)
```

---

## Appendix A — OWASP Top 10 (2021) → section map

| OWASP 2021 | Covered by |
|---|---|
| A01 Broken Access Control | 3.4, 2.10 (open redirect), 4.4 |
| A02 Cryptographic Failures | 3.2, 7.3, 7.4, 4.5, 1.x (secret exposure) |
| A03 Injection | 2.1–2.3, 2.6–2.9, 5.2 |
| A04 Insecure Design | (design-level; not regex-detectable — note in report) |
| A05 Security Misconfiguration | 4.1–4.7, 6.x, 2.8 (XXE) |
| A06 Vulnerable & Outdated Components | (needs SCA, not regex — cross-ref build plan) |
| A07 Identification & Auth Failures | 3.1, 3.3, 3.5, 3.6 |
| A08 Software & Data Integrity Failures | 2.5, 7.6 (SRI), 4.6 (piped shell install) |
| A09 Security Logging & Monitoring | 7.1, 7.5 (over/under-logging signals) |
| A10 SSRF | 2.4 |

AI → **OWASP LLM Top 10** (Section 5). Mobile → **OWASP Mobile Top 10 / MASVS** (Section 6).

## Appendix B — Engine compatibility, severity rubric & rule schema

**Lookahead inventory (fails on RE2 / Go / ripgrep-default / Rust regex).** Run `rg --pcre2`, or substitute a two-pass "match broadly, then exclude" approach. Listed (not tabled) so the literal `|` in each pattern stays intact:

- **2.5 `yaml.load`** — original: `yaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)`. RE2-safe: match every `yaml\.load\s*\(`, then drop lines containing `SafeLoader`.
- **7.3 plaintext HTTP** — original: `http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)`. RE2-safe: match `http://[A-Za-z0-9.\-]+`, then exclude loopback/private hosts in code.
- **6.3 Flutter http** — same pattern and fix as 7.3.
- **2.8 XXE (Java)** — original: `DocumentBuilderFactory(?![^;]*setFeature)`. RE2-safe: match the factory, then confirm no nearby `setFeature(...)` hardening.
- **3.4 route without auth** — original: `@app\.route(?![^)]*auth)`. RE2-safe: match routes, then cross-check against an auth-decorator allowlist.

**Severity rubric (suggested, for consistency).**

- **CRITICAL** — live credential / private key leak, or direct RCE (command injection, unsafe deserialization, SSTI).
- **HIGH** — likely-exploitable injection (SQLi, XSS, XXE, SSRF), auth bypass.
- **MEDIUM** — misconfiguration, info leak, weak crypto, open redirect.
- **LOW / INFO** — best-practice deviations, publishable keys, verbose errors.

**Recommended per-rule schema** (the current file has regex + severity; adding these three fields pays off in reporting and triage):

```yaml
- id: sqli-python-fstring
  name: "SQL query built with f-string"
  regex: '(execute|executemany)\s*\(\s*f["'']'
  severity: HIGH
  confidence: medium        # confirmed | firm | medium | low
  owasp: A03
  cwe: CWE-89
  file_types: ["*.py"]
  remediation: "Use parameterized queries / bound parameters."
```