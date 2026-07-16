# Lefthook Tools — Centralized Configuration Repository

A centralized configuration repository for providing security rules and code quality checks that can be shared across all projects.

## Overview

This repository serves as a **single source of truth** for static analysis tool configurations executed via Lefthook git hooks. With the centralized remotes approach, each project simply references this repository without needing to duplicate configurations.

**Supported languages:** Java/Spring Boot, Go

```
lefthook-tools/
├── semgrep/
│   ├── rules/
│   │   ├── java/
│   │   │   ├── sql-injection.yaml    # Taint-based SQL injection detection
│   │   │   ├── secrets.yaml          # Hardcoded credentials detection
│   │   │   ├── code-quality.yaml     # Empty catch blocks, System.out usage
│   │   │   └── README.md             # Details & examples for Java rules
│   │   └── go/
│   │       ├── sql-injection.yaml    # Taint-based SQL injection (multi-framework)
│   │       ├── secrets.yaml          # Hardcoded credentials, JWT secrets
│   │       ├── code-quality.yaml     # Ignored errors, defer in loop, etc.
│   │       └── README.md             # Details & examples for Go rules
│   └── .semgrepignore                # Path exclusions for Semgrep
├── trivy/
│   ├── trivy.yaml                    # Trivy scanner configuration
│   └── .trivyignore                  # CVE suppressions (with justification)
├── lefthook-remote.yml               # Pre-commit hook definitions
├── Installation-Guide.md
└── README.md                         # ← You are here
```

## Tools Used

| Tool | Purpose | Minimum Version |
|------|---------|-----------------|
| [Lefthook](https://github.com/evilmartians/lefthook) | Git hooks manager | v1.6+ |
| [Semgrep](https://semgrep.dev/) | Static analysis (SAST) | v1.50+ |
| [Trivy](https://trivy.dev/) | Vulnerability & secret scanner | v0.72+ |

## Quick Start

### 1. Install Prerequisites

```bash
# Lefthook
winget install -e --id evilmartians.lefthook --accept-package-agreements --accept-source-agreements

# Trivy
winget install -e --id AquaSecurity.Trivy --accept-package-agreements --accept-source-agreements

# Semgrep
pip install semgrep
```

Verify installation:

```bash
lefthook version
semgrep --version
trivy --version
```

### 2. Configure in Consumer Project

Create a `lefthook.yml` file in your project root:

**Java/Spring Boot project:**

```yaml
# lefthook.yml
remotes:
  - git_url: https://github.com/ahmadzulfadli/lefthook-configuration.git
    ref: master
    configs:
      - lefthook-remote.yml
```

**Go project:**

```yaml
# lefthook.yml
remotes:
  - git_url: https://github.com/ahmadzulfadli/lefthook-configuration.git
    ref: master
    configs:
      - lefthook-remote.yml
```

> Both Java and Go projects use the same remote configuration. The scanner automatically detects and applies rules based on file extensions (`*.java`, `*.go`, etc.).

### 3. Activate in Consumer Project

```bash
cd /path/to/your-project

# Install hooks
lefthook install

# Test run
lefthook run pre-commit
```

### Clear Cache (if needed)

```bash
Remove-Item -Recurse -Force .git\info\lefthook-remotes
Remove-Item -Force .git\info\lefthook.checksum
lefthook install
```

## Semgrep Rules

### Java/Spring Boot Rules

#### Security Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `tainted-sql-injection` | ERROR | Taint analysis: tracks data flow from `@RequestParam`, `@PathVariable`, `@RequestBody`, etc. to SQL sinks (JDBC, JPA, JdbcTemplate) |
| `spring-data-raw-native-query` | ERROR | Detects string concatenation in `@Query(nativeQuery = true)` |
| `java-hardcoded-password` | ERROR | Java variables containing credential keywords with hardcoded values |
| `spring-hardcoded-credential-properties` | ERROR | Hardcoded credentials in `application.properties` / `application.yml` |

#### Code Quality Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `java-empty-catch-block` | ERROR | Empty catch block — silent failures (CWE-390) |
| `java-use-logger-not-sysout` | ERROR | `System.out.println` / `printStackTrace` → use SLF4J instead |

> Full details and valid/invalid examples: see [`semgrep/rules/java/README.md`](semgrep/rules/java/README.md)

---

### Go Rules

#### Security Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `go-tainted-sql-injection` | ERROR | Taint analysis: tracks data flow from HTTP input (net/http, Gin, Echo, Fiber, mux, chi) to SQL sinks (database/sql, sqlx, GORM) |
| `go-sql-string-formatting` | ERROR | Detects `fmt.Sprintf` used directly inside SQL function calls |
| `go-hardcoded-credential` | ERROR | Go variables containing credential keywords with hardcoded values |
| `go-hardcoded-credential-in-func` | ERROR | Hardcoded connection strings in `sql.Open`, `sqlx.Connect`, `redis.NewClient`, etc. |
| `go-hardcoded-jwt-secret` | ERROR | JWT signing key hardcoded in source code |

#### Code Quality Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `go-ignored-error` | ERROR | Error ignored using blank identifier `_` (CWE-390) |
| `go-use-structured-logger` | ERROR | `fmt.Println` / `log.Printf` → use structured logger (slog, zerolog, zap) |
| `go-defer-in-loop` | ERROR | `defer` inside loop causes resource leak (CWE-404) |
| `go-goroutine-without-recover` | ERROR | Goroutine without `recover()` — panic crashes entire program (CWE-248) |
| `go-context-background-in-handler` | ERROR | `context.Background()` in HTTP handler — should use request context |

> Full details and valid/invalid examples: see [`semgrep/rules/go/README.md`](semgrep/rules/go/README.md)

## Trivy Configuration

Trivy configuration (`trivy/trivy.yaml`) is set up for:

- **Severity filter:** Only `HIGH` and `CRITICAL`
- **Scanners:** `vuln` (CVE) and `secret` (leaked credentials)
- **Package types:** OS packages and library dependencies
- **Exit code:** `1` (fail build if issues are found)
- **Skip directories:**
  - Common: `.idea`, `.vscode`, `.github`, `.git`, `node_modules`
  - Java: `.mvn`, `target/classes`, `target/test-classes`, `loadtests`
  - Go: `vendor`, `bin`, `dist`, `testdata`, `mocks`
- **Skip files:** `mvnw`, `mvnw.cmd`, `Dockerfile`, `*.pb.go`, `*_generated.go`, `mock_*.go`

### .trivyignore

The `.trivyignore` file is used to suppress CVEs that have been reviewed. Each entry **must** include:
- Ticket/issue reference
- Justification for the suppression

Format:
```
CVE-XXXX-XXXXX  # [TICKET-123] Justification: reason for ignoring
```

## Architecture: How Lefthook Remotes Work

```
┌─────────────────────────────────────────────────────────┐
│  Project A (Java/Spring Boot)                           │
│  lefthook.yml → remotes: lefthook-tools.git             │
└────────────────────────┬────────────────────────────────┘
                         │
┌─────────────────────────────────────────────────────────┐
│  Project B (Go microservice)                            │
│  lefthook.yml → remotes: lefthook-tools.git             │
└────────────────────────┬────────────────────────────────┘
                         │
┌─────────────────────────────────────────────────────────┐
│  Project C (Java/Spring Boot)                           │
│  lefthook.yml → remotes: lefthook-tools.git             │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  lefthook-tools (This repository)                       │
│  ┌───────────┐  ┌─────────────────────────────────────┐ │
│  │   Trivy   │  │         Semgrep Rules               │ │
│  │  config   │  │  ┌──────────┐  ┌────────────────┐  │ │
│  │           │  │  │   Java   │  │       Go       │  │ │
│  │           │  │  │  6 rules │  │   10 rules     │  │ │
│  └───────────┘  │  └──────────┘  └────────────────┘  │ │
│                 └─────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Benefits:**
- **Consistency** — All projects (Java & Go) use the same quality standards
- **Single update** — Update rules in one place, automatically applied to all projects
- **Versioning** — Use `ref: v1.0.0` to pin a specific version
- **Multi-language** — One remote config handles both Java and Go scanning
- **Enforcement** — Git hooks ensure code is scanned before commit

## How It Works

The `lefthook-remote.yml` defines two pre-commit commands that run in parallel:

1. **Semgrep** — Scans staged files matching `*.{java,go,xml,yml,yaml,properties,mod,sum}` using all rules in `semgrep/rules/` (both `java/` and `go/` subfolders). Only reports findings with `ERROR` severity.

2. **Trivy** — Scans the entire project filesystem for vulnerabilities in dependencies (`pom.xml`, `go.sum`, etc.) and leaked secrets. Uses configuration from `trivy/trivy.yaml`.

Both commands must pass (exit code 0) for the commit to proceed.

## Contributing

1. Add new rules in the appropriate language folder (`semgrep/rules/java/` or `semgrep/rules/go/`)
2. Include complete metadata (CWE, OWASP, confidence, likelihood, impact)
3. Update the language-specific README (`semgrep/rules/<lang>/README.md`) with valid/invalid examples
4. Test rules against sample code before merging
5. To add a new language, create a new subfolder under `semgrep/rules/` and update `.semgrepignore`

## References

- [Lefthook — Remotes Configuration](https://github.com/evilmartians/lefthook/blob/master/docs/configuration.md#remotes)
- [Semgrep Rule Syntax](https://semgrep.dev/docs/writing-rules/rule-syntax/)
- [Semgrep Taint Mode](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/)
- [Trivy Configuration](https://trivy.dev/latest/docs/references/configuration/config-file/)
- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)
