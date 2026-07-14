# Lefthook Tools — Centralized Configuration Repository

A centralized configuration repository for providing security rules and code quality checks that can be shared across all projects.

## Overview

This repository serves as a **single source of truth** for static analysis tool configurations executed via Lefthook git hooks. With the centralized remotes approach, each project simply references this repository without needing to duplicate configurations.

```
lefthook-tools/
├── semgrep/
│   ├── rules/
│   │   ├── sql-injection.yaml    # Taint-based SQL injection detection
│   │   ├── secrets.yaml          # Hardcoded credentials detection
│   │   ├── code-quality.yaml     # Empty catch blocks, System.out usage
│   │   └── README.md             # Details & examples for each rule
│   └── .semgrepignore            # Path exclusions for Semgrep
├── trivy/
│   ├── trivy.yaml                # Trivy scanner configuration
│   └── .trivyignore              # CVE suppressions (with justification)
├── Installation-Guide.md
└── README.md                     # ← You are here
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

Create a `lefthook.yml` file in your Java/Spring Boot project root:

```yaml
# lefthook.yml
remotes:
  - git_url: https://github.com/<org>/lefthook-tools.git
    ref: main
    configs:
      - lefthook-remote.yml
```

> **Note:** Replace `<org>` with the GitHub organization/user hosting this repository.

### 3. Create Remote Config

Create a `lefthook-remote.yml` file in the root of this repository (the file referenced by consumers):

```yaml
# lefthook-remote.yml
pre-commit:
  commands:
    semgrep-security:
      glob: "*.java"
      run: >
        semgrep
        --config {remote}/semgrep/rules/sql-injection.yaml
        --config {remote}/semgrep/rules/secrets.yaml
        --error
        --no-git-ignore
        {staged_files}
      stage_fixed: true

    semgrep-quality:
      glob: "*.java"
      run: >
        semgrep
        --config {remote}/semgrep/rules/code-quality.yaml
        --error
        --no-git-ignore
        {staged_files}
      stage_fixed: true

    trivy-scan:
      run: >
        trivy fs
        --config {remote}/trivy/trivy.yaml
        --ignorefile {remote}/trivy/.trivyignore
        .
```

### 4. Activate in Consumer Project

```bash
cd /path/to/your-java-project

# Install hooks
lefthook install

# Test run
lefthook run pre-commit
```

## Semgrep Rules

### Security Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `tainted-sql-injection` | ERROR | Taint analysis: tracks data flow from `@RequestParam`, `@PathVariable`, `@RequestBody`, etc. to SQL sinks |
| `spring-data-raw-native-query` | ERROR | Detects string concatenation in `@Query(nativeQuery = true)` |
| `java-hardcoded-password` | ERROR | Java variables containing credential keywords with hardcoded values |
| `spring-hardcoded-credential-properties` | WARNING | Hardcoded credentials in `application.properties` / `application.yml` |

### Code Quality Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `java-empty-catch-block` | WARNING | Empty catch block (CWE-390) |
| `java-use-logger-not-sysout` | WARNING | `System.out.println` / `printStackTrace` → use SLF4J instead |

> Full details and valid/invalid examples: see [`semgrep/rules/README.md`](semgrep/rules/README.md)

## Trivy Configuration

Trivy configuration (`trivy/trivy.yaml`) is set up for:

- **Severity filter:** Only `HIGH` and `CRITICAL`
- **Scanners:** `vuln` (CVE) and `secret` (leaked credentials)
- **Package types:** OS packages and library dependencies
- **Exit code:** `1` (fail build if issues are found)
- **Skip:** IDE files, build artifacts, test classes, load tests

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
│  Project B (Java/Spring Boot)                           │
│  lefthook.yml → remotes: lefthook-tools.git             │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  lefthook-tools (This repository)                       │
│  ┌───────────┐  ┌─────────────────┐                    │
│  │   Trivy   │  │    Semgrep      │                    │
│  │  config   │  │  custom rules   │                    │
│  └───────────┘  └─────────────────┘                    │
└─────────────────────────────────────────────────────────┘
```

**Benefits:**
- **Consistency** — All projects use the same rules
- **Single update** — Update rules in one place, automatically applied to all projects
- **Versioning** — Use `ref: v1.0.0` to pin a specific version
- **Enforcement** — Git hooks ensure code is scanned before commit

## Manual Usage (Without Lefthook)

To run tools directly:

```bash
# Semgrep - all rules
semgrep --config semgrep/rules/ /path/to/project

# Semgrep - specific rule
semgrep --config semgrep/rules/sql-injection.yaml /path/to/project

# Trivy - filesystem scan
trivy fs --config trivy/trivy.yaml --ignorefile trivy/.trivyignore /path/to/project
```

## Customization

### Project-Level Override

Consumer projects can add local rules or override behavior:

```yaml
# lefthook.yml (in consumer project)
remotes:
  - git_url: https://github.com/<org>/lefthook-tools.git
    ref: main
    configs:
      - lefthook-remote.yml

pre-commit:
  commands:
    # Additional local rule
    semgrep-local:
      glob: "*.java"
      run: semgrep --config .semgrep/local-rules.yaml --error {staged_files}
```

### Pin Version

For production stability, pin to a specific tag/commit:

```yaml
remotes:
  - git_url: https://github.com/<org>/lefthook-tools.git
    ref: v1.0.0  # or commit SHA
    configs:
      - lefthook-remote.yml
```

## Contributing

1. Add new rules in the appropriate folder (`semgrep/rules/` or `trivy/`)
2. Include complete metadata (CWE, OWASP, confidence)
3. Update documentation in `semgrep/rules/README.md` with valid/invalid examples
4. Test rules against sample code before merging

## References

- [Lefthook — Remotes Configuration](https://github.com/evilmartians/lefthook/blob/master/docs/configuration.md#remotes)
- [Semgrep Rule Syntax](https://semgrep.dev/docs/writing-rules/rule-syntax/)
- [Semgrep Taint Mode](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/)
- [Trivy Configuration](https://trivy.dev/latest/docs/references/configuration/config-file/)
- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)
