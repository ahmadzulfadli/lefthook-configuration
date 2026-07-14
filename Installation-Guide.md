# Use Lefthook + Semgrep + Trivy
# How To Install

## Install Lefthook
```bash
winget install -e --id evilmartians.lefthook --accept-package-agreements --accept-source-agreements
```

## Install Trivy
```bash
winget install -e --id AquaSecurity.Trivy --accept-package-agreements --accept-source-agreements
```

## Install Semgrep
```bash
pip install semgrep
```

## Validate Installations
```bash
lefthook version
semgrep --version
trivy --version
```

# How To Use
## Java
```bash
# Create lefthook config
lefthook install

# Run pre-commit job
lefthook run pre-commit
```
