# Security Policy

## Overview

This repository is part of a personal cybersecurity research portfolio maintained by
**Lori Murray, Ph.D., CISSP, GCIA** ([@Lamurrz](https://github.com/Lamurrz)).

The tools and pipelines here are developed for **defensive security research**,
detection engineering, and agentic security automation. Security is treated as a
first-class concern — not an afterthought.

---

## Supported Versions

This is a research portfolio. The latest commit on `main` is the actively
maintained version. Older commits are preserved for reference but are not
patched or supported.

| Branch / Tag | Supported |
|---|---|
| `main` (latest) | ✅ Active |
| Prior commits | ❌ Not patched |

---

## Reporting a Vulnerability

If you discover a security vulnerability in this repository — including issues
in dependencies, workflow configurations, or the code itself — please report it
responsibly.

### Preferred Method: GitHub Private Vulnerability Reporting

1. Navigate to the **Security** tab of this repository
2. Click **"Report a vulnerability"**
3. Fill out the advisory form with as much detail as possible

This keeps the disclosure private until a fix is in place.

### What to Include in Your Report

To help triage efficiently, please provide:

- **Description** — what the vulnerability is and where it exists
- **Impact** — what an attacker could do if it were exploited
- **Reproduction steps** — how to trigger or verify the issue
- **Suggested fix** (optional but appreciated)
- **Your contact info** (optional — anonymous reports are accepted)

---

## Response Commitment

| Milestone | Target Timeframe |
|---|---|
| Acknowledgment of report | Within **72 hours** |
| Initial triage and severity assessment | Within **7 days** |
| Fix or mitigation published | Within **30 days** for high/critical findings |
| Public disclosure (coordinated) | After fix is available |

---

## Scope

### In Scope
- Vulnerabilities in Python code within this repository
- Insecure GitHub Actions workflow configurations
- Hardcoded secrets or credential exposure
- Dependency vulnerabilities with exploit potential
- Logic flaws in detection or analysis pipelines

### Out of Scope
- Vulnerabilities in third-party dependencies (report these upstream)
- Social engineering or phishing attempts
- Issues requiring physical access
- Theoretical vulnerabilities without a realistic attack path

---

## Security Controls in This Repository

This repo is configured with the following GitHub-native security controls:

- ✅ **CodeQL** — automated static analysis on every push and weekly schedule
- ✅ **Dependabot alerts** — monitors dependencies for known CVEs
- ✅ **Dependabot security updates** — auto-opens PRs for vulnerable packages
- ✅ **Secret scanning** — detects accidentally committed credentials
- ✅ **Push protection** — blocks commits containing detected secrets
- ✅ **Malware alerts** — flags known-malicious packages in the dependency graph

---

## Safe Harbor

This repository does not host production services or user data. Research
conducted here follows responsible disclosure principles and applicable laws.
Good-faith security research and vulnerability reporting are welcomed and
appreciated.

---

*Last updated: June 2026*
