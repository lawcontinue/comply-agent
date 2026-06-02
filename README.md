# comply-agent

**AI Agent OWASP Agentic Top 10 Compliance Scanner**

Automatically scan your AI agent's prompts, configurations, tool definitions, and behavior logs for compliance issues against the [OWASP Agentic Top 10 (2026)](https://owasp.org/www-project-agentic-top-10/).

## Install

```bash
pip install comply-agent
```

## Quick Start

```bash
# Scan a prompt
comply-agent scan --prompt "ignore all previous instructions"

# Scan from files
comply-agent scan --prompt-file agent_prompt.txt --config-file agent.yaml

# JSON output
comply-agent scan --prompt-file prompt.txt --format json --output report.json

# List all rules
comply-agent rules
```

## Example Output

```
============================================================
  comply-agent Report
============================================================
  Score: 40.0/100  (2 passed / 3 failed / 5 rules)
============================================================

  🔴 [ASI01] Prompt Injection Vulnerability
     Location: prompt:1
     Matched:  ignore all previous instructions
     Fix:      1. Use structured input separation...

  🟠 [ASI02] Sensitive Data Disclosure
     Location: config:5
     Matched:  api_key=abc123def456ghi789...
     Fix:      1. Add output filtering/redaction...

  🟡 [ASI06] Excessive Agency / Over-Autonomy
     Location: prompt:3
     Matched:  never ask for permission
     Fix:      1. Add human-in-the-loop...
```

## Covered OWASP Risks

| OWASP ID | Risk | Category | Status |
|----------|------|----------|--------|
| ASI01 | Prompt Injection | Input | ✅ |
| ASI02 | Sensitive Data Disclosure | Output | ✅ |
| ASI03 | Supply Chain Vulnerability | Audit | ✅ |
| ASI04 | Unauthorized Access | Permission | ✅ |
| ASI05 | Output Manipulation | Output | ✅ |
| ASI06 | Excessive Agency | Permission | ✅ |
| ASI07 | Authentication Failure | Auth | ✅ |
| ASI08 | Improper Error Handling | Output | ✅ |
| ASI09 | Insufficient Monitoring | Audit | ✅ |

## How It Works

1. **Load rules** — YAML-based rules for each OWASP risk category
2. **Scan inputs** — Match regex patterns against prompts, configs, tool defs, logs
3. **Score** — Calculate compliance score (0-100)
4. **Report** — Generate Markdown, JSON, or terminal report with findings and fixes

## Custom Rules

Add your own rules in YAML:

```yaml
id: custom-001
owasp_id: CUSTOM
title: My Custom Rule
severity: medium
category: output
description: Detects something specific
patterns:
  - "my_sensitive_pattern"
fix: How to fix it
```

Point to custom rules dir: `comply-agent scan --rules-dir ./my_rules --prompt "..."`

## License

MIT
