"""Rule engine — load YAML rules, match against agent config/prompt/logs."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml


@dataclass
class Rule:
    id: str
    owasp_id: str
    title: str
    severity: str  # critical/high/medium/low
    description: str
    patterns: List[str]  # regex patterns to match
    fix: str  # remediation advice
    category: str = "general"  # input/permission/output/audit/auth


@dataclass
class Finding:
    rule: Rule
    matched: str
    location: str
    line: int = 0


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    total_rules: int = 0
    passed: int = 0
    failed: int = 0
    score: float = 0.0  # 0-100, higher = more compliant

    def __post_init__(self):
        self.failed = len(self.findings)
        self.passed = self.total_rules - self.failed
        self.score = round((self.passed / self.total_rules) * 100, 1) if self.total_rules else 0


def load_rules(rules_dir: Optional[str] = None) -> List[Rule]:
    """Load all YAML rule files from the rules directory."""
    if rules_dir is None:
        rules_dir = str(Path(__file__).parent.parent / "rules")
    rules = []
    for f in sorted(Path(rules_dir).glob("*.yaml")):
        with open(f) as fh:
            data = yaml.safe_load(fh)
            rules.append(Rule(
                id=data["id"],
                owasp_id=data["owasp_id"],
                title=data["title"],
                severity=data["severity"],
                description=data["description"],
                patterns=data["patterns"],
                fix=data["fix"],
                category=data.get("category", "general"),
            ))
    return rules


class Scanner:
    """Scan agent config, prompts, and logs for compliance issues."""

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules = load_rules(rules_dir)

    def scan_text(self, text: str, source: str = "input") -> List[Finding]:
        """Scan a single text block against all rules."""
        findings = []
        lines = text.split("\n")
        for rule in self.rules:
            for pattern in rule.patterns:
                try:
                    regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                except re.error:
                    continue
                for i, line in enumerate(lines, 1):
                    m = regex.search(line)
                    if m:
                        findings.append(Finding(
                            rule=rule,
                            matched=m.group(0)[:200],
                            location=f"{source}:{i}",
                            line=i,
                        ))
                        break  # one match per rule per source
                # Also try full-text match (multi-line patterns)
                m = regex.search(text)
                if m and not any(f.rule.id == rule.id for f in findings):
                    findings.append(Finding(
                        rule=rule,
                        matched=m.group(0)[:200],
                        location=source,
                        line=0,
                    ))
        return findings

    def scan(
        self,
        prompt: Optional[str] = None,
        config: Optional[str] = None,
        tools: Optional[str] = None,
        logs: Optional[str] = None,
    ) -> ScanResult:
        """Scan all inputs and aggregate findings."""
        all_findings = []
        seen = set()  # deduplicate: (rule_id, matched)

        for source, text in [("prompt", prompt), ("config", config),
                             ("tools", tools), ("logs", logs)]:
            if not text:
                continue
            for f in self.scan_text(text, source):
                key = (f.rule.id, f.matched)
                if key not in seen:
                    seen.add(key)
                    all_findings.append(f)

        return ScanResult(
            findings=all_findings,
            total_rules=len(self.rules),
        )
