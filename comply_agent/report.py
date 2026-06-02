"""Report generator — Markdown, JSON, terminal output."""
from __future__ import annotations

import json
from typing import Optional

from .scanner import ScanResult, Finding

SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


class ReportGenerator:
    def __init__(self, result: ScanResult):
        self.result = result

    def markdown(self) -> str:
        """Generate Markdown report."""
        lines = [
            "# comply-agent Report",
            "",
            f"**Score**: {self.result.score}/100",
            f"**Rules**: {self.result.total_rules} total | {self.result.passed} passed | {self.result.failed} failed",
            "",
        ]

        if not self.result.findings:
            lines.append("✅ No compliance issues detected.")
            return "\n".join(lines)

        # Group by severity
        by_severity = {"critical": [], "high": [], "medium": [], "low": []}
        for f in self.result.findings:
            by_severity.get(f.rule.severity, by_severity["low"]).append(f)

        for sev in ("critical", "high", "medium", "low"):
            items = by_severity[sev]
            if not items:
                continue
            icon = SEVERITY_ICON.get(sev, "⚪")
            lines.append(f"## {icon} {sev.upper()} ({len(items)} findings)")
            lines.append("")
            for f in items:
                lines.append(f"### {f.rule.owasp_id}: {f.rule.title}")
                lines.append(f"- **Severity**: {f.rule.severity}")
                lines.append(f"- **Category**: {f.rule.category}")
                lines.append(f"- **Location**: {f.location}")
                lines.append(f"- **Matched**: `{f.matched[:100]}`")
                lines.append(f"- **Description**: {f.rule.description}")
                lines.append(f"- **Fix**: {f.rule.fix}")
                lines.append("")

        return "\n".join(lines)

    def json(self) -> str:
        """Generate JSON report."""
        data = {
            "score": self.result.score,
            "total_rules": self.result.total_rules,
            "passed": self.result.passed,
            "failed": self.result.failed,
            "findings": [
                {
                    "rule_id": f.rule.id,
                    "owasp_id": f.rule.owasp_id,
                    "title": f.rule.title,
                    "severity": f.rule.severity,
                    "category": f.rule.category,
                    "location": f.location,
                    "matched": f.matched[:200],
                    "description": f.rule.description,
                    "fix": f.rule.fix,
                }
                for f in self.result.findings
            ],
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def terminal(self) -> str:
        """Generate colored terminal output."""
        lines = [
            f"\n{'='*60}",
            f"  comply-agent Report",
            f"{'='*60}",
            f"  Score: {self.result.score}/100  "
            f"({self.result.passed} passed / {self.result.failed} failed / {self.result.total_rules} rules)",
            f"{'='*60}",
        ]

        if not self.result.findings:
            lines.append("  ✅ No compliance issues detected.")
            return "\n".join(lines)

        for f in self.result.findings:
            icon = SEVERITY_ICON.get(f.rule.severity, "⚪")
            lines.append(f"\n  {icon} [{f.rule.owasp_id}] {f.rule.title}")
            lines.append(f"     Location: {f.location}")
            lines.append(f"     Matched:  {f.matched[:80]}")
            lines.append(f"     Fix:      {f.rule.fix[:80]}")

        lines.append(f"\n{'='*60}")
        return "\n".join(lines)
