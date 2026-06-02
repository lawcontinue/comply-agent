"""Report generator — Markdown, JSON, terminal output with legal references."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .scanner import ScanResult, Finding

SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def _load_references() -> dict:
    """Load all reference YAML files."""
    refs = {}
    ref_dir = Path(__file__).parent / "references"
    for f in ref_dir.glob("*.yaml"):
        with open(f) as fh:
            refs[f.stem] = yaml.safe_load(fh)
    return refs


def _map_findings_to_refs(owasp_id: str, refs: dict) -> List[dict]:
    """Find all legal references that map to a given OWASP ID."""
    results = []
    for ref_name, ref_data in refs.items():
        if ref_name == "incidents":
            # Special handling for incidents
            for inc in ref_data.get("incidents", []):
                if owasp_id in inc.get("owasp_ids", []):
                    results.append({
                        "source": "incident",
                        "id": inc["id"],
                        "title": inc["title"],
                        "lessons": inc["lessons"],
                    })
            continue

        # Handle nested structures (eu_ai_act.articles, china_ai_law.regulations[].articles, etc.)
        for key in ("articles", "regulations", "controls"):
            items = ref_data.get(key, [])
            if key == "regulations":
                for reg in items:
                    for art in reg.get("articles", []):
                        if owasp_id in art.get("maps_to", []):
                            results.append({
                                "source": ref_name,
                                "regulation": reg.get("name", ""),
                                "article": art.get("article", art.get("clause", "")),
                                "title": art.get("title", ""),
                                "obligation": art.get("obligation", ""),
                            })
            else:
                for art in items:
                    if owasp_id in art.get("maps_to", []):
                        results.append({
                            "source": ref_name,
                            "article": art.get("article", art.get("clause", "")),
                            "title": art.get("title", ""),
                            "obligation": art.get("obligation", ""),
                        })
    return results


class ReportGenerator:
    def __init__(self, result: ScanResult):
        self.result = result
        self.refs = _load_references()

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
                # Legal references
                ref_items = _map_findings_to_refs(f.rule.owasp_id, self.refs)
                if ref_items:
                    lines.append("- **Legal References**:")
                    for r in ref_items[:3]:  # max 3 per finding
                        if r["source"] == "incident":
                            lines.append(f"  - ⚠️ Case: {r['title']} — {r['lessons']}")
                        else:
                            lines.append(f"  - 📜 {r.get('regulation', r['source'])} {r['article']}: {r['title']}")
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
                    "legal_references": _map_findings_to_refs(f.rule.owasp_id, self.refs),
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
            ref_items = _map_findings_to_refs(f.rule.owasp_id, self.refs)
            for r in ref_items[:2]:
                if r["source"] == "incident":
                    lines.append(f"     Case:     {r['title'][:60]}")
                else:
                    lines.append(f"     📜 {r.get('regulation', r['source'])} {r['article']}: {r['title'][:40]}")

        lines.append(f"\n{'='*60}")
        return "\n".join(lines)
