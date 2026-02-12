from __future__ import annotations

import json
from pathlib import Path

from consec.models import Severity, TrivyReport, Vulnerability


class ParseError(Exception):
    pass


def parse_trivy_json(source: str | Path) -> TrivyReport:
    path = Path(source)

    if path.exists() and path.is_file():
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as e:
            raise ParseError(f"Cannot read file: {path}") from e
    else:
        raw = str(source)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError(f"Invalid JSON: {e}") from e

    if not isinstance(data, dict):
        raise ParseError("Expected a JSON object at the top level")

    try:
        report = TrivyReport.model_validate(data)
    except Exception as e:
        raise ParseError(f"JSON does not match Trivy schema: {e}") from e

    return report


def extract_vulnerabilities(report: TrivyReport) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []
    if not report.results:
        return vulns

    for result in report.results:
        if result.vulnerabilities:
            for vuln in result.vulnerabilities:
                vuln.target = result.target
                vulns.append(vuln)

    return vulns


def filter_by_severity(
    vulns: list[Vulnerability],
    min_severity: Severity = Severity.LOW,
) -> list[Vulnerability]:
    return [v for v in vulns if v.normalized_severity >= min_severity]


def to_documents(vulns: list[Vulnerability]) -> list[dict]:
    documents = []
    seen_ids: set[str] = set()

    for vuln in vulns:
        if vuln.vulnerability_id in seen_ids:
            continue
        seen_ids.add(vuln.vulnerability_id)

        doc = {
            "id": vuln.vulnerability_id,
            "text": vuln.to_document_text(),
            "metadata": {
                "cve_id": vuln.vulnerability_id,
                "severity": vuln.severity,
                "pkg_name": vuln.pkg_name,
                "installed_version": vuln.installed_version,
                "fixed_version": vuln.fixed_version or "",
                "has_fix": vuln.has_fix,
                "target": vuln.target or "",
            },
        }
        documents.append(doc)

    return documents
