from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
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


@dataclass
class DockerfileInfo:
    base_images: list[str] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)
    run_commands: list[str] = field(default_factory=list)
    exposed_ports: list[str] = field(default_factory=list)
    env_vars: list[str] = field(default_factory=list)
    copy_add_commands: list[str] = field(default_factory=list)
    user: str | None = None
    entrypoint: str | None = None
    cmd: str | None = None
    raw_content: str = ""

    @property
    def runs_as_root(self) -> bool:
        return self.user is None or self.user.strip() in ("", "root", "0")

    @property
    def has_healthcheck(self) -> bool:
        return "HEALTHCHECK" in self.raw_content

    def to_summary(self) -> str:
        parts = [f"Base image(s): {', '.join(self.base_images) or 'unknown'}"]
        if self.stages:
            parts.append(f"Build stages: {len(self.stages)}")
        parts.append(f"RUN commands: {len(self.run_commands)}")
        parts.append(f"Exposed ports: {', '.join(self.exposed_ports) or 'none'}")
        parts.append(f"Runs as root: {'yes' if self.runs_as_root else 'no'}")
        parts.append(f"Has healthcheck: {'yes' if self.has_healthcheck else 'no'}")
        return "\n".join(parts)


def parse_dockerfile(source: str | Path) -> DockerfileInfo:
    path = Path(source)
    if path.exists() and path.is_file():
        content = path.read_text(encoding="utf-8")
    else:
        content = str(source)

    info = DockerfileInfo(raw_content=content)

    continued_line = ""
    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if line.endswith("\\"):
            continued_line += line[:-1] + " "
            continue

        if continued_line:
            line = continued_line + line
            continued_line = ""

        upper = line.upper()

        if upper.startswith("FROM "):
            parts = line.split()
            image = parts[1] if len(parts) > 1 else "unknown"
            info.base_images.append(image)
            if " AS " in line.upper():
                match = re.search(r"(?i)\bAS\b\s+(\S+)", line)
                if match:
                    info.stages.append(match.group(1))

        elif upper.startswith("RUN "):
            info.run_commands.append(line[4:].strip())

        elif upper.startswith("EXPOSE "):
            ports = line[7:].strip().split()
            info.exposed_ports.extend(ports)

        elif upper.startswith("ENV "):
            info.env_vars.append(line[4:].strip())

        elif upper.startswith(("COPY ", "ADD ")):
            info.copy_add_commands.append(line)

        elif upper.startswith("USER "):
            info.user = line[5:].strip()

        elif upper.startswith("ENTRYPOINT "):
            info.entrypoint = line[11:].strip()

        elif upper.startswith("CMD "):
            info.cmd = line[4:].strip()

    return info
