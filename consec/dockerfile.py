"""Dockerfile parser for extracting security-relevant context."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DockerfileInfo:
    """Parsed information from a Dockerfile."""
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
        """Check if the container likely runs as root (no USER directive)."""
        return self.user is None or self.user.strip() in ("", "root", "0")

    @property
    def has_healthcheck(self) -> bool:
        """Check if a HEALTHCHECK directive exists."""
        return "HEALTHCHECK" in self.raw_content

    def to_summary(self) -> str:
        """Generate a summary string for prompt context."""
        parts = [f"Base image(s): {', '.join(self.base_images) or 'unknown'}"]
        if self.stages:
            parts.append(f"Build stages: {len(self.stages)}")
        parts.append(f"RUN commands: {len(self.run_commands)}")
        parts.append(f"Exposed ports: {', '.join(self.exposed_ports) or 'none'}")
        parts.append(f"Runs as root: {'yes' if self.runs_as_root else 'no'}")
        parts.append(f"Has healthcheck: {'yes' if self.has_healthcheck else 'no'}")
        return "\n".join(parts)


def parse_dockerfile(source: str | Path) -> DockerfileInfo:
    """Parse a Dockerfile and extract security-relevant information.

    Args:
        source: Path to Dockerfile or raw Dockerfile content string.

    Returns:
        DockerfileInfo with extracted directives.
    """
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
