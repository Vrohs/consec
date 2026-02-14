from __future__ import annotations

import re
from dataclasses import dataclass

from consec.parser import DockerfileInfo

SENSITIVE_ENV_PATTERNS = re.compile(
    r"(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|AWS_ACCESS|AWS_SECRET)",
    re.IGNORECASE,
)


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    description: str
    remediation: str


def _check_unpinned_base_image(info: DockerfileInfo) -> list[Finding]:
    findings = []
    for image in info.base_images:
        if image == "scratch":
            continue
        name_tag = image.split("@")[0]
        if ":" not in name_tag or name_tag.endswith(":latest"):
            findings.append(
                Finding(
                    rule_id="CSC-001",
                    severity="HIGH",
                    title=f"Unpinned base image: {image}",
                    description=(
                        "Using ':latest' or an untagged image means builds are not "
                        "reproducible and may pull in unexpected changes or vulnerabilities."
                    ),
                    remediation=(
                        f"Pin to a specific version, "
                        f"e.g. {name_tag.split(':')[0]}:3.19-alpine"
                    ),
                )
            )
    return findings


def _check_root_user(info: DockerfileInfo) -> Finding | None:
    if not info.runs_as_root:
        return None
    return Finding(
        rule_id="CSC-002",
        severity="HIGH",
        title="Container runs as root",
        description=(
            "No USER directive found, or USER is set to root. "
            "A compromised container running as root gives attackers full host access."
        ),
        remediation="Add 'USER nonroot' or 'USER 1000' after installing dependencies.",
    )


def _check_missing_healthcheck(info: DockerfileInfo) -> Finding | None:
    if info.has_healthcheck:
        return None
    return Finding(
        rule_id="CSC-003",
        severity="MEDIUM",
        title="Missing HEALTHCHECK instruction",
        description=(
            "Without a HEALTHCHECK, Docker has no way to know if the process inside "
            "the container is actually healthy. Orchestrators cannot restart unhealthy containers."
        ),
        remediation="Add: HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1",
    )


def _check_copy_all(info: DockerfileInfo) -> list[Finding]:
    findings = []
    for cmd in info.copy_add_commands:
        parts = cmd.split()
        if len(parts) >= 2 and parts[1] in (".", "./"):
            findings.append(
                Finding(
                    rule_id="CSC-004",
                    severity="MEDIUM",
                    title=f"Broad source copy: {cmd}",
                    description=(
                        "Copying the entire build context may include secrets, "
                        ".git directories, or development files in the final image."
                    ),
                    remediation="Use a .dockerignore file and copy only what's needed.",
                )
            )
    return findings


def _check_apt_cache(info: DockerfileInfo) -> list[Finding]:
    findings = []
    for cmd in info.run_commands:
        if "apt-get update" in cmd and "rm -rf /var/lib/apt/lists" not in cmd:
            findings.append(
                Finding(
                    rule_id="CSC-005",
                    severity="LOW",
                    title="apt cache not cleaned",
                    description=(
                        "Running apt-get update without cleaning /var/lib/apt/lists/* "
                        "in the same RUN layer bloats the image with unnecessary cache data."
                    ),
                    remediation=(
                        "Chain cleanup in the same RUN: "
                        "RUN apt-get update && apt-get install -y pkg "
                        "&& rm -rf /var/lib/apt/lists/*"
                    ),
                )
            )
    return findings


def _check_secrets_in_env(info: DockerfileInfo) -> list[Finding]:
    findings = []
    for env in info.env_vars:
        key = env.split("=")[0].strip()
        if SENSITIVE_ENV_PATTERNS.search(key):
            findings.append(
                Finding(
                    rule_id="CSC-006",
                    severity="HIGH",
                    title=f"Possible secret in ENV: {key}",
                    description=(
                        "Hardcoding secrets in ENV makes them visible in the image "
                        "metadata (docker inspect) and build logs."
                    ),
                    remediation=(
                        "Use Docker secrets, build-time --secret mounts, "
                        "or runtime env vars instead."
                    ),
                )
            )
    return findings


def _check_add_misuse(info: DockerfileInfo) -> list[Finding]:
    findings = []
    for cmd in info.copy_add_commands:
        upper = cmd.upper()
        if not upper.startswith("ADD "):
            continue
        parts = cmd.split()
        if len(parts) >= 2:
            src = parts[1]
            if not src.startswith(("http://", "https://")) and not src.endswith(
                (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")
            ):
                findings.append(
                    Finding(
                        rule_id="CSC-007",
                        severity="LOW",
                        title=f"ADD used instead of COPY: {cmd}",
                        description=(
                            "ADD has extra features (URL fetching, "
                            "auto-extraction) that make behavior less "
                            "predictable. COPY is preferred for simple "
                            "file copies."
                        ),
                        remediation=f"Replace with: COPY {' '.join(parts[1:])}",
                    )
                )
    return findings


def _check_ssh_port(info: DockerfileInfo) -> Finding | None:
    if "22" not in info.exposed_ports:
        return None
    return Finding(
        rule_id="CSC-008",
        severity="MEDIUM",
        title="SSH port (22) exposed",
        description=(
            "Exposing SSH inside a container is an anti-pattern. Containers should be "
            "treated as immutable; use 'docker exec' or orchestrator tools for debugging."
        ),
        remediation="Remove 'EXPOSE 22' and avoid running SSH daemons in containers.",
    )


def check_dockerfile(info: DockerfileInfo) -> list[Finding]:
    findings: list[Finding] = []

    findings.extend(_check_unpinned_base_image(info))

    result = _check_root_user(info)
    if result:
        findings.append(result)

    result = _check_missing_healthcheck(info)
    if result:
        findings.append(result)

    findings.extend(_check_copy_all(info))
    findings.extend(_check_apt_cache(info))
    findings.extend(_check_secrets_in_env(info))
    findings.extend(_check_add_misuse(info))

    result = _check_ssh_port(info)
    if result:
        findings.append(result)

    return findings
