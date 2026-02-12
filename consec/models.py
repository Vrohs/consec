from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        try:
            return cls(value.upper())
        except ValueError:
            return cls.UNKNOWN

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.UNKNOWN: 0,
        }[self]

    def __ge__(self, other: "Severity") -> bool:
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:
        return self.rank > other.rank

    def __le__(self, other: "Severity") -> bool:
        return self.rank <= other.rank

    def __lt__(self, other: "Severity") -> bool:
        return self.rank < other.rank


class CVSS(BaseModel):
    v3_score: Optional[float] = Field(None, alias="V3Score")
    v3_vector: Optional[str] = Field(None, alias="V3Vector")
    v2_score: Optional[float] = Field(None, alias="V2Score")
    v2_vector: Optional[str] = Field(None, alias="V2Vector")

    model_config = {"populate_by_name": True}


class DataSource(BaseModel):
    id: Optional[str] = Field(None, alias="ID")
    name: Optional[str] = Field(None, alias="Name")
    url: Optional[str] = Field(None, alias="URL")

    model_config = {"populate_by_name": True}


class Vulnerability(BaseModel):
    vulnerability_id: str = Field(..., alias="VulnerabilityID")
    pkg_name: str = Field("", alias="PkgName")
    pkg_id: Optional[str] = Field(None, alias="PkgID")
    installed_version: str = Field("", alias="InstalledVersion")
    fixed_version: Optional[str] = Field(None, alias="FixedVersion")
    severity: str = Field("UNKNOWN", alias="Severity")
    severity_source: Optional[str] = Field(None, alias="SeveritySource")
    title: Optional[str] = Field(None, alias="Title")
    description: Optional[str] = Field(None, alias="Description")
    references: list[str] = Field(default_factory=list, alias="References")
    cvss: Optional[dict[str, CVSS]] = Field(None, alias="CVSS")
    primary_url: Optional[str] = Field(None, alias="PrimaryURL")
    data_source: Optional[DataSource] = Field(None, alias="DataSource")
    published_date: Optional[str] = Field(None, alias="PublishedDate")
    last_modified_date: Optional[str] = Field(None, alias="LastModifiedDate")
    status: Optional[str] = Field(None, alias="Status")
    layer: Optional[dict] = Field(None, alias="Layer")
    pkg_path: Optional[str] = Field(None, alias="PkgPath")
    target: Optional[str] = Field(None)

    model_config = {"populate_by_name": True}

    @property
    def normalized_severity(self) -> Severity:
        return Severity.from_string(self.severity)

    @property
    def has_fix(self) -> bool:
        return self.fixed_version is not None and self.fixed_version != ""

    def to_summary(self) -> str:
        fix_info = (
            f" (fix: {self.fixed_version})" if self.has_fix else " (no fix available)"
        )
        return (
            f"[{self.normalized_severity.value}] {self.vulnerability_id}: "
            f"{self.pkg_name}@{self.installed_version}{fix_info}"
        )

    def to_document_text(self) -> str:
        parts = [
            f"CVE ID: {self.vulnerability_id}",
            f"Severity: {self.severity}",
            f"Package: {self.pkg_name} (installed: {self.installed_version})",
        ]
        if self.fixed_version:
            parts.append(f"Fixed Version: {self.fixed_version}")
        if self.title:
            parts.append(f"Title: {self.title}")
        if self.description:
            parts.append(f"Description: {self.description}")
        if self.target:
            parts.append(f"Target: {self.target}")
        if self.primary_url:
            parts.append(f"Reference: {self.primary_url}")
        return "\n".join(parts)


class Result(BaseModel):
    target: str = Field(..., alias="Target")
    result_class: Optional[str] = Field(None, alias="Class")
    result_type: Optional[str] = Field(None, alias="Type")
    vulnerabilities: Optional[list[Vulnerability]] = Field(
        None, alias="Vulnerabilities"
    )
    misconfigurations: Optional[list[dict]] = Field(None, alias="Misconfigurations")

    model_config = {"populate_by_name": True}

    @property
    def vulnerability_count(self) -> int:
        return len(self.vulnerabilities) if self.vulnerabilities else 0


class Metadata(BaseModel):
    os: Optional[dict] = Field(None, alias="OS")
    image_id: Optional[str] = Field(None, alias="ImageID")
    diff_ids: Optional[list[str]] = Field(None, alias="DiffIDs")
    repo_tags: Optional[list[str]] = Field(None, alias="RepoTags")
    repo_digests: Optional[list[str]] = Field(None, alias="RepoDigests")
    image_config: Optional[dict] = Field(None, alias="ImageConfig")

    model_config = {"populate_by_name": True}


class TrivyReport(BaseModel):
    schema_version: int = Field(2, alias="SchemaVersion")
    created_at: Optional[str] = Field(None, alias="CreatedAt")
    artifact_name: str = Field("", alias="ArtifactName")
    artifact_type: Optional[str] = Field(None, alias="ArtifactType")
    metadata: Optional[Metadata] = Field(None, alias="Metadata")
    results: Optional[list[Result]] = Field(None, alias="Results")

    model_config = {"populate_by_name": True}

    @property
    def total_vulnerabilities(self) -> int:
        if not self.results:
            return 0
        return sum(r.vulnerability_count for r in self.results)

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        if not self.results:
            return counts
        for result in self.results:
            if result.vulnerabilities:
                for vuln in result.vulnerabilities:
                    sev = Severity.from_string(vuln.severity)
                    counts[sev.value] += 1
        return counts
