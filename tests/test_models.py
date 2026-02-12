"""Tests for Pydantic data models."""

import pytest

from consec.models import (
    CVSS,
    DataSource,
    Metadata,
    Result,
    Severity,
    TrivyReport,
    Vulnerability,
)


class TestSeverity:
    """Behavioral tests for the Severity enum."""

    def test_from_valid_string(self):
        assert Severity.from_string("CRITICAL") == Severity.CRITICAL
        assert Severity.from_string("HIGH") == Severity.HIGH
        assert Severity.from_string("MEDIUM") == Severity.MEDIUM
        assert Severity.from_string("LOW") == Severity.LOW

    def test_from_string_case_insensitive(self):
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("High") == Severity.HIGH
        assert Severity.from_string("medium") == Severity.MEDIUM

    def test_from_invalid_string_returns_unknown(self):
        assert Severity.from_string("INVALID") == Severity.UNKNOWN
        assert Severity.from_string("") == Severity.UNKNOWN
        assert Severity.from_string("nil") == Severity.UNKNOWN

    def test_rank_ordering(self):
        assert Severity.CRITICAL.rank > Severity.HIGH.rank
        assert Severity.HIGH.rank > Severity.MEDIUM.rank
        assert Severity.MEDIUM.rank > Severity.LOW.rank
        assert Severity.LOW.rank > Severity.UNKNOWN.rank

    def test_comparison_operators(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH >= Severity.HIGH
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.UNKNOWN <= Severity.LOW
        assert not (Severity.LOW > Severity.HIGH)


class TestVulnerability:
    """Behavioral tests for the Vulnerability model."""

    @pytest.fixture
    def vuln_with_fix(self):
        return Vulnerability(
            VulnerabilityID="CVE-2024-6119",
            PkgName="openssl",
            InstalledVersion="3.0.13-1~deb12u1",
            FixedVersion="3.0.14-1~deb12u1",
            Severity="HIGH",
            Title="openssl: Possible denial of service",
            Description="Applications performing certificate name checks may crash.",
            PrimaryURL="https://nvd.nist.gov/vuln/detail/CVE-2024-6119",
        )

    @pytest.fixture
    def vuln_without_fix(self):
        return Vulnerability(
            VulnerabilityID="CVE-2024-41996",
            PkgName="openssl",
            InstalledVersion="3.0.13-1~deb12u1",
            Severity="LOW",
        )

    def test_has_fix_when_fixed_version_present(self, vuln_with_fix):
        assert vuln_with_fix.has_fix is True

    def test_has_fix_when_no_fixed_version(self, vuln_without_fix):
        assert vuln_without_fix.has_fix is False

    def test_has_fix_when_empty_string(self):
        vuln = Vulnerability(
            VulnerabilityID="CVE-TEST",
            PkgName="test",
            InstalledVersion="1.0",
            FixedVersion="",
            Severity="LOW",
        )
        assert vuln.has_fix is False

    def test_normalized_severity(self, vuln_with_fix):
        assert vuln_with_fix.normalized_severity == Severity.HIGH

    def test_normalized_severity_unknown_for_invalid(self):
        vuln = Vulnerability(
            VulnerabilityID="CVE-TEST",
            PkgName="test",
            InstalledVersion="1.0",
            Severity="BOGUS",
        )
        assert vuln.normalized_severity == Severity.UNKNOWN

    def test_to_summary_with_fix(self, vuln_with_fix):
        summary = vuln_with_fix.to_summary()
        assert "CVE-2024-6119" in summary
        assert "HIGH" in summary
        assert "openssl" in summary
        assert "fix: 3.0.14" in summary

    def test_to_summary_without_fix(self, vuln_without_fix):
        summary = vuln_without_fix.to_summary()
        assert "no fix available" in summary

    def test_to_document_text_includes_all_fields(self, vuln_with_fix):
        doc = vuln_with_fix.to_document_text()
        assert "CVE-2024-6119" in doc
        assert "HIGH" in doc
        assert "openssl" in doc
        assert "3.0.14-1~deb12u1" in doc
        assert "denial of service" in doc
        assert "nvd.nist.gov" in doc

    def test_to_document_text_minimal_fields(self, vuln_without_fix):
        doc = vuln_without_fix.to_document_text()
        assert "CVE-2024-41996" in doc
        assert "openssl" in doc
        assert "Fixed Version" not in doc

    def test_alias_parsing(self):
        """Verify that Trivy JSON field names (PascalCase) map correctly."""
        data = {
            "VulnerabilityID": "CVE-2024-1234",
            "PkgName": "curl",
            "InstalledVersion": "7.88.1",
            "FixedVersion": "7.88.2",
            "Severity": "CRITICAL",
            "Title": "Test vuln",
            "Description": "A test.",
            "References": ["https://example.com"],
            "PrimaryURL": "https://example.com/cve",
        }
        vuln = Vulnerability.model_validate(data)
        assert vuln.vulnerability_id == "CVE-2024-1234"
        assert vuln.pkg_name == "curl"
        assert vuln.severity == "CRITICAL"
        assert len(vuln.references) == 1


class TestResult:
    """Tests for the Result model."""

    def test_vulnerability_count_with_vulns(self):
        result = Result(
            Target="test",
            Vulnerabilities=[
                Vulnerability(
                    VulnerabilityID="CVE-1",
                    PkgName="a",
                    InstalledVersion="1",
                    Severity="HIGH",
                ),
                Vulnerability(
                    VulnerabilityID="CVE-2",
                    PkgName="b",
                    InstalledVersion="1",
                    Severity="LOW",
                ),
            ],
        )
        assert result.vulnerability_count == 2

    def test_vulnerability_count_none(self):
        result = Result(Target="test")
        assert result.vulnerability_count == 0

    def test_vulnerability_count_empty_list(self):
        result = Result(Target="test", Vulnerabilities=[])
        assert result.vulnerability_count == 0


class TestTrivyReport:
    """Tests for the TrivyReport model."""

    @pytest.fixture
    def report_with_vulns(self):
        return TrivyReport(
            SchemaVersion=2,
            ArtifactName="nginx:1.25",
            Results=[
                Result(
                    Target="nginx:1.25 (debian 12.4)",
                    Vulnerabilities=[
                        Vulnerability(
                            VulnerabilityID="CVE-1",
                            PkgName="openssl",
                            InstalledVersion="3.0",
                            Severity="CRITICAL",
                        ),
                        Vulnerability(
                            VulnerabilityID="CVE-2",
                            PkgName="curl",
                            InstalledVersion="7.88",
                            Severity="HIGH",
                        ),
                    ],
                ),
                Result(
                    Target="python packages",
                    Vulnerabilities=[
                        Vulnerability(
                            VulnerabilityID="CVE-3",
                            PkgName="requests",
                            InstalledVersion="2.31",
                            Severity="MEDIUM",
                        ),
                    ],
                ),
            ],
        )

    @pytest.fixture
    def empty_report(self):
        return TrivyReport(SchemaVersion=2, ArtifactName="alpine:3.19")

    def test_total_vulnerabilities(self, report_with_vulns):
        assert report_with_vulns.total_vulnerabilities == 3

    def test_total_vulnerabilities_empty(self, empty_report):
        assert empty_report.total_vulnerabilities == 0

    def test_severity_counts(self, report_with_vulns):
        counts = report_with_vulns.severity_counts()
        assert counts["CRITICAL"] == 1
        assert counts["HIGH"] == 1
        assert counts["MEDIUM"] == 1
        assert counts["LOW"] == 0
        assert counts["UNKNOWN"] == 0

    def test_severity_counts_empty(self, empty_report):
        counts = empty_report.severity_counts()
        assert all(v == 0 for v in counts.values())
