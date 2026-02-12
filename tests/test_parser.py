import json
import tempfile
from pathlib import Path

import pytest

from consec.models import Severity, Vulnerability
from consec.parser import (
    ParseError,
    extract_vulnerabilities,
    filter_by_severity,
    parse_trivy_json,
    to_documents,
)


SAMPLE_SCAN_DIR = Path(__file__).parent.parent / "data" / "sample_scans"


class TestParseTrivyJson:
    def test_parse_valid_file(self):
        report = parse_trivy_json(SAMPLE_SCAN_DIR / "nginx_scan.json")
        assert report.artifact_name == "nginx:1.25"
        assert report.schema_version == 2
        assert report.results is not None
        assert len(report.results) == 2

    def test_parse_clean_scan(self):
        report = parse_trivy_json(SAMPLE_SCAN_DIR / "alpine_clean.json")
        assert report.artifact_name == "alpine:3.19"
        assert report.results is None
        assert report.total_vulnerabilities == 0

    def test_parse_from_json_string(self):
        data = json.dumps(
            {"SchemaVersion": 2, "ArtifactName": "test:latest", "Results": []}
        )
        report = parse_trivy_json(data)
        assert report.artifact_name == "test:latest"

    def test_parse_invalid_json_raises_error(self):
        with pytest.raises(ParseError, match="Invalid JSON"):
            parse_trivy_json("{invalid json}")

    def test_parse_non_object_json_raises_error(self):
        with pytest.raises(ParseError, match="Expected a JSON object"):
            parse_trivy_json("[]")

    def test_parse_nonexistent_file_as_string(self):
        with pytest.raises(ParseError):
            parse_trivy_json("/nonexistent/path/that/is/not/json")

    def test_parse_empty_string_raises_error(self):
        with pytest.raises(ParseError):
            parse_trivy_json("")

    def test_parse_valid_json_missing_required_fields(self):
        data = json.dumps({"SchemaVersion": 2})
        report = parse_trivy_json(data)
        assert report.artifact_name == ""
        assert report.total_vulnerabilities == 0

    def test_parse_writes_to_temp_file(self):
        data = {
            "SchemaVersion": 2,
            "ArtifactName": "temp:test",
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "PkgName": "testpkg",
                            "InstalledVersion": "1.0",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            report = parse_trivy_json(f.name)

        assert report.artifact_name == "temp:test"
        assert report.total_vulnerabilities == 1


class TestExtractVulnerabilities:
    def test_extract_from_multi_result_report(self):
        report = parse_trivy_json(SAMPLE_SCAN_DIR / "nginx_scan.json")
        vulns = extract_vulnerabilities(report)
        assert len(vulns) == 6
        targets = {v.target for v in vulns}
        assert len(targets) == 2

    def test_extract_from_empty_report(self):
        report = parse_trivy_json(SAMPLE_SCAN_DIR / "alpine_clean.json")
        vulns = extract_vulnerabilities(report)
        assert vulns == []

    def test_extract_annotates_target(self):
        report = parse_trivy_json(SAMPLE_SCAN_DIR / "nginx_scan.json")
        vulns = extract_vulnerabilities(report)
        for vuln in vulns:
            assert vuln.target is not None
            assert vuln.target != ""


class TestFilterBySeverity:
    @pytest.fixture
    def mixed_vulns(self):
        return [
            Vulnerability(
                VulnerabilityID="CVE-C",
                PkgName="a",
                InstalledVersion="1",
                Severity="CRITICAL",
            ),
            Vulnerability(
                VulnerabilityID="CVE-H",
                PkgName="b",
                InstalledVersion="1",
                Severity="HIGH",
            ),
            Vulnerability(
                VulnerabilityID="CVE-M",
                PkgName="c",
                InstalledVersion="1",
                Severity="MEDIUM",
            ),
            Vulnerability(
                VulnerabilityID="CVE-L",
                PkgName="d",
                InstalledVersion="1",
                Severity="LOW",
            ),
            Vulnerability(
                VulnerabilityID="CVE-U",
                PkgName="e",
                InstalledVersion="1",
                Severity="UNKNOWN",
            ),
        ]

    def test_filter_critical_only(self, mixed_vulns):
        result = filter_by_severity(mixed_vulns, Severity.CRITICAL)
        assert len(result) == 1
        assert result[0].vulnerability_id == "CVE-C"

    def test_filter_high_and_above(self, mixed_vulns):
        result = filter_by_severity(mixed_vulns, Severity.HIGH)
        assert len(result) == 2
        ids = {v.vulnerability_id for v in result}
        assert ids == {"CVE-C", "CVE-H"}

    def test_filter_medium_and_above(self, mixed_vulns):
        result = filter_by_severity(mixed_vulns, Severity.MEDIUM)
        assert len(result) == 3

    def test_filter_all(self, mixed_vulns):
        result = filter_by_severity(mixed_vulns, Severity.UNKNOWN)
        assert len(result) == 5

    def test_filter_empty_list(self):
        result = filter_by_severity([], Severity.LOW)
        assert result == []


class TestToDocuments:
    @pytest.fixture
    def sample_vulns(self):
        return [
            Vulnerability(
                VulnerabilityID="CVE-2024-6119",
                PkgName="openssl",
                InstalledVersion="3.0.13",
                FixedVersion="3.0.14",
                Severity="HIGH",
                Title="Test vuln",
                Description="A test vulnerability.",
            ),
            Vulnerability(
                VulnerabilityID="CVE-2024-5535",
                PkgName="openssl",
                InstalledVersion="3.0.13",
                Severity="CRITICAL",
            ),
        ]

    def test_converts_to_document_format(self, sample_vulns):
        docs = to_documents(sample_vulns)
        assert len(docs) == 2
        for doc in docs:
            assert "id" in doc
            assert "text" in doc
            assert "metadata" in doc

    def test_document_metadata_fields(self, sample_vulns):
        docs = to_documents(sample_vulns)
        meta = docs[0]["metadata"]
        assert meta["cve_id"] == "CVE-2024-6119"
        assert meta["severity"] == "HIGH"
        assert meta["pkg_name"] == "openssl"
        assert meta["has_fix"] is True

    def test_deduplication(self):
        vulns = [
            Vulnerability(
                VulnerabilityID="CVE-DUPE",
                PkgName="a",
                InstalledVersion="1",
                Severity="HIGH",
            ),
            Vulnerability(
                VulnerabilityID="CVE-DUPE",
                PkgName="b",
                InstalledVersion="2",
                Severity="HIGH",
            ),
        ]
        docs = to_documents(vulns)
        assert len(docs) == 1
        assert docs[0]["id"] == "CVE-DUPE"

    def test_empty_input(self):
        docs = to_documents([])
        assert docs == []
