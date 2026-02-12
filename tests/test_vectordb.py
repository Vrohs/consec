"""Tests for the ChromaDB vector store."""

import tempfile
from pathlib import Path

import pytest

from consec.models import Result, TrivyReport, Vulnerability
from consec.vectordb import VulnVectorStore


@pytest.fixture
def temp_store(tmp_path):
    """Create a VulnVectorStore with a temporary directory."""
    store = VulnVectorStore(persist_dir=tmp_path / "test_chroma")
    yield store
    store.clear()


@pytest.fixture
def sample_documents():
    """Sample documents for ingestion testing."""
    return [
        {
            "id": "CVE-2024-6119",
            "text": "CVE ID: CVE-2024-6119\nSeverity: HIGH\nPackage: openssl\nDescription: Possible DoS.",
            "metadata": {
                "cve_id": "CVE-2024-6119",
                "severity": "HIGH",
                "pkg_name": "openssl",
                "installed_version": "3.0.13",
                "fixed_version": "3.0.14",
                "has_fix": True,
                "target": "debian 12",
            },
        },
        {
            "id": "CVE-2024-5535",
            "text": "CVE ID: CVE-2024-5535\nSeverity: CRITICAL\nPackage: openssl\nDescription: Buffer overread.",
            "metadata": {
                "cve_id": "CVE-2024-5535",
                "severity": "CRITICAL",
                "pkg_name": "openssl",
                "installed_version": "3.0.13",
                "fixed_version": "3.0.15",
                "has_fix": True,
                "target": "debian 12",
            },
        },
        {
            "id": "CVE-2023-44487",
            "text": "CVE ID: CVE-2023-44487\nSeverity: HIGH\nPackage: nghttp2\nDescription: HTTP/2 Rapid Reset.",
            "metadata": {
                "cve_id": "CVE-2023-44487",
                "severity": "HIGH",
                "pkg_name": "nghttp2",
                "installed_version": "1.52.0",
                "fixed_version": "1.52.0-1+deb12u2",
                "has_fix": True,
                "target": "debian 12",
            },
        },
    ]


class TestVulnVectorStoreIngestion:
    """Behavioral tests for document ingestion."""

    def test_ingest_adds_documents(self, temp_store, sample_documents):
        """When documents are ingested, the collection count should increase."""
        added = temp_store.ingest_documents(sample_documents)
        assert added == 3
        assert temp_store.count == 3

    def test_ingest_deduplicates(self, temp_store, sample_documents):
        """Ingesting the same documents twice should not create duplicates."""
        temp_store.ingest_documents(sample_documents)
        added = temp_store.ingest_documents(sample_documents)
        assert added == 0
        assert temp_store.count == 3

    def test_ingest_empty_list(self, temp_store):
        """Ingesting an empty list should return 0 and not error."""
        added = temp_store.ingest_documents([])
        assert added == 0
        assert temp_store.count == 0

    def test_ingest_partial_new_documents(self, temp_store, sample_documents):
        """Only new documents should be added when some already exist."""
        temp_store.ingest_documents(sample_documents[:1])
        assert temp_store.count == 1

        added = temp_store.ingest_documents(sample_documents)
        assert added == 2
        assert temp_store.count == 3


class TestVulnVectorStoreQuery:
    """Behavioral tests for querying the vector store."""

    def test_query_returns_results(self, temp_store, sample_documents):
        """Querying should return relevant documents."""
        temp_store.ingest_documents(sample_documents)
        results = temp_store.query("openssl vulnerability", n_results=2)
        assert len(results) == 2
        assert all("id" in r for r in results)
        assert all("text" in r for r in results)
        assert all("metadata" in r for r in results)

    def test_query_empty_store(self, temp_store):
        """Querying an empty store should return an empty list."""
        results = temp_store.query("anything")
        assert results == []

    def test_query_result_structure(self, temp_store, sample_documents):
        """Each result should have the expected fields."""
        temp_store.ingest_documents(sample_documents)
        results = temp_store.query("HTTP/2 attack", n_results=1)
        assert len(results) >= 1
        result = results[0]
        assert "id" in result
        assert "text" in result
        assert "metadata" in result
        assert "distance" in result

    def test_query_relevance(self, temp_store, sample_documents):
        """Query about HTTP/2 should return the HTTP/2 related CVE."""
        temp_store.ingest_documents(sample_documents)
        results = temp_store.query("HTTP/2 Rapid Reset denial of service", n_results=1)
        assert results[0]["id"] == "CVE-2023-44487"

    def test_query_n_results_capped(self, temp_store, sample_documents):
        """n_results should be capped at the collection size."""
        temp_store.ingest_documents(sample_documents[:1])
        results = temp_store.query("openssl", n_results=10)
        assert len(results) == 1


class TestVulnVectorStoreIngestScan:
    """Behavioral tests for ingesting full scan reports."""

    def test_ingest_scan_report(self, temp_store):
        """Should extract and ingest vulnerabilities from a TrivyReport."""
        report = TrivyReport(
            SchemaVersion=2,
            ArtifactName="test:latest",
            Results=[
                Result(
                    Target="test (debian)",
                    Vulnerabilities=[
                        Vulnerability(
                            VulnerabilityID="CVE-A",
                            PkgName="pkg-a",
                            InstalledVersion="1.0",
                            Severity="HIGH",
                        ),
                        Vulnerability(
                            VulnerabilityID="CVE-B",
                            PkgName="pkg-b",
                            InstalledVersion="2.0",
                            Severity="CRITICAL",
                        ),
                    ],
                ),
            ],
        )
        added = temp_store.ingest_scan(report)
        assert added == 2
        assert temp_store.count == 2

    def test_ingest_empty_scan(self, temp_store):
        """Ingesting a scan with no vulnerabilities should work without error."""
        report = TrivyReport(SchemaVersion=2, ArtifactName="clean:latest")
        added = temp_store.ingest_scan(report)
        assert added == 0


class TestVulnVectorStoreClear:
    """Tests for clearing the collection."""

    def test_clear_removes_all(self, temp_store, sample_documents):
        """Clear should remove all documents."""
        temp_store.ingest_documents(sample_documents)
        assert temp_store.count == 3
        temp_store.clear()
        assert temp_store.count == 0

    def test_clear_empty_store(self, temp_store):
        """Clearing an already empty store should not error."""
        temp_store.clear()
        assert temp_store.count == 0
