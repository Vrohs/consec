import pytest

from consec.models import Result, TrivyReport, Vulnerability
from consec.vectordb import VulnVectorStore


@pytest.fixture
def temp_store(tmp_path):
    store = VulnVectorStore(persist_dir=tmp_path / "test_chroma")
    yield store
    store.clear()


@pytest.fixture
def sample_documents():
    return [
        {
            "id": "CVE-2024-6119",
            "text": (
                "CVE ID: CVE-2024-6119\nSeverity: HIGH\n"
                "Package: openssl\nDescription: Possible DoS."
            ),
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
            "text": (
                "CVE ID: CVE-2024-5535\nSeverity: CRITICAL\n"
                "Package: openssl\nDescription: Buffer overread."
            ),
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
            "text": (
                "CVE ID: CVE-2023-44487\nSeverity: HIGH\n"
                "Package: nghttp2\nDescription: HTTP/2 Rapid Reset."
            ),
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
    def test_ingest_adds_documents(self, temp_store, sample_documents):
        added = temp_store.ingest_documents(sample_documents)
        assert added == 3
        assert temp_store.count == 3

    def test_ingest_deduplicates(self, temp_store, sample_documents):
        temp_store.ingest_documents(sample_documents)
        added = temp_store.ingest_documents(sample_documents)
        assert added == 0
        assert temp_store.count == 3

    def test_ingest_empty_list(self, temp_store):
        added = temp_store.ingest_documents([])
        assert added == 0
        assert temp_store.count == 0

    def test_ingest_partial_new_documents(self, temp_store, sample_documents):
        temp_store.ingest_documents(sample_documents[:1])
        assert temp_store.count == 1

        added = temp_store.ingest_documents(sample_documents)
        assert added == 2
        assert temp_store.count == 3


class TestVulnVectorStoreQuery:
    def test_query_returns_results(self, temp_store, sample_documents):
        temp_store.ingest_documents(sample_documents)
        results = temp_store.query("openssl vulnerability", n_results=2)
        assert len(results) == 2
        assert all("id" in r for r in results)
        assert all("text" in r for r in results)
        assert all("metadata" in r for r in results)

    def test_query_empty_store(self, temp_store):
        results = temp_store.query("anything")
        assert results == []

    def test_query_result_structure(self, temp_store, sample_documents):
        temp_store.ingest_documents(sample_documents)
        results = temp_store.query("HTTP/2 attack", n_results=1)
        assert len(results) >= 1
        result = results[0]
        assert "id" in result
        assert "text" in result
        assert "metadata" in result
        assert "distance" in result

    def test_query_relevance(self, temp_store, sample_documents):
        temp_store.ingest_documents(sample_documents)
        results = temp_store.query("HTTP/2 Rapid Reset denial of service", n_results=1)
        assert results[0]["id"] == "CVE-2023-44487"

    def test_query_n_results_capped(self, temp_store, sample_documents):
        temp_store.ingest_documents(sample_documents[:1])
        results = temp_store.query("openssl", n_results=10)
        assert len(results) == 1


class TestVulnVectorStoreIngestScan:
    def test_ingest_scan_report(self, temp_store):
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
        report = TrivyReport(SchemaVersion=2, ArtifactName="clean:latest")
        added = temp_store.ingest_scan(report)
        assert added == 0


class TestVulnVectorStoreClear:
    def test_clear_removes_all(self, temp_store, sample_documents):
        temp_store.ingest_documents(sample_documents)
        assert temp_store.count == 3
        temp_store.clear()
        assert temp_store.count == 0

    def test_clear_empty_store(self, temp_store):
        temp_store.clear()
        assert temp_store.count == 0
