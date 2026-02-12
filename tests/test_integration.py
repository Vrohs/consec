from pathlib import Path

import pytest

from consec.parser import extract_vulnerabilities, parse_trivy_json, to_documents
from consec.vectordb import VulnVectorStore


SAMPLE_SCAN_DIR = Path(__file__).parent.parent / "data" / "sample_scans"


class TestEndToEndParseIngestQuery:
    def test_parse_ingest_query_flow(self, tmp_path):
        report = parse_trivy_json(SAMPLE_SCAN_DIR / "nginx_scan.json")
        assert report.total_vulnerabilities == 6

        vulns = extract_vulnerabilities(report)
        docs = to_documents(vulns)
        assert len(docs) == 6

        store = VulnVectorStore(persist_dir=tmp_path / "integration_chroma")
        added = store.ingest_scan(report)
        assert added == 6

        results = store.query("openssl buffer overread", n_results=2)
        assert len(results) == 2
        cve_ids = [r["id"] for r in results]
        assert "CVE-2024-5535" in cve_ids

        results = store.query("HTTP/2 Rapid Reset", n_results=1)
        assert results[0]["id"] == "CVE-2023-44487"

        store.clear()

    def test_empty_scan_does_not_break_pipeline(self, tmp_path):
        report = parse_trivy_json(SAMPLE_SCAN_DIR / "alpine_clean.json")
        assert report.total_vulnerabilities == 0

        vulns = extract_vulnerabilities(report)
        assert vulns == []

        docs = to_documents(vulns)
        assert docs == []

        store = VulnVectorStore(persist_dir=tmp_path / "empty_chroma")
        added = store.ingest_documents(docs)
        assert added == 0

        results = store.query("anything")
        assert results == []

        store.clear()

    def test_multiple_scans_accumulate(self, tmp_path):
        store = VulnVectorStore(persist_dir=tmp_path / "multi_chroma")

        report1 = parse_trivy_json(SAMPLE_SCAN_DIR / "nginx_scan.json")
        added1 = store.ingest_scan(report1)
        assert added1 == 6

        added2 = store.ingest_scan(report1)
        assert added2 == 0
        assert store.count == 6

        store.clear()


@pytest.mark.requires_ollama
class TestEndToEndWithLLM:
    def test_full_rag_query(self, tmp_path):
        from consec.rag import SecurityRAGChain

        report = parse_trivy_json(SAMPLE_SCAN_DIR / "nginx_scan.json")
        store = VulnVectorStore(persist_dir=tmp_path / "llm_chroma")
        store.ingest_scan(report)

        chain = SecurityRAGChain(vector_store=store)
        response = chain.ask("What is CVE-2024-6119 and how do I fix it?")
        assert len(response) > 50
        assert "CVE-2024-6119" in response or "openssl" in response.lower()

        store.clear()
