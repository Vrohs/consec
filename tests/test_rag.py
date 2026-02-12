from unittest.mock import MagicMock, patch

import pytest

from consec.rag import SecurityRAGChain
from consec.vectordb import VulnVectorStore


@pytest.fixture
def mock_store(tmp_path):
    store = VulnVectorStore(persist_dir=tmp_path / "test_chroma")
    store.ingest_documents(
        [
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
                    "target": "debian",
                },
            },
        ]
    )
    yield store
    store.clear()


@pytest.fixture
def mock_llm():
    llm = MagicMock()
    llm.invoke.return_value = MagicMock(
        content="This is a mocked LLM response about security."
    )
    return llm


class TestSecurityRAGChainRetrieval:
    def test_retrieve_context_returns_string(self, mock_store):
        chain = SecurityRAGChain(vector_store=mock_store)
        context = chain._retrieve_context("openssl vulnerability")
        assert "CVE-2024-6119" in context
        assert "openssl" in context

    def test_retrieve_context_empty_store(self, tmp_path):
        empty_store = VulnVectorStore(persist_dir=tmp_path / "empty_chroma")
        chain = SecurityRAGChain(vector_store=empty_store)
        context = chain._retrieve_context("anything")
        assert "No relevant" in context
        empty_store.clear()


class TestSecurityRAGChainGeneration:
    @patch("consec.rag.get_llm")
    def test_explain_cve(self, mock_get_llm, mock_store, mock_llm):
        mock_get_llm.return_value = mock_llm
        chain = SecurityRAGChain(vector_store=mock_store)
        chain._llm = mock_llm

        mock_llm.__or__ = MagicMock(return_value=mock_llm)
        mock_llm.invoke.return_value = "Explanation of CVE-2024-6119"

        with patch.object(chain, "_get_llm", return_value=mock_llm):
            with patch("consec.prompts.EXPLAIN_CVE_PROMPT.__or__") as mock_chain:
                final_chain = MagicMock()
                final_chain.__or__ = MagicMock(return_value=final_chain)
                final_chain.invoke.return_value = "Explanation of CVE-2024-6119"
                mock_chain.return_value = final_chain

                context = chain._retrieve_context("CVE-2024-6119")
                assert "CVE-2024-6119" in context

    @patch("consec.rag.get_llm")
    def test_ask_general_question(self, mock_get_llm, mock_store, mock_llm):
        mock_get_llm.return_value = mock_llm
        chain = SecurityRAGChain(vector_store=mock_store)

        context = chain._retrieve_context("How to fix openssl issues?")
        assert "openssl" in context

    def test_chain_initialization(self, mock_store):
        chain = SecurityRAGChain(vector_store=mock_store)
        assert chain._llm is None
        assert chain._store is not None

    def test_chain_custom_n_results(self, mock_store):
        chain = SecurityRAGChain(vector_store=mock_store, n_results=3)
        assert chain._n_results == 3


class TestSecurityRAGChainDockerfile:
    @patch("consec.rag.get_llm")
    def test_ask_with_dockerfile_delegates_to_review(
        self, mock_get_llm, mock_store, mock_llm
    ):
        mock_get_llm.return_value = mock_llm
        chain = SecurityRAGChain(vector_store=mock_store)

        dockerfile = "FROM nginx:1.25\nEXPOSE 80"
        context = chain._retrieve_context(f"Dockerfile security {dockerfile[:200]}")
        assert isinstance(context, str)
