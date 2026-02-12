"""RAG chain orchestration — retrieve, augment, generate."""

from __future__ import annotations

from typing import Optional

from langchain_core.output_parsers import StrOutputParser

from consec.llm import get_llm
from consec.prompts import (
    DOCKERFILE_REVIEW_PROMPT,
    EXPLAIN_CVE_PROMPT,
    GENERAL_QUERY_PROMPT,
    SUGGEST_FIX_PROMPT,
)
from consec.vectordb import VulnVectorStore


class SecurityRAGChain:
    """Orchestrates the RAG pipeline: retrieve context → augment prompt → generate response."""

    def __init__(
        self,
        vector_store: VulnVectorStore | None = None,
        model: str | None = None,
        n_results: int = 5,
    ):
        """Initialize the RAG chain.

        Args:
            vector_store: Pre-configured VulnVectorStore. Creates one if None.
            model: Ollama model name. Uses default if None.
            n_results: Number of documents to retrieve per query.
        """
        self._store = vector_store or VulnVectorStore()
        self._n_results = n_results
        self._model_name = model
        self._llm = None
        self._parser = StrOutputParser()

    def _get_llm(self):
        """Lazy-load the LLM (allows deferring connection check)."""
        if self._llm is None:
            kwargs = {}
            if self._model_name:
                kwargs["model"] = self._model_name
            self._llm = get_llm(**kwargs)
        return self._llm

    def _retrieve_context(self, query: str) -> str:
        """Retrieve relevant documents and format as context string."""
        results = self._store.query(query, n_results=self._n_results)
        if not results:
            return "No relevant vulnerability data found in the knowledge base."

        context_parts = []
        for r in results:
            context_parts.append(f"---\n{r['text']}\n")
        return "\n".join(context_parts)

    def explain_cve(self, cve_id: str) -> str:
        """Explain a specific CVE with RAG context.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-6119').

        Returns:
            Natural language explanation of the CVE.
        """
        context = self._retrieve_context(cve_id)
        chain = EXPLAIN_CVE_PROMPT | self._get_llm() | self._parser
        return chain.invoke({"context": context, "question": f"Explain {cve_id}"})

    def suggest_fixes(self, scan_summary: str) -> str:
        """Suggest fixes for vulnerabilities in a scan.

        Args:
            scan_summary: Human-readable summary of scan findings.

        Returns:
            Prioritized fix suggestions.
        """
        context = self._retrieve_context(scan_summary)
        chain = SUGGEST_FIX_PROMPT | self._get_llm() | self._parser
        return chain.invoke({"context": context, "scan_summary": scan_summary})

    def review_dockerfile(
        self,
        dockerfile_content: str,
        scan_summary: Optional[str] = None,
    ) -> str:
        """Review a Dockerfile for security issues.

        Args:
            dockerfile_content: Raw Dockerfile text.
            scan_summary: Optional scan findings to correlate.

        Returns:
            Security review of the Dockerfile.
        """
        context = self._retrieve_context(
            f"Dockerfile security {dockerfile_content[:200]}"
        )
        chain = DOCKERFILE_REVIEW_PROMPT | self._get_llm() | self._parser
        return chain.invoke(
            {
                "context": context,
                "dockerfile": dockerfile_content,
                "scan_summary": scan_summary or "No scan data available.",
            }
        )

    def ask(
        self,
        question: str,
        scan_context: Optional[str] = None,
        dockerfile: Optional[str] = None,
    ) -> str:
        """General-purpose security question with RAG context.

        Args:
            question: User's natural language question.
            scan_context: Optional scan results for additional context.
            dockerfile: Optional Dockerfile content.

        Returns:
            Natural language answer.
        """
        combined_query = question
        if scan_context:
            combined_query += f"\n\nScan context: {scan_context[:500]}"

        context = self._retrieve_context(combined_query)

        if dockerfile:
            return self.review_dockerfile(dockerfile, scan_context)

        chain = GENERAL_QUERY_PROMPT | self._get_llm() | self._parser
        return chain.invoke({"context": context, "question": question})
