from __future__ import annotations

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
    def __init__(
        self,
        vector_store: VulnVectorStore | None = None,
        model: str | None = None,
        n_results: int = 5,
    ):
        self._store = vector_store or VulnVectorStore()
        self._n_results = n_results
        self._model_name = model
        self._llm = None
        self._parser = StrOutputParser()

    def _get_llm(self):
        if self._llm is None:
            kwargs = {}
            if self._model_name:
                kwargs["model"] = self._model_name
            self._llm = get_llm(**kwargs)
        return self._llm

    def _retrieve_context(self, query: str) -> str:
        results = self._store.query(query, n_results=self._n_results)
        if not results:
            return "No relevant vulnerability data found in the knowledge base."

        context_parts = []
        for r in results:
            context_parts.append(f"---\n{r['text']}\n")
        return "\n".join(context_parts)

    def explain_cve(self, cve_id: str) -> str:
        context = self._retrieve_context(cve_id)
        chain = EXPLAIN_CVE_PROMPT | self._get_llm() | self._parser
        return chain.invoke({"context": context, "question": f"Explain {cve_id}"})

    def suggest_fixes(self, scan_summary: str) -> str:
        context = self._retrieve_context(scan_summary)
        chain = SUGGEST_FIX_PROMPT | self._get_llm() | self._parser
        return chain.invoke({"context": context, "scan_summary": scan_summary})

    def review_dockerfile(
        self,
        dockerfile_content: str,
        scan_summary: str | None = None,
    ) -> str:
        context = self._retrieve_context(f"Dockerfile security {dockerfile_content[:200]}")
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
        scan_context: str | None = None,
        dockerfile: str | None = None,
    ) -> str:
        combined_query = question
        if scan_context:
            combined_query += f"\n\nScan context: {scan_context[:500]}"

        context = self._retrieve_context(combined_query)

        if dockerfile:
            return self.review_dockerfile(dockerfile, scan_context)

        chain = GENERAL_QUERY_PROMPT | self._get_llm() | self._parser
        return chain.invoke({"context": context, "question": question})
