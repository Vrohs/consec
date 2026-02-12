from __future__ import annotations

from pathlib import Path

import chromadb

from consec.embeddings import get_embedding_function
from consec.models import TrivyReport
from consec.parser import extract_vulnerabilities, to_documents
from consec.utils import CHROMA_DIR, ensure_dirs

COLLECTION_NAME = "consec_vulns"


class VulnVectorStore:
    def __init__(self, persist_dir: str | Path | None = None):
        self._persist_dir = Path(persist_dir) if persist_dir else CHROMA_DIR
        ensure_dirs()
        self._client = chromadb.PersistentClient(path=str(self._persist_dir))
        self._embedding_fn = get_embedding_function()
        self._collection = self._client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=self._embedding_fn,
            metadata={"description": "Container vulnerability data for RAG"},
        )

    @property
    def count(self) -> int:
        return self._collection.count()

    def ingest_documents(self, documents: list[dict]) -> int:
        if not documents:
            return 0

        existing_ids = set(self._collection.get()["ids"])
        new_docs = [d for d in documents if d["id"] not in existing_ids]

        if not new_docs:
            return 0

        self._collection.add(
            ids=[d["id"] for d in new_docs],
            documents=[d["text"] for d in new_docs],
            metadatas=[d["metadata"] for d in new_docs],
        )

        return len(new_docs)

    def ingest_scan(self, report: TrivyReport) -> int:
        vulns = extract_vulnerabilities(report)
        docs = to_documents(vulns)
        return self.ingest_documents(docs)

    def query(self, query_text: str, n_results: int = 5) -> list[dict]:
        if self.count == 0:
            return []

        actual_n = min(n_results, self.count)
        results = self._collection.query(
            query_texts=[query_text],
            n_results=actual_n,
        )

        output = []
        for i in range(len(results["ids"][0])):
            output.append(
                {
                    "id": results["ids"][0][i],
                    "text": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                    "distance": (
                        results["distances"][0][i] if results.get("distances") else None
                    ),
                }
            )

        return output

    def clear(self) -> None:
        self._client.delete_collection(COLLECTION_NAME)
        self._collection = self._client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=self._embedding_fn,
            metadata={"description": "Container vulnerability data for RAG"},
        )
