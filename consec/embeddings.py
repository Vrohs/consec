from __future__ import annotations

from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

DEFAULT_MODEL_NAME = "all-MiniLM-L6-v2"


def get_embedding_function(
    model_name: str = DEFAULT_MODEL_NAME,
) -> SentenceTransformerEmbeddingFunction:
    return SentenceTransformerEmbeddingFunction(model_name=model_name)
