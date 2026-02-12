from __future__ import annotations

import requests
from langchain_ollama import ChatOllama

from consec.utils import DEFAULT_MODEL, OLLAMA_BASE_URL


class OllamaConnectionError(Exception):
    pass


def check_ollama_connection(base_url: str = OLLAMA_BASE_URL) -> bool:
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=5)
        resp.raise_for_status()
        return True
    except (requests.ConnectionError, requests.Timeout, requests.HTTPError) as e:
        raise OllamaConnectionError(
            f"Cannot connect to Ollama at {base_url}.\n"
            "Please ensure Ollama is installed and running:\n"
            "  1. Install: https://ollama.ai/download\n"
            "  2. Start:   ollama serve\n"
            f"  3. Pull a model: ollama pull {DEFAULT_MODEL}\n"
            f"Error: {e}"
        ) from e


def get_available_models(base_url: str = OLLAMA_BASE_URL) -> list[str]:
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


def get_llm(
    model: str = DEFAULT_MODEL,
    base_url: str = OLLAMA_BASE_URL,
    temperature: float = 0.1,
    num_predict: int = 1024,
) -> ChatOllama:
    check_ollama_connection(base_url)

    return ChatOllama(
        model=model,
        base_url=base_url,
        temperature=temperature,
        num_predict=num_predict,
    )
