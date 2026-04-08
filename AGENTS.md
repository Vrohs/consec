# AGENTS.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

**consec** is an LLM-powered container security assistant that enhances Trivy vulnerability scans with RAG (Retrieval-Augmented Generation) using local LLMs via Ollama. It parses Trivy JSON output, stores vulnerability data in ChromaDB, and uses LangChain to provide natural-language explanations, remediations, and Dockerfile security reviews.

## Build & Development Commands

```bash
# Install in development mode (inside a venv)
pip install -e ".[dev]"

# Run all tests (excluding those needing Ollama)
pytest tests/ -v -m "not requires_ollama"

# Run all tests (requires Ollama running locally)
pytest tests/ -v

# Run a single test file
pytest tests/test_parser.py -v

# Run a single test class or method
pytest tests/test_parser.py::TestParseTrivyJson::test_parse_valid_file -v

# Run with coverage
pytest tests/ -v --cov=consec --cov-report=term-missing

# Lint
ruff check consec/ tests/

# Lint with auto-fix
ruff check --fix consec/ tests/
```

## Prerequisites

- **Python 3.10+**
- **Ollama** running locally (for LLM features; not needed for parsing/ingestion/rule checks)
- Default model: `llama3.1:8b` (override via `CONSEC_MODEL` env var)
- Ollama URL defaults to `http://localhost:11434` (override via `OLLAMA_BASE_URL`)

## Architecture

The CLI entry point is `consec/cli.py` which defines a Typer app with these commands: `scan`, `parse`, `ingest`, `query`, `review`, `check`. The `consec` script entry point is registered in `pyproject.toml` as `consec.cli:app`.

### Data Flow

1. **Parse**: `parser.py` reads Trivy JSON (file or string) into Pydantic models defined in `models.py`. It also parses Dockerfiles into `DockerfileInfo` dataclasses.
2. **Ingest**: `vectordb.py` (`VulnVectorStore`) converts parsed vulnerabilities into documents and stores them in a persistent ChromaDB collection. Embeddings are generated via sentence-transformers (`all-MiniLM-L6-v2`) in `embeddings.py`.
3. **Query/Review**: `rag.py` (`SecurityRAGChain`) retrieves relevant docs from ChromaDB, then pipes them through LangChain prompt templates (`prompts.py`) to an Ollama-backed `ChatOllama` LLM (`llm.py`). The LLM is lazily initialized on first use.
4. **Check (static)**: `rules.py` runs rule-based Dockerfile checks (rule IDs `CSC-001` through `CSC-008`) without requiring an LLM. This is a fully offline static analysis path.

### Key Design Patterns

- **Pydantic models with aliased fields**: `models.py` uses `Field(alias="...")` with `populate_by_name=True` to map Trivy's PascalCase JSON keys to snake_case Python attributes. When constructing models in tests, use the alias names (e.g., `VulnerabilityID=`, not `vulnerability_id=`).
- **Lazy LLM initialization**: `SecurityRAGChain` defers Ollama connection until `_get_llm()` is first called, so parsing/ingestion paths never touch the LLM.
- **Deduplication**: `to_documents()` in `parser.py` deduplicates vulnerabilities by CVE ID before ingestion.
- **Rich console output**: All user-facing display goes through `utils.py` helpers using the `rich` library.

## Test Conventions

- Tests use `pytest` with `pytest-mock` and `pytest-bdd`.
- Test markers: `integration`, `slow`, `requires_ollama`. Most unit tests run without Ollama.
- Sample scan data lives in `data/sample_scans/` (`nginx_scan.json`, `alpine_clean.json`) and is referenced by tests via `Path(__file__).parent.parent / "data" / "sample_scans"`.
- Integration tests in `test_integration.py` use `tmp_path` for isolated ChromaDB instances.

## Ruff Configuration

- Target: Python 3.10
- Line length: 100
- Enabled rule sets: E, F, I, N, W, UP (see `pyproject.toml [tool.ruff.lint]`)

## Environment Variables

- `CONSEC_HOME` — data directory (default: `~/.consec`), contains the ChromaDB persistence directory
- `CONSEC_MODEL` — Ollama model name (default: `llama3.1:8b`)
- `OLLAMA_BASE_URL` — Ollama server URL (default: `http://localhost:11434`)
