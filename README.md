# 🔒 consec — LLM-Powered Container Security Assistant

**consec** enhances [Trivy](https://trivy.dev/) container vulnerability scans with **RAG** (Retrieval-Augmented Generation) and **local LLMs** for natural-language explanations, remediations, and context-aware Dockerfile advice.

> Zero-cost • Offline-capable • Privacy-first

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

---

## Architecture

```
Trivy JSON ──► consec parse ──► Parsed CVEs ──► ChromaDB (Vector Store)
                                                      │
User Query ──► consec query ──► Retrieve top-k docs ──┤
                                                      ▼
                                              LangChain RAG Chain
                                                      │
                              Dockerfile context ──────┤
                                                      ▼
                                              Ollama (Local LLM)
                                                      │
                                                      ▼
                                          Natural Language Response
```

## Quick Start

### Prerequisites

- **Python 3.10+**
- **[Ollama](https://ollama.ai/download)** — for local LLM inference
- **[Trivy](https://aquasecurity.github.io/trivy/)** — for container scanning (optional, can use existing JSON)
- **Docker** — for scanning images (optional)

### Installation

```bash
# Clone the repository
git clone https://github.com/Vrohs/consec.git
cd consec

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Pull an LLM model
ollama pull llama3.1:8b
```

### Usage

```bash
# Scan a Docker image
consec scan nginx:latest

# Parse an existing Trivy JSON file
consec parse data/sample_scans/nginx_scan.json

# Ingest scan data into the vector database
consec ingest data/sample_scans/nginx_scan.json

# Ask about a specific CVE
consec query "Explain CVE-2024-6119 and how to fix it"

# Interactive Q&A mode
consec query --interactive "What are the most critical vulnerabilities?"

# Review a Dockerfile for security issues
consec review Dockerfile --scan data/sample_scans/nginx_scan.json
```

### Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `CONSEC_HOME` | `~/.consec` | Data directory |
| `CONSEC_MODEL` | `llama3.1:8b` | Default Ollama model |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |

## Development

```bash
# Run tests (excluding tests that need Ollama)
pytest tests/ -v -m "not requires_ollama"

# Run all tests (requires Ollama running)
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=consec --cov-report=term-missing

# Lint
ruff check consec/ tests/
```

## Project Structure

```
consec/
├── consec/             # Main package
│   ├── cli.py          # Typer CLI commands
│   ├── models.py       # Pydantic data models (Trivy schema)
│   ├── parser.py       # Trivy JSON & Dockerfile parser
│   ├── vectordb.py     # ChromaDB vector store
│   ├── embeddings.py   # Sentence-transformer embeddings
│   ├── llm.py          # Ollama LLM integration
│   ├── prompts.py      # LangChain prompt templates
│   ├── rag.py          # RAG chain orchestration
│   └── utils.py        # Display helpers & config
├── data/sample_scans/  # Sample Trivy JSON outputs
├── tests/              # Comprehensive test suite
├── pyproject.toml      # Project configuration
└── requirements.txt    # Dependencies
```

## License

MIT — see [LICENSE](LICENSE).
