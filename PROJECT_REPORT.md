# PROJECT/INTERNSHIP SYNOPSIS

## **consec - LLM-Powered Container Security Assistant**

**Department of Computer Science and Engineering**

Submitted in Partial Fulfillment of the Degree of BE (CSE)

**Chitkara University, Himachal Pradesh**

---

## 1. Introduction to the Project (Brief)

### 1.1 Overview

**consec** (Container Security) is a command-line tool built in Python that enhances container vulnerability scanning with Artificial Intelligence. It integrates with Trivy, a widely-used open-source container vulnerability scanner, and augments its raw output with natural-language explanations, actionable remediation advice, and static Dockerfile security analysis — all powered by locally-running Large Language Models (LLMs) via Ollama.

The tool is designed with three core principles: **zero-cost** (no paid API dependencies), **privacy-first** (all data processing happens on the user's machine), and **offline-capable** (works without internet after initial setup).

### 1.2 Problem Statement

Modern software development increasingly relies on containerized applications deployed via Docker. However, securing these containers presents significant challenges:

1. **Vulnerability overload:** A single container image can contain hundreds of known vulnerabilities (CVEs). Tools like Trivy report these as raw data — CVE IDs, severity scores, affected package versions — which is difficult for developers without security expertise to interpret.

2. **Lack of actionable guidance:** Existing scanners tell you *what* is wrong but not *how to fix it* in the context of your specific container configuration.

3. **Dockerfile misconfigurations:** Many security issues originate not from vulnerable packages but from insecure Dockerfile practices — running as root, exposing sensitive ports, hardcoding secrets, using unpinned base images.

4. **Manual cross-referencing:** Developers must manually correlate vulnerability data with Dockerfile configuration, NVD advisories, and package changelogs to determine the appropriate remediation.

**consec addresses these gaps** by combining traditional vulnerability scanning with Retrieval-Augmented Generation (RAG) to produce context-aware, human-readable security analysis.

### 1.3 Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Language | **Python 3.10+** | Core implementation |
| CLI Framework | **Typer** | Command-line interface with argument parsing |
| Terminal UI | **Rich** | Color-coded tables, panels, progress spinners |
| Data Validation | **Pydantic v2** | JSON schema validation for Trivy output |
| Vector Database | **ChromaDB** | Persistent semantic search over vulnerability data |
| Embeddings | **Sentence-Transformers** (all-MiniLM-L6-v2) | 384-dimensional vector embeddings for CVE documents |
| LLM Orchestration | **LangChain** | RAG pipeline construction and prompt management |
| Local LLM | **Ollama** (llama3.1:8b) | On-device inference for natural-language generation |
| Testing | **pytest** | Unit, integration, and BDD testing |
| Linting | **Ruff** | Code quality enforcement |
| CI/CD | **GitHub Actions** | Automated linting, testing (3 Python versions), Docker builds |
| Containerization | **Docker** (multi-stage) | Production-ready container image with non-root execution |

### 1.4 Key Technical Concepts

- **Trivy:** An open-source vulnerability scanner by Aqua Security that detects CVEs in container images, filesystems, and code repositories. It outputs structured JSON reports listing every known vulnerability in an image's packages.

- **RAG (Retrieval-Augmented Generation):** An AI architecture that combines information retrieval with text generation. Instead of relying solely on an LLM's training data, RAG first retrieves relevant documents from a knowledge base, then feeds them as context to the LLM for more accurate, grounded responses.

- **CVE (Common Vulnerabilities and Exposures):** A standardized system for identifying publicly known security vulnerabilities. Each CVE has a unique ID (e.g., CVE-2024-6119) and severity rating (CRITICAL, HIGH, MEDIUM, LOW).

- **Ollama:** A tool for running large language models locally on consumer hardware. It eliminates the need for cloud API calls, ensuring data privacy and zero operational cost.

- **Vector Embeddings:** Numerical representations of text that capture semantic meaning. Similar texts have similar vectors, enabling semantic search — finding documents related to a query by meaning, not just keyword matching.

### 1.5 Features

The tool provides **7 CLI commands**:

| Command | Description | Requires LLM? |
|---------|-------------|:-:|
| `consec scan <image>` | Scan a Docker image using Trivy and display a formatted vulnerability summary | No |
| `consec parse <json>` | Parse and display an existing Trivy JSON scan report | No |
| `consec ingest <json>` | Ingest vulnerability data into the ChromaDB vector store for RAG queries | No |
| `consec query <question>` | Ask natural-language security questions, answered via RAG with LLM | Yes |
| `consec review <dockerfile>` | AI-powered security review of a Dockerfile, correlated with scan data | Yes |
| `consec check <dockerfile>` | Run 10 static security rules against a Dockerfile (no LLM required) | No |
| `consec export <json> <output>` | Export scan results as Markdown or JSON reports | No |

Additionally, the tool implements **10 Dockerfile security rules** (CSC-001 to CSC-010):

| Rule ID | Severity | Issue Detected |
|---------|----------|----------------|
| CSC-001 | HIGH | Unpinned or `:latest` base images |
| CSC-002 | HIGH | Container running as root user |
| CSC-003 | MEDIUM | Missing HEALTHCHECK instruction |
| CSC-004 | MEDIUM | Broad `COPY .` copying entire build context |
| CSC-005 | LOW | apt package cache not cleaned in same layer |
| CSC-006 | HIGH | Secrets (passwords, tokens, API keys) hardcoded in ENV |
| CSC-007 | LOW | `ADD` used where `COPY` is more appropriate |
| CSC-008 | MEDIUM | SSH port (22) exposed |
| CSC-009 | MEDIUM | Pipe-to-shell patterns (`curl \| sh`, `wget \| bash`) |
| CSC-010 | LOW | No multi-stage build (larger attack surface) |

---

## 2. Literature Survey

### 2.1 Existing Container Security Tools

| Tool | Developer | Approach | Limitations |
|------|-----------|----------|-------------|
| **Trivy** | Aqua Security | Scans container images, filesystems, and repos for CVEs | Raw data output; no remediation guidance; no Dockerfile analysis |
| **Snyk Container** | Snyk | Commercial vulnerability scanning with fix suggestions | Cloud-dependent; paid tiers; data leaves the machine |
| **Docker Scout** | Docker Inc. | Image analysis integrated into Docker Desktop | Tied to Docker ecosystem; limited offline capability |
| **Clair** | Quay/Red Hat | Static analysis of container layers | Complex setup; no LLM integration; no Dockerfile review |
| **Grype** | Anchore | Vulnerability scanner for container images | Similar to Trivy — raw output, no AI-powered analysis |
| **Hadolint** | GitHub community | Dockerfile linter based on best practices | Rule-based only; no vulnerability correlation; no LLM |
| **Dockle** | Goodwith Tech | Container image linter for CIS benchmarks | Image-level only; no Dockerfile source analysis |

### 2.2 Gap Analysis

No existing tool combines all three capabilities:
1. **Vulnerability scanning** (what CVEs exist)
2. **Static Dockerfile analysis** (what misconfigurations exist)
3. **AI-powered explanation and remediation** (what to do about it)

consec is the first open-source tool to unify these three aspects using locally-running LLMs, ensuring privacy and zero operational cost.

### 2.3 Related Research

- **RAG (Lewis et al., 2020):** "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks" introduced the RAG architecture that consec adapts for security analysis. By grounding LLM responses in retrieved CVE data, consec avoids hallucinations common in pure LLM approaches.

- **LLM for Security (OWASP, 2023):** The OWASP Foundation has documented how LLMs can assist in security analysis, while noting the importance of grounding responses in authoritative data sources — exactly what consec's RAG pipeline achieves.

- **Sentence-BERT (Reimers & Gurevych, 2019):** The all-MiniLM-L6-v2 embedding model used by consec is based on this work, enabling efficient semantic similarity search over vulnerability descriptions.

---

## 3. Methodology / Planning of Work

### 3.1 Development Methodology

The project follows an **iterative development** approach with 4 phases:

**Phase 1 — Foundation (Core Infrastructure)**
- Implemented Pydantic data models for Trivy JSON schema
- Built Trivy JSON parser with validation
- Created Dockerfile parser for extracting directives
- Set up ChromaDB vector store with Sentence-Transformer embeddings
- Integrated Ollama via LangChain for LLM inference
- Designed 4 specialized prompt templates (CVE explanation, fix suggestion, Dockerfile review, general query)
- Implemented 5 CLI commands: scan, parse, ingest, query, review

**Phase 2 — Code Quality & Modernization**
- Removed verbose docstrings for cleaner codebase
- Modernized type hints to Python 3.10+ syntax (`X | None`)
- Consolidated duplicate parsing modules
- Enforced consistent formatting with Ruff

**Phase 3 — CI/CD & Containerization**
- Created GitHub Actions pipeline with 3 parallel jobs (lint, test, Docker build)
- Test matrix across Python 3.10, 3.11, and 3.12
- Built multi-stage Dockerfile with non-root user execution
- Added health checks and Docker-specific Ollama configuration

**Phase 4 — Static Analysis & Export**
- Implemented 10 Dockerfile security rules (CSC-001 to CSC-010)
- Added `check` command for offline, deterministic analysis
- Built Markdown and JSON report exporter
- Added comprehensive CLI test suite
- Integrated coverage badge generation in CI

### 3.2 System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      consec CLI (Typer)                   │
│   scan  |  parse  |  ingest  |  query  |  review  |  check  |  export   │
└────┬─────────┬──────────┬─────────┬──────────┬──────────┬─────────┬─────┘
     │         │          │         │          │          │         │
     ▼         ▼          │         │          │          ▼         ▼
┌─────────┐ ┌──────────┐ │    ┌─────────┐    │   ┌───────────┐ ┌──────────┐
│  Trivy  │ │  Parser  │ │    │   RAG   │    │   │  Rules    │ │ Exporter │
│ Scanner │ │ Module   │ │    │  Chain  │    │   │  Engine   │ │ (MD/JSON)│
└────┬────┘ └────┬─────┘ │    └────┬────┘    │   │(10 rules) │ └──────────┘
     │           │        │         │         │   └───────────┘
     ▼           ▼        ▼         ▼         ▼
┌─────────────────────────────┐  ┌──────────────────┐
│      Pydantic Models        │  │   LangChain +    │
│  (TrivyReport, Vulnerability│  │   Ollama (LLM)   │
│   Result, Severity, CVSS)   │  │  temperature=0.1 │
└──────────────┬──────────────┘  └────────┬─────────┘
               │                          │
               ▼                          │
       ┌───────────────┐                  │
       │   ChromaDB    │◄─────────────────┘
       │ Vector Store  │  (semantic retrieval)
       │ + Sentence-   │
       │ Transformers  │
       └───────────────┘
```

### 3.3 RAG Pipeline Flow

1. **Ingestion:** Trivy JSON is parsed into structured vulnerability objects. Each CVE is converted to a text document and embedded into a 384-dimensional vector using Sentence-Transformers (all-MiniLM-L6-v2). Vectors are stored in ChromaDB with metadata (CVE ID, severity, package, versions).

2. **Retrieval:** When a user asks a question, the query is embedded using the same model. ChromaDB performs a cosine similarity search to find the top-5 most relevant CVE documents.

3. **Augmented Generation:** Retrieved CVE documents are formatted as context and injected into a LangChain prompt template along with the user's question. The complete prompt is sent to the local Ollama LLM (llama3.1:8b) with low temperature (0.1) for consistent, factual responses.

4. **Response:** The LLM generates a structured response with sections for Summary, Impact, and Remediation — grounded in actual vulnerability data from the user's scans.

---

## 4. Facilities Required for Proposed Work

### 4.1 Software Requirements

| Software | Version | Purpose |
|----------|---------|---------|
| Python | 3.10 or higher | Core runtime |
| pip | Latest | Package management |
| Ollama | Latest | Local LLM inference server |
| Trivy | Latest | Container vulnerability scanning |
| Docker | Latest (optional) | Container image building and scanning |
| Git | Latest | Version control |
| OS | Linux / macOS / Windows (WSL2) | Development and execution |

### 4.2 Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16 GB (for LLM inference) |
| Storage | 10 GB free | 20 GB (for models + vector DB) |
| GPU | Not required | NVIDIA GPU with CUDA (faster inference) |

### 4.3 Python Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| typer | >= 0.9.0 | CLI framework |
| rich | >= 13.0.0 | Terminal formatting |
| pydantic | >= 2.0.0 | Data validation |
| chromadb | >= 0.4.0 | Vector database |
| sentence-transformers | >= 2.2.0 | Text embeddings |
| langchain | >= 0.2.0 | LLM orchestration |
| langchain-ollama | >= 0.1.0 | Ollama integration |
| requests | >= 2.31.0 | HTTP client |

### 4.4 Development Dependencies

| Package | Purpose |
|---------|---------|
| pytest | Test framework |
| pytest-cov | Code coverage |
| pytest-mock | Mocking utilities |
| ruff | Linting and formatting |


---

## 5. References

1. Lewis, P., Perez, E., Piktus, A., et al. (2020). "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks." *Advances in Neural Information Processing Systems (NeurIPS)*.

2. Reimers, N., & Gurevych, I. (2019). "Sentence-BERT: Sentence Embeddings using Siamese BERT-Networks." *Proceedings of EMNLP-IJCNLP*.

3. OWASP Foundation (2023). "OWASP Top 10 for Large Language Model Applications." https://owasp.org/www-project-top-10-for-large-language-model-applications/

4. Aqua Security. "Trivy — Comprehensive Security Scanner." https://trivy.dev/

5. Ollama. "Run Large Language Models Locally." https://ollama.com/

6. LangChain Documentation. "Building Applications with LLMs." https://python.langchain.com/

7. Docker Documentation. "Dockerfile Best Practices." https://docs.docker.com/develop/develop-images/dockerfile_best-practices/

8. NIST National Vulnerability Database (NVD). https://nvd.nist.gov/

9. CIS Docker Benchmark. "Center for Internet Security." https://www.cisecurity.org/benchmark/docker

10. ChromaDB Documentation. "The AI-native Open-source Embedding Database." https://www.trychroma.com/

---

## 6. Project Metrics Summary

| Metric | Value |
|--------|-------|
| Total source code | ~1,500 lines across 12 modules |
| Total test code | ~1,500+ lines across 8 test files |
| Test methods | 100+ |
| CLI commands | 7 |
| Security rules | 10 (CSC-001 to CSC-010) |
| LLM prompt templates | 4 |
| Export formats | 2 (Markdown, JSON) |
| CI/CD jobs | 3 (lint, test, Docker build) |
| Python versions tested | 3 (3.10, 3.11, 3.12) |
| Git commits | 8 |
| Repository | https://github.com/Vrohs/consec |
| License | MIT |
