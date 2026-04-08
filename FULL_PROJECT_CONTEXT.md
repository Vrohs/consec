# FULL PROJECT CONTEXT — consec

Everything you need to know to write reports, make slides, or answer any question about this project. This is a raw knowledge dump, not a formatted report.

---

## WHAT IS THIS PROJECT

**consec** = "Container Security". It's a Python CLI tool that makes container vulnerability scanning actually useful.

The problem: You run Trivy (an open-source scanner by Aqua Security) on a Docker image and it dumps 200+ CVEs as raw JSON — CVE IDs, CVSS scores, package versions. Unless you're a security engineer, this output is meaningless. You don't know what's dangerous, what to fix first, or how to fix it.

consec takes that raw output and:
1. Parses it into clean, color-coded terminal tables
2. Stores CVE data in a vector database (ChromaDB) for semantic search
3. Lets you ask questions in plain English ("What's the most critical vulnerability? How do I fix it?")
4. Uses a locally-running LLM (via Ollama) to generate explanations, impact assessments, and fix suggestions
5. Reviews your Dockerfile for 10 common security misconfigurations
6. Exports reports in Markdown or JSON

Everything runs on your machine. No cloud APIs. No data leaves. Zero cost.

---

## WHY IT MATTERS (FOR PRESENTATIONS)

Container security is a massive industry problem:
- 75%+ of container images in production have known HIGH/CRITICAL vulnerabilities (Sysdig 2023 report)
- Docker Hub has 15M+ images, many with unpatched CVEs
- Most developers ignore scanner output because it's too overwhelming
- Dockerfile misconfigurations (running as root, hardcoded secrets, unpinned images) are a separate class of risk that scanners don't catch

consec is novel because NO existing tool combines all three:
1. Vulnerability scanning (Trivy integration)
2. Static Dockerfile analysis (10 rules)
3. AI-powered explanation and remediation (RAG + local LLM)

The closest tools and what they lack:
- **Trivy** — great scanner, but raw output only, no AI, no Dockerfile review
- **Snyk** — has fix suggestions but it's cloud-based, paid, data leaves your machine
- **Docker Scout** — Docker ecosystem only, limited offline, no LLM
- **Hadolint** — Dockerfile linter only, no vulnerability correlation, no AI
- **Grype** — another scanner, same raw-output problem as Trivy
- **Clair** — complex setup, no LLM, no Dockerfile review
- **Dockle** — image linter for CIS benchmarks, no source analysis, no AI

---

## CORE TECHNOLOGY EXPLAINED

### RAG (Retrieval-Augmented Generation)
This is the key innovation. Regular LLMs hallucinate — they make stuff up. RAG solves this by:
1. Taking real vulnerability data from your actual scans
2. Converting each CVE into a 384-dimensional vector using Sentence-Transformers (all-MiniLM-L6-v2 model)
3. Storing vectors in ChromaDB (a vector database)
4. When you ask a question, your question is also converted to a vector
5. ChromaDB finds the 5 most semantically similar CVEs (cosine similarity)
6. Those real CVEs are injected as context into the LLM prompt
7. The LLM generates its answer grounded in real data, not hallucination

This is the same architecture behind ChatGPT's "search the web" feature, but applied to vulnerability data and running entirely locally.

### Ollama
Ollama lets you run LLMs on your laptop. consec defaults to `llama3.1:8b` — Meta's Llama 3.1 at 8 billion parameters. It's good enough for security analysis and runs on 8GB RAM. Temperature is set to 0.1 (very low) so answers are factual and consistent, not creative.

### LangChain
A Python framework for building LLM-powered applications. consec uses it for:
- **Prompt templates** — 4 specialized templates for different tasks (CVE explanation, fix suggestion, Dockerfile review, general query)
- **Chain composition** — The `prompt | llm | parser` pipe syntax that connects everything
- **Output parsing** — StrOutputParser to extract text from LLM responses

### ChromaDB
An open-source vector database. Stores vulnerability embeddings persistently at `~/.consec/chromadb/`. Supports semantic similarity search — "find CVEs similar to this question" even if the exact words don't match.

### Sentence-Transformers (all-MiniLM-L6-v2)
A lightweight (22.7M parameters) embedding model that converts text to 384-dimensional vectors. It's the same model used in many production RAG systems. Fast and accurate for semantic similarity.

### Pydantic v2
Data validation library. Every piece of Trivy JSON is validated against a strict schema (TrivyReport → Result → Vulnerability → CVSS). This catches malformed input early. The models use aliases to map Trivy's PascalCase JSON (`VulnerabilityID`) to Python's snake_case (`vulnerability_id`).

---

## THE 7 CLI COMMANDS — WHAT EACH ONE ACTUALLY DOES

### 1. `consec scan <image>` (cli.py:57-110)
- Runs `subprocess.run(["trivy", "image", "--format", "json", "--quiet", image])` with 300s timeout
- If Trivy not installed → helpful error with install URL
- If `--output file.json` → saves raw JSON to file
- Parses JSON into TrivyReport using Pydantic
- Displays severity summary table (CRITICAL/HIGH/MEDIUM/LOW counts)
- Extracts and filters vulnerabilities by `--severity` threshold
- Displays vulnerability table (CVE ID, Severity, Package, Installed Version, Fixed Version, Title)
- If `--ingest` flag → also ingests into ChromaDB vector store

### 2. `consec parse <json>` (cli.py:112-130)
- Reads a Trivy JSON file (already scanned, no Trivy needed)
- Same parsing + display as scan, just from a file instead of live scan
- Useful when you have scan results from CI/CD pipelines

### 3. `consec ingest <json>` (cli.py:133-143)
- Parses Trivy JSON → extracts vulnerabilities → deduplicates by CVE ID → converts to embedding documents → stores in ChromaDB
- Each document has: id (CVE ID), text (full vulnerability description for embedding), metadata (severity, package, versions, has_fix, target)
- Deduplication happens at two levels: parser deduplicates by CVE ID, and vector store checks existing IDs before adding
- Shows spinner during ingestion, then "Ingested X new documents (total: Y)"

### 4. `consec query <question>` (cli.py:146-187)
- Creates SecurityRAGChain (lazily initializes LLM on first use)
- If `--scan file.json` provided → parses it, takes first 20 vulnerabilities as context summaries
- If `--interactive` flag → enters REPL loop where you keep asking questions
- Normal mode: embeds question → searches ChromaDB for top-5 similar CVEs → formats as context → fills GENERAL_QUERY_PROMPT template → sends to Ollama → displays response in a Rich panel
- Interactive mode: same flow but in a loop with `consec>` prompt, type `quit` to exit

### 5. `consec review <dockerfile>` (cli.py:190-231)
- Reads Dockerfile from disk
- Optionally loads a Trivy scan JSON for correlation
- Creates SecurityRAGChain, calls review_dockerfile()
- RAG retrieves: searches "Dockerfile security {first 200 chars of Dockerfile}" in vector store
- Fills DOCKERFILE_REVIEW_PROMPT with: retrieved CVE context + Dockerfile content + scan summary
- LLM analyzes each directive, identifies risky lines, suggests corrections, rates severity
- Displays in a "Dockerfile Security Review" Rich panel

### 6. `consec check <dockerfile>` (cli.py:234-258)
- **No LLM required** — fully deterministic, offline
- Parses Dockerfile into DockerfileInfo dataclass (base images, stages, RUN commands, ports, env vars, COPY/ADD, user, entrypoint, cmd)
- Runs all 10 security check functions
- Displays findings table (Rule ID, Severity, Issue, Remediation)
- Exit code 1 if any HIGH/CRITICAL findings, exit code 0 otherwise

### 7. `consec export <json> <output>` (cli.py:261-294)
- Parses Trivy JSON, extracts and filters vulnerabilities
- `--format markdown` → Markdown report with severity summary table + vulnerability table
- `--format json` → structured JSON with generated_at timestamp, artifact_name, severity_counts, vulnerabilities array
- `--severity HIGH` → only include HIGH and above

---

## THE 10 SECURITY RULES — WHAT EACH DETECTS AND WHY

### CSC-001: Unpinned Base Image (HIGH)
**Detects:** `FROM node:latest` or `FROM ubuntu` (no version tag)
**Why dangerous:** `:latest` changes without warning. Your build today might use Ubuntu 22.04, tomorrow Ubuntu 24.04, breaking your app or introducing new CVEs. Supply chain attack vector — if a malicious image is pushed as `:latest`, your build pulls it automatically.
**Fix:** Pin to exact version: `FROM node:20.11-alpine` or digest: `FROM node@sha256:abc123...`
**How it works in code:** Checks each base_image — skips "scratch" and images with "@sha256:" digest. Flags if no ":" in image name, or if tag is "latest".

### CSC-002: Container Runs as Root (HIGH)
**Detects:** No `USER` directive or `USER root` or `USER 0`
**Why dangerous:** If the container is compromised, attacker has root. Can escape to host, read sensitive files, modify system. Violates principle of least privilege.
**Fix:** Add `USER 1000` or `USER nonroot` after installing packages.
**How it works:** Checks `info.runs_as_root` property → True if user is None, "", "root", or "0".

### CSC-003: Missing HEALTHCHECK (MEDIUM)
**Detects:** No HEALTHCHECK instruction in Dockerfile
**Why dangerous:** Container orchestrators (Kubernetes, Docker Swarm) can't tell if your app is actually running vs hung. Dead container keeps receiving traffic.
**Fix:** Add `HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1`
**How it works:** Checks `info.has_healthcheck` → looks for "HEALTHCHECK" in raw_content.

### CSC-004: Broad Source Copy (MEDIUM)
**Detects:** `COPY . /app` or `COPY ./ /app`
**Why dangerous:** Copies EVERYTHING from build context — .git directory (with secrets in history), .env files, node_modules, test data, credentials. Bloats image and leaks sensitive data.
**Fix:** Use `.dockerignore` and copy specific files: `COPY package.json package-lock.json ./`
**How it works:** Checks each copy_add_command for source being "." or "./" (split by space, check first arg after COPY/ADD).

### CSC-005: apt Cache Not Cleaned (LOW)
**Detects:** `apt-get update` in a RUN command without `rm -rf /var/lib/apt/lists` in the same command
**Why dangerous:** Leaves package cache in the image layer — wastes 30-100MB per layer, increases attack surface (cached package metadata).
**Fix:** Chain cleanup in same RUN: `RUN apt-get update && apt-get install -y pkg && rm -rf /var/lib/apt/lists/*`
**How it works:** For each run_command, checks if "apt-get update" is present but "/var/lib/apt/lists" is not.

### CSC-006: Secrets in ENV (HIGH)
**Detects:** ENV variables with names matching PASSWORD, SECRET, TOKEN, API_KEY, PRIVATE_KEY, AWS_ACCESS, AWS_SECRET
**Why dangerous:** ENV values are baked into the image layer and visible to anyone with `docker inspect` or `docker history`. They persist in image registries forever.
**Fix:** Use Docker secrets, `--secret` flag in BuildKit, or pass at runtime: `docker run -e DB_PASSWORD=$DB_PASSWORD`
**How it works:** Regex `SENSITIVE_ENV_PATTERNS` matches against each env_var's key (part before "=").

### CSC-007: ADD Misuse (LOW)
**Detects:** `ADD` used for files that aren't tar archives or URLs
**Why dangerous:** ADD has implicit tar extraction and URL fetching behavior that COPY doesn't. Using ADD when you mean COPY is confusing and can have unintended side effects.
**Fix:** Use `COPY` for regular files. Reserve `ADD` only for auto-extracting tars or downloading URLs.
**How it works:** For each copy_add_command starting with "ADD", checks if source ends with .tar/.tar.gz/.tgz/.zip or starts with http/https. If neither → finding.

### CSC-008: SSH Port Exposed (MEDIUM)
**Detects:** `EXPOSE 22`
**Why dangerous:** SSH in containers is an anti-pattern. It increases attack surface, requires managing SSH keys inside containers, and goes against immutable infrastructure principles.
**Fix:** Remove `EXPOSE 22`. Use `docker exec` for debugging. For remote access, use container orchestrator's native mechanisms.
**How it works:** Checks if "22" is in `info.exposed_ports`.

### CSC-009: Pipe-to-Shell (MEDIUM)
**Detects:** `curl ... | sh`, `wget ... | bash`, `curl ... | zsh`, `wget ... | dash`
**Why dangerous:** Downloads and immediately executes code without verification. MITM attack can inject malicious code. No checksum validation. The URL could be compromised.
**Fix:** Download file, verify checksum, then execute: `RUN curl -o install.sh URL && echo "sha256hash install.sh" | sha256sum -c - && sh install.sh`
**How it works:** Regex `PIPE_TO_SHELL_PATTERN` = `(curl|wget)\s+.*\|\s*(sh|bash|zsh|dash)` matched against each run_command.

### CSC-010: No Multi-stage Build (LOW)
**Detects:** Single FROM statement (that isn't `scratch`)
**Why dangerous:** Build tools (compilers, package managers, dev dependencies) end up in the final image. Larger image = more CVEs, more attack surface, slower deploys.
**Fix:** Use multi-stage: `FROM node:20 AS builder` ... `FROM node:20-alpine` ... `COPY --from=builder`
**How it works:** Checks if `len(info.base_images) == 1` and first base image isn't "scratch".

---

## THE RAG CHAIN — HOW AI ANSWERS WORK (rag.py)

### SecurityRAGChain class

**Constructor:** Takes optional vector_store, model name, n_results (default 5)
- Lazy LLM initialization — doesn't connect to Ollama until first query
- Creates VulnVectorStore if none provided

**_retrieve_context(query):**
1. Calls `self._store.query(query, n_results=5)`
2. ChromaDB embeds the query and finds 5 nearest CVE documents
3. Formats results as:
   ```
   ---
   [Full CVE document text]

   ---
   [Next CVE document text]
   ...
   ```
4. If no results: "No relevant vulnerability data found in the knowledge base."

**explain_cve(cve_id):**
- Retrieves context for the CVE ID
- Uses EXPLAIN_CVE_PROMPT: "Explain {cve_id}" → Summary, Impact, Remediation sections

**suggest_fixes(scan_summary):**
- Retrieves context for scan summary text
- Uses SUGGEST_FIX_PROMPT → prioritized fixes with exact commands, breaking changes

**review_dockerfile(dockerfile_content, scan_summary):**
- Retrieves context for "Dockerfile security {first 200 chars}"
- Uses DOCKERFILE_REVIEW_PROMPT → line-by-line review with corrections and severity ratings

**ask(question, scan_context, dockerfile):**
- If dockerfile provided → routes to review_dockerfile
- Otherwise: appends scan_context (first 500 chars) to query for better retrieval
- Uses GENERAL_QUERY_PROMPT → general security answer

### Chain Composition (LangChain Pipe Syntax)
```python
chain = PROMPT_TEMPLATE | self._get_llm() | self._parser
result = chain.invoke({"context": context, "question": question})
```
This is LangChain's LCEL (LangChain Expression Language):
1. PROMPT_TEMPLATE formats the variables into a chat message
2. `|` pipes it to the LLM (ChatOllama)
3. `|` pipes LLM output to StrOutputParser (extracts text string)

---

## THE 4 PROMPT TEMPLATES (prompts.py)

All prompts use ChatPromptTemplate.from_messages() with a (system, human) message pair.

### EXPLAIN_CVE_PROMPT
**System role:** "Container security expert. Provide clear, actionable explanations. Use retrieved context to ground answers. If context doesn't contain relevant info, say so clearly."
**Human:** Receives {context} and {question}. Asks for: what the vulnerability is, potential impact, specific remediation steps.

### SUGGEST_FIX_PROMPT
**System role:** "Container security expert specializing in vulnerability remediation. Provide specific, actionable fix suggestions prioritized by severity. Include exact package versions and commands."
**Human:** Receives {context} and {scan_summary}. Asks for: exact command/Dockerfile change, why it resolves the issue, potential breaking changes.

### DOCKERFILE_REVIEW_PROMPT
**System role:** "Container security expert who reviews Dockerfiles. Analyze Dockerfile and scan results. Reference specific line numbers and directives."
**Human:** Receives {context}, {dockerfile} (in a code block), and {scan_summary}. Asks for: problematic line/directive, security risk explanation, corrected version, severity rating.

### GENERAL_QUERY_PROMPT
**System role:** "Container security expert. Answer using retrieved context when relevant. Be precise and actionable. State what you know from context and what needs more info."
**Human:** Receives {context} and {question}. Asks for a thorough answer.

---

## DATA MODELS — HOW TRIVY DATA IS STRUCTURED (models.py)

### Severity Enum
Values: CRITICAL (rank 4), HIGH (3), MEDIUM (2), LOW (1), UNKNOWN (0)
- Has comparison operators (`>=`, `>`, etc.) based on rank
- `from_string()` converts case-insensitively, returns UNKNOWN for invalid

### Vulnerability Model (the core data unit)
Maps directly to one CVE entry in Trivy JSON. Key fields:
- `vulnerability_id` (alias VulnerabilityID) — e.g., "CVE-2024-6119"
- `pkg_name` / `installed_version` / `fixed_version` — affected package info
- `severity` — "CRITICAL", "HIGH", etc.
- `title` / `description` — human-readable CVE description
- `references` — list of URLs (NVD, vendor advisories)
- `cvss` — dict of CVSS scores (v2 and v3)
- `target` — which image layer this came from (added by parser, not Trivy)

Key methods:
- `to_summary()` → one-liner: `[HIGH] CVE-2024-6119: openssl@3.0.13 (fix: 3.0.14)`
- `to_document_text()` → multi-line text used for vector embedding
- `has_fix` property → True if fixed_version exists and is non-empty

### TrivyReport Model (top-level)
- `artifact_name` — the scanned image name
- `results` — list of Result objects (one per image layer)
- `severity_counts()` → `{"CRITICAL": 2, "HIGH": 5, ...}`
- `total_vulnerabilities` → sum across all results

### DockerfileInfo Dataclass (parser.py)
Not Pydantic — a simple dataclass. Represents a parsed Dockerfile:
- `base_images` — all FROM image references
- `stages` — all `AS <name>` stage names
- `run_commands` — all RUN command bodies
- `exposed_ports` — all EXPOSE values
- `env_vars` — all ENV key=value strings
- `copy_add_commands` — all COPY/ADD full lines
- `user` — USER directive value (or None)
- `raw_content` — full Dockerfile text
- `runs_as_root` property — True if no USER or USER is root/0
- `has_healthcheck` property — True if HEALTHCHECK in raw content

---

## HOW PARSING WORKS (parser.py)

### Trivy JSON Parsing
1. Check if source is a file path → read it; else treat as JSON string
2. `json.loads()` the raw string
3. Validate it's a dict (not a list)
4. `TrivyReport.model_validate(data)` — Pydantic validates every field against the schema, using aliases to map PascalCase to snake_case
5. Raises ParseError on any failure

### Vulnerability Extraction
- Iterates through `report.results` → each result's `vulnerabilities`
- Tags each vulnerability with `vuln.target = result.target` (so you know which layer it came from)
- Deduplicates by vulnerability_id when converting to documents

### Dockerfile Parsing
Line-by-line iteration:
1. Skip comments (`#`) and empty lines
2. Handle line continuations (`\` at end → join with next line)
3. Case-insensitive directive matching:
   - FROM: extracts image name, detects `AS <stage>` via regex
   - RUN: extracts command body
   - EXPOSE: splits ports by whitespace
   - ENV: stores full key=value
   - COPY/ADD: stores full command
   - USER: extracts username/uid
   - ENTRYPOINT/CMD: extracts value

---

## VECTOR DATABASE (vectordb.py)

### VulnVectorStore class
- **Storage:** ChromaDB PersistentClient at `~/.consec/chromadb/`
- **Collection:** `consec_vulns`
- **Embeddings:** Sentence-Transformers all-MiniLM-L6-v2 (384 dimensions)

### Ingestion Flow
1. Get all existing document IDs from ChromaDB
2. Filter out duplicates (documents with IDs already in store)
3. Add new documents: `collection.add(ids=..., documents=..., metadatas=...)`
4. Return count of newly added documents

### Query Flow
1. If store is empty → return empty list
2. Cap n_results to actual document count
3. `collection.query(query_texts=[query], n_results=n)` — ChromaDB embeds the query and finds nearest neighbors
4. Return list of dicts: `{id, text, metadata, distance}`

---

## EXPORT FORMATS (exporter.py)

### Markdown Export
```markdown
# Security Scan Report — nginx:latest

_Generated by consec on 2026-03-26 12:00 UTC_

## Summary
| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 5 |
...
| **TOTAL** | **15** |

## Vulnerabilities
| CVE ID | Severity | Package | Installed | Fixed | Title |
...
```

### JSON Export
```json
{
  "generated_at": "2026-03-26T12:00:00+00:00",
  "artifact_name": "nginx:latest",
  "total_vulnerabilities": 15,
  "severity_counts": {"CRITICAL": 2, "HIGH": 5, ...},
  "vulnerabilities": [
    {
      "cve_id": "CVE-2024-6119",
      "severity": "HIGH",
      "package": "openssl",
      "installed_version": "3.0.13",
      "fixed_version": "3.0.14",
      "has_fix": true,
      "title": "...",
      "target": "debian 12"
    }
  ]
}
```

---

## DISPLAY & UI (utils.py)

All terminal output uses the **Rich** library:
- **Severity color coding:** CRITICAL=bold red, HIGH=red, MEDIUM=yellow, LOW=blue, UNKNOWN=dim
- **Tables:** Rich Tables with borders for scan summaries and vulnerability lists
- **Panels:** Rich Panels with cyan borders for LLM responses
- **Progress spinners:** Shown during LLM processing and vector DB ingestion
- **Status messages:** ✓ (green) for success, ✗ (bold red) for errors, ℹ (blue) for info

### Configuration Constants
```python
CONSEC_HOME = ~/.consec (overridden by CONSEC_HOME env var)
CHROMA_DIR = CONSEC_HOME/chromadb
DEFAULT_MODEL = "llama3.1:8b" (overridden by CONSEC_MODEL env var)
OLLAMA_BASE_URL = "http://localhost:11434" (overridden by OLLAMA_BASE_URL env var)
```

---

## CI/CD PIPELINE (.github/workflows/ci.yml)

Three jobs running in parallel on every push/PR to main:

### Job 1: Lint (ubuntu-latest, Python 3.12)
- `pip install -e ".[dev]"`
- `ruff check consec/ tests/` — lint for errors, style, imports, naming, upgrades
- `ruff format --check consec/ tests/` — verify formatting

### Job 2: Test (ubuntu-latest, Python 3.10/3.11/3.12 matrix)
- `pip install -e ".[dev]"`
- `pytest tests/ -v -m "not requires_ollama" --cov=consec --cov-report=xml --cov-report=term-missing`
- On Python 3.12 + main branch: generates coverage badge SVG
- Uploads coverage.xml and badge as artifacts

### Job 3: Docker Build (ubuntu-latest)
- `docker build -t consec:ci-test .`
- `docker run --rm consec:ci-test --version` — verifies the built image works

---

## DOCKERFILE — HOW THE CONTAINER IS BUILT

Two-stage build:

**Stage 1 (builder):**
```dockerfile
FROM python:3.11-slim AS builder
WORKDIR /build
COPY pyproject.toml requirements.txt ./
COPY consec/ consec/
COPY data/sample_scans/ data/sample_scans/
RUN pip install --no-cache-dir --prefix=/install .
```

**Stage 2 (runtime):**
```dockerfile
FROM python:3.11-slim
RUN groupadd --gid 1000 consec && useradd --uid 1000 --gid consec --create-home consec
COPY --from=builder /install /usr/local
COPY --from=builder /build/data /home/consec/data
ENV CONSEC_HOME=/home/consec/.consec OLLAMA_BASE_URL=http://host.docker.internal:11434
WORKDIR /home/consec
USER consec
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["consec", "--version"]
ENTRYPOINT ["consec"]
CMD ["--help"]
```

Key decisions:
- **Multi-stage** to exclude build tools from runtime image
- **Non-root user** (consec:1000) for security
- **host.docker.internal** URL for Ollama so container can reach host's Ollama
- **HEALTHCHECK** so orchestrators can monitor container health

---

## PROJECT CONFIGURATION (pyproject.toml)

- **Build system:** setuptools >= 68.0
- **Python:** >= 3.10
- **Entry point:** `consec = "consec.cli:app"` — Typer app registered as CLI command
- **Ruff config:** target Python 3.10, line length 100, rules E/F/I/N/W/UP (errors, pyflakes, imports, naming, warnings, upgrades)
- **pytest markers:** integration, slow, requires_ollama
- **Dev dependencies:** pytest, pytest-cov, pytest-mock, pytest-bdd, behave, ruff

---

## TESTING — WHAT'S TESTED AND HOW

### 8 Test Files

**test_models.py** (~227 lines) — Severity enum ranking/comparison, Vulnerability model properties (has_fix, to_summary, to_document_text), TrivyReport aggregation (severity_counts, total_vulnerabilities)

**test_parser.py** (~227 lines) — parse_trivy_json from file and string, invalid JSON handling, extract_vulnerabilities with target annotation, filter_by_severity thresholds, to_documents deduplication and metadata

**test_dockerfile.py** (~287 lines) — Multi-stage FROM parsing, AS stage detection, RUN extraction, EXPOSE ports, ENV vars, COPY/ADD, USER directive, ENTRYPOINT/CMD, line continuation handling, comment skipping, runs_as_root/has_healthcheck properties

**test_rules.py** (~287 lines) — Every single rule individually tested with positive cases (should trigger) and negative cases (should not trigger). CSC-001 tested with latest, no tag, pinned, digest. CSC-006 tested with PASSWORD, API_KEY, safe vars. Etc.

**test_vectordb.py** (~173 lines) — Ingestion, deduplication (ingest same doc twice), query results structure, empty store handling, count property, clear()

**test_rag.py** (~105 lines) — Mocked LLM, context retrieval formatting, explain_cve/suggest_fixes/review_dockerfile/ask routing, empty context handling

**test_cli.py** (~122 lines) — CLI commands via Typer test runner: parse valid/invalid files, check with findings, export markdown/json, severity filtering

**test_integration.py** (~82 lines) — Full parse→ingest→query pipeline, empty scan handling, multiple scan accumulation, uses tmp_path for isolated ChromaDB

### What's NOT tested
- `exporter.py` — no dedicated test file (tested indirectly via CLI tests)
- `llm.py` — only mocked in RAG tests (real Ollama tests marked requires_ollama)
- `embeddings.py` — no dedicated tests
- `prompts.py` — no dedicated tests (tested indirectly via RAG tests)

---

## DEVELOPMENT HISTORY

8 commits over 3 days (Feb 12-14, 2026):

1. **334a53c** (Feb 12) — Initial implementation. Everything from scratch: models, parser, vectordb, embeddings, LLM integration, RAG chain, prompts, CLI with 5 commands, utils, all core tests. The big bang commit.

2. **04d4b86** (Feb 12) — Removed verbose docstrings from all modules and tests. Kept code clean.

3. **d80f83e** (Feb 12) — Reformatted dockerfile.py with consistent indentation.

4. **1304228** (Feb 12) — Minor style: reordered import in cli.py, added blank line in test_parser.py.

5. **a9179cc** (Feb 12) — Modernized all type hints from `Optional[X]` to `X | None` (Python 3.10+ syntax).

6. **9fc5508** (Feb 14) — Consolidated Dockerfile parsing. Deleted duplicate `parser_for_dockerfile_lint_issue.py`, merged into `parser.py`.

7. **83e2b41** (Feb 14) — Added GitHub Actions CI (lint + test matrix + Docker build). Updated Dockerfile to multi-stage with non-root user.

8. **5fef5d7** (Feb 14) — Implemented 8 Dockerfile security rules (CSC-001 to CSC-008) with `check` command and comprehensive tests.

### Uncommitted Work (current state)
- **+2 new rules:** CSC-009 (pipe-to-shell) and CSC-010 (no multi-stage) in rules.py (+63 lines)
- **Export feature:** New exporter.py module + `export` command in cli.py (+36 lines to CLI)
- **CLI tests:** New test_cli.py file
- **CI badge:** Coverage badge generation in ci.yml (+13 lines)
- **README updates:** Added badges and export command examples (+11 lines)
- **Total:** +188 lines added, -5 lines removed across 5 modified + 4 new files

---

## KEY DESIGN DECISIONS — WHY THINGS ARE THE WAY THEY ARE

### Why Ollama instead of OpenAI/Anthropic APIs?
Privacy. Security teams don't want vulnerability data sent to cloud providers. Also: zero cost, offline capability, no API key management.

### Why ChromaDB instead of FAISS/Pinecone?
ChromaDB has built-in persistence (saves to disk), embedded mode (no server needed), and native Sentence-Transformer integration. FAISS has no persistence. Pinecone is cloud-only.

### Why Pydantic aliases instead of renaming JSON keys?
Trivy uses PascalCase (`VulnerabilityID`), Python convention is snake_case (`vulnerability_id`). Aliases let us keep Python-idiomatic code while accepting Trivy's JSON format without transformation.

### Why lazy LLM initialization?
Most commands (parse, check, export, ingest) don't need Ollama. Lazy init means the tool works fully offline for these commands — Ollama is only needed for query and review.

### Why 10 security rules?
These are the most common Dockerfile security mistakes based on CIS Docker Benchmark, Hadolint's rule set, and Docker's official best practices guide. They cover the highest-impact issues that developers actually make.

### Why exit code 1 for HIGH/CRITICAL in check?
CI/CD integration. You can add `consec check Dockerfile` to your pipeline and it'll fail the build if there are serious security issues. MEDIUM/LOW don't fail the build (exit 0 with info message).

---

## SAMPLE DATA

### data/sample_scans/nginx_scan.json
Real Trivy output from scanning `nginx:1.25`. Contains 2 Result objects (OS packages layer). Used in all parser/integration tests.

### data/sample_scans/alpine_clean.json
Clean scan — no vulnerabilities found. Used to test "no vulns" path.

---

## NUMBERS FOR YOUR SLIDES

| What | Count |
|------|-------|
| Source code (Python) | ~1,500 lines |
| Test code | ~1,500+ lines |
| Modules | 12 |
| CLI commands | 7 |
| Security rules | 10 |
| Prompt templates | 4 |
| Test files | 8 |
| Test methods | 100+ |
| Git commits | 8 |
| CI/CD jobs | 3 |
| Python versions tested | 3 |
| Export formats | 2 |
| Dependencies | 9 runtime + 6 dev |
| Env vars | 3 |
| Cloud API cost | $0 |
| Data sent to cloud | 0 bytes |

---

## ACADEMIC REFERENCES

1. Lewis et al. (2020) "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks" — NeurIPS. The RAG architecture this project is built on.
2. Reimers & Gurevych (2019) "Sentence-BERT" — EMNLP-IJCNLP. The embedding model (all-MiniLM-L6-v2) is based on this.
3. OWASP (2023) "Top 10 for LLM Applications" — Security considerations for LLM-powered tools.
4. CIS Docker Benchmark — The security rules are aligned with CIS recommendations.
5. Sysdig Container Security Report (2023) — 87% of container images have HIGH/CRITICAL CVEs.
6. Docker Official Best Practices — Dockerfile writing guidelines the rules enforce.
