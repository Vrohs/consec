FROM python:3.11-slim AS builder

WORKDIR /build

COPY pyproject.toml requirements.txt ./
COPY consec/ consec/
COPY data/sample_scans/ data/sample_scans/

RUN pip install --no-cache-dir --prefix=/install .


FROM python:3.11-slim

RUN groupadd --gid 1000 consec \
    && useradd --uid 1000 --gid consec --create-home consec

COPY --from=builder /install /usr/local
COPY --from=builder /build/data /home/consec/data

ENV CONSEC_HOME=/home/consec/.consec \
    OLLAMA_BASE_URL=http://host.docker.internal:11434

WORKDIR /home/consec
USER consec

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["consec", "--version"]

ENTRYPOINT ["consec"]
CMD ["--help"]
