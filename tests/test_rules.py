from consec.parser import parse_dockerfile
from consec.rules import Finding, check_dockerfile


class TestUnpinnedBaseImage:
    def test_flags_latest_tag(self):
        info = parse_dockerfile("FROM nginx:latest\nCMD nginx")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-001" in ids

    def test_flags_no_tag(self):
        info = parse_dockerfile("FROM nginx\nCMD nginx")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-001" in ids

    def test_passes_pinned_tag(self):
        info = parse_dockerfile("FROM nginx:1.25\nCMD nginx")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-001" not in ids

    def test_passes_digest(self):
        info = parse_dockerfile("FROM nginx@sha256:abc123\nCMD nginx")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-001" not in ids

    def test_passes_scratch(self):
        info = parse_dockerfile("FROM scratch\nCOPY app /app")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-001" not in ids


class TestRootUser:
    def test_flags_no_user_directive(self):
        info = parse_dockerfile("FROM alpine:3.19\nRUN echo hello")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-002" in ids

    def test_flags_explicit_root(self):
        info = parse_dockerfile("FROM alpine:3.19\nUSER root")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-002" in ids

    def test_passes_nonroot_user(self):
        info = parse_dockerfile("FROM alpine:3.19\nUSER appuser")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-002" not in ids


class TestMissingHealthcheck:
    def test_flags_no_healthcheck(self):
        info = parse_dockerfile("FROM nginx:1.25\nCMD nginx")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-003" in ids

    def test_passes_with_healthcheck(self):
        content = "FROM nginx:1.25\nHEALTHCHECK CMD curl localhost"
        info = parse_dockerfile(content)
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-003" not in ids


class TestCopyAll:
    def test_flags_copy_dot(self):
        info = parse_dockerfile("FROM python:3.11\nCOPY . /app")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-004" in ids

    def test_flags_copy_dot_slash(self):
        info = parse_dockerfile("FROM python:3.11\nCOPY ./ /app")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-004" in ids

    def test_passes_specific_copy(self):
        info = parse_dockerfile("FROM python:3.11\nCOPY requirements.txt .")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-004" not in ids


class TestAptCache:
    def test_flags_no_cleanup(self):
        content = "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl"
        info = parse_dockerfile(content)
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-005" in ids

    def test_passes_with_cleanup(self):
        content = (
            "FROM ubuntu:22.04\n"
            "RUN apt-get update && apt-get install -y curl "
            "&& rm -rf /var/lib/apt/lists/*"
        )
        info = parse_dockerfile(content)
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-005" not in ids


class TestSecretsInEnv:
    def test_flags_password(self):
        info = parse_dockerfile("FROM alpine:3.19\nENV DB_PASSWORD=secret123")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-006" in ids

    def test_flags_api_key(self):
        info = parse_dockerfile("FROM alpine:3.19\nENV API_KEY=abc123")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-006" in ids

    def test_flags_aws_secret(self):
        info = parse_dockerfile("FROM alpine:3.19\nENV AWS_SECRET_ACCESS_KEY=xxx")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-006" in ids

    def test_passes_normal_env(self):
        info = parse_dockerfile("FROM alpine:3.19\nENV APP_ENV=production")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-006" not in ids


class TestAddMisuse:
    def test_flags_add_plain_file(self):
        info = parse_dockerfile("FROM alpine:3.19\nADD config.json /app/")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-007" in ids

    def test_passes_add_tar(self):
        info = parse_dockerfile("FROM alpine:3.19\nADD app.tar.gz /app/")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-007" not in ids

    def test_passes_add_url(self):
        info = parse_dockerfile("FROM alpine:3.19\nADD https://example.com/file /app/")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-007" not in ids

    def test_passes_copy(self):
        info = parse_dockerfile("FROM alpine:3.19\nCOPY config.json /app/")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-007" not in ids


class TestSshPort:
    def test_flags_port_22(self):
        info = parse_dockerfile("FROM ubuntu:22.04\nEXPOSE 22 80")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-008" in ids

    def test_passes_no_ssh(self):
        info = parse_dockerfile("FROM nginx:1.25\nEXPOSE 80 443")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-008" not in ids


class TestPipeToShell:
    def test_flags_curl_pipe_bash(self):
        content = "FROM alpine:3.19\nRUN curl -fsSL https://example.com/install.sh | bash"
        info = parse_dockerfile(content)
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-009" in ids

    def test_flags_wget_pipe_sh(self):
        content = "FROM alpine:3.19\nRUN wget -qO- https://example.com/setup | sh"
        info = parse_dockerfile(content)
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-009" in ids

    def test_passes_safe_download(self):
        content = (
            "FROM alpine:3.19\n"
            "RUN curl -fsSL -o install.sh https://example.com/install.sh "
            "&& sh install.sh"
        )
        info = parse_dockerfile(content)
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-009" not in ids

    def test_passes_no_pipe(self):
        content = "FROM alpine:3.19\nRUN curl -fsSL https://example.com/file.txt -o /tmp/file.txt"
        info = parse_dockerfile(content)
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-009" not in ids


class TestNoMultistage:
    def test_flags_single_stage(self):
        info = parse_dockerfile("FROM golang:1.22\nRUN go build -o app .\nCMD ./app")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-010" in ids

    def test_passes_multistage(self):
        content = (
            "FROM golang:1.22 AS builder\n"
            "RUN go build -o app .\n"
            "FROM gcr.io/distroless/static:nonroot\n"
            "COPY --from=builder /app /app\n"
            "USER nonroot\n"
            "HEALTHCHECK CMD /app --health\n"
            "CMD /app"
        )
        info = parse_dockerfile(content)
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-010" not in ids

    def test_passes_scratch(self):
        info = parse_dockerfile("FROM scratch\nCOPY app /app")
        findings = check_dockerfile(info)
        ids = [f.rule_id for f in findings]
        assert "CSC-010" not in ids


class TestCheckDockerfile:
    def test_clean_dockerfile_no_findings(self):
        content = """FROM python:3.11-slim AS builder
RUN pip install -r requirements.txt
FROM python:3.11-slim
USER appuser
HEALTHCHECK CMD python -c 'print("ok")'
COPY requirements.txt .
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "app.py"]"""
        info = parse_dockerfile(content)
        findings = check_dockerfile(info)
        assert findings == []

    def test_multiple_findings(self):
        content = """FROM ubuntu
RUN apt-get update && apt-get install -y curl
ENV DB_PASSWORD=hunter2
COPY . /app
EXPOSE 22"""
        info = parse_dockerfile(content)
        findings = check_dockerfile(info)
        rule_ids = {f.rule_id for f in findings}
        assert "CSC-001" in rule_ids
        assert "CSC-002" in rule_ids
        assert "CSC-003" in rule_ids
        assert "CSC-004" in rule_ids
        assert "CSC-005" in rule_ids
        assert "CSC-006" in rule_ids
        assert "CSC-008" in rule_ids
        assert "CSC-010" in rule_ids

    def test_empty_dockerfile(self):
        info = parse_dockerfile("")
        findings = check_dockerfile(info)
        assert isinstance(findings, list)

    def test_finding_has_all_fields(self):
        info = parse_dockerfile("FROM nginx:latest")
        findings = check_dockerfile(info)
        csc001 = [f for f in findings if f.rule_id == "CSC-001"][0]
        assert isinstance(csc001, Finding)
        assert csc001.severity == "HIGH"
        assert csc001.title
        assert csc001.description
        assert csc001.remediation
