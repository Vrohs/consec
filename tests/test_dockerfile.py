"""Tests for the Dockerfile parser."""

import tempfile
from pathlib import Path

import pytest

from consec.dockerfile import DockerfileInfo, parse_dockerfile


class TestParseDockerfile:
    """Behavioral tests for Dockerfile parsing."""

    def test_parse_simple_dockerfile(self):
        """Should extract base image, run commands, and exposed ports."""
        content = """FROM nginx:1.25
RUN apt-get update && apt-get install -y curl
EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]"""

        info = parse_dockerfile(content)
        assert info.base_images == ["nginx:1.25"]
        assert len(info.run_commands) == 1
        assert "apt-get" in info.run_commands[0]
        assert info.exposed_ports == ["80", "443"]
        assert info.cmd is not None

    def test_parse_multistage_dockerfile(self):
        """Should detect multiple stages and base images."""
        content = """FROM golang:1.21 AS builder
RUN go build -o app .

FROM alpine:3.19
COPY --from=builder /app /app
USER nobody
ENTRYPOINT ["/app"]"""

        info = parse_dockerfile(content)
        assert len(info.base_images) == 2
        assert "golang:1.21" in info.base_images
        assert "alpine:3.19" in info.base_images
        assert info.stages == ["builder"]
        assert info.user == "nobody"
        assert info.entrypoint is not None

    def test_runs_as_root_no_user_directive(self):
        """Without USER directive, should report runs_as_root True."""
        info = parse_dockerfile("FROM alpine:3.19\nRUN echo hello")
        assert info.runs_as_root is True

    def test_runs_as_root_explicit_root(self):
        """With USER root, should report runs_as_root True."""
        info = parse_dockerfile("FROM alpine:3.19\nUSER root")
        assert info.runs_as_root is True

    def test_not_runs_as_root(self):
        """With non-root USER, should report runs_as_root False."""
        info = parse_dockerfile("FROM alpine:3.19\nUSER appuser")
        assert info.runs_as_root is False

    def test_has_healthcheck(self):
        """Should detect HEALTHCHECK directive."""
        content = """FROM nginx:1.25
HEALTHCHECK CMD curl -f http://localhost/ || exit 1"""
        info = parse_dockerfile(content)
        assert info.has_healthcheck is True

    def test_no_healthcheck(self):
        """Without HEALTHCHECK, should report False."""
        info = parse_dockerfile("FROM nginx:1.25\nRUN echo hello")
        assert info.has_healthcheck is False

    def test_env_variables(self):
        """Should capture ENV directives."""
        content = """FROM python:3.11
ENV PYTHONUNBUFFERED=1
ENV APP_ENV=production"""
        info = parse_dockerfile(content)
        assert len(info.env_vars) == 2

    def test_copy_and_add_commands(self):
        """Should capture COPY and ADD directives."""
        content = """FROM python:3.11
COPY requirements.txt .
ADD app.tar.gz /app
COPY . /app"""
        info = parse_dockerfile(content)
        assert len(info.copy_add_commands) == 3

    def test_comments_ignored(self):
        """Comments should not be parsed as directives."""
        content = """# This is a comment
FROM alpine:3.19
# Another comment
RUN echo hello"""
        info = parse_dockerfile(content)
        assert len(info.base_images) == 1
        assert len(info.run_commands) == 1

    def test_line_continuation(self):
        """Backslash line continuations should be joined."""
        content = """FROM alpine:3.19
RUN apk add --no-cache \\
    curl \\
    wget"""
        info = parse_dockerfile(content)
        assert len(info.run_commands) == 1
        assert "curl" in info.run_commands[0]
        assert "wget" in info.run_commands[0]

    def test_parse_from_file(self, tmp_path):
        """Should parse from a file path."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM nginx:1.25\nEXPOSE 80")
        info = parse_dockerfile(dockerfile)
        assert info.base_images == ["nginx:1.25"]

    def test_to_summary(self):
        """Summary should include key security-relevant info."""
        content = """FROM nginx:1.25
RUN apt-get update
EXPOSE 80
USER www-data"""
        info = parse_dockerfile(content)
        summary = info.to_summary()
        assert "nginx:1.25" in summary
        assert "Runs as root: no" in summary
        assert "Exposed ports: 80" in summary

    def test_empty_dockerfile(self):
        """Empty Dockerfile should not crash."""
        info = parse_dockerfile("")
        assert info.base_images == []
        assert info.run_commands == []
