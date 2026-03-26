from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from consec.cli import app

runner = CliRunner()

SAMPLE_DIR = Path(__file__).parent.parent / "data" / "sample_scans"
NGINX_SCAN = str(SAMPLE_DIR / "nginx_scan.json")
CLEAN_SCAN = str(SAMPLE_DIR / "alpine_clean.json")


class TestParseCommand:
    def test_parse_valid_file(self):
        result = runner.invoke(app, ["parse", NGINX_SCAN])
        assert result.exit_code == 0
        assert "Scan Summary" in result.output

    def test_parse_with_severity_filter(self):
        result = runner.invoke(app, ["parse", NGINX_SCAN, "--severity", "HIGH"])
        assert result.exit_code == 0

    def test_parse_missing_file(self):
        result = runner.invoke(app, ["parse", "/nonexistent/file.json"])
        assert result.exit_code != 0

    def test_parse_clean_scan(self):
        result = runner.invoke(app, ["parse", CLEAN_SCAN])
        assert result.exit_code == 0
        assert "Scan Summary" in result.output


class TestCheckCommand:
    def test_check_secure_dockerfile(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text(
            "FROM python:3.11-slim AS builder\n"
            "RUN pip install flask\n"
            "FROM python:3.11-slim\n"
            "USER appuser\n"
            "HEALTHCHECK CMD python -c 'print(1)'\n"
            "COPY app.py .\n"
            "CMD python app.py\n"
        )
        result = runner.invoke(app, ["check", str(df)])
        assert result.exit_code == 0
        assert "passed" in result.output.lower() or "0" in result.output

    def test_check_insecure_dockerfile(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu:latest\nCOPY . /app\nENV DB_PASSWORD=secret\n")
        result = runner.invoke(app, ["check", str(df)])
        assert result.exit_code == 1

    def test_check_missing_dockerfile(self):
        result = runner.invoke(app, ["check", "/nonexistent/Dockerfile"])
        assert result.exit_code == 1


class TestExportCommand:
    def test_export_markdown(self, tmp_path):
        out = tmp_path / "report.md"
        result = runner.invoke(
            app, ["export", NGINX_SCAN, str(out), "--format", "markdown"]
        )
        assert result.exit_code == 0
        assert out.exists()
        content = out.read_text()
        assert "Security Scan Report" in content
        assert "| Severity | Count |" in content

    def test_export_json(self, tmp_path):
        out = tmp_path / "report.json"
        result = runner.invoke(
            app, ["export", NGINX_SCAN, str(out), "--format", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "severity_counts" in data
        assert "vulnerabilities" in data

    def test_export_with_severity_filter(self, tmp_path):
        out = tmp_path / "report.json"
        result = runner.invoke(
            app,
            ["export", NGINX_SCAN, str(out), "--format", "json", "-s", "CRITICAL"],
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        for v in data["vulnerabilities"]:
            assert v["severity"] == "CRITICAL"

    def test_export_invalid_format(self, tmp_path):
        out = tmp_path / "report.txt"
        result = runner.invoke(
            app, ["export", NGINX_SCAN, str(out), "--format", "xml"]
        )
        assert result.exit_code == 1

    def test_export_missing_input(self, tmp_path):
        out = tmp_path / "report.md"
        result = runner.invoke(
            app, ["export", "/nonexistent.json", str(out)]
        )
        assert result.exit_code != 0


class TestVersionFlag:
    def test_version(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "consec v" in result.output

    def test_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "consec" in result.output
