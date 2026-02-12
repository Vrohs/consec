"""Prompt templates for security analysis."""

from langchain_core.prompts import ChatPromptTemplate

EXPLAIN_CVE_PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a container security expert. Provide clear, actionable explanations "
            "of vulnerabilities. Use the retrieved context to ground your answers. "
            "If the context doesn't contain relevant information, say so clearly rather "
            "than guessing. Format your response with sections: Summary, Impact, and Remediation.",
        ),
        (
            "human",
            "## Retrieved Security Context\n{context}\n\n"
            "## Question\n{question}\n\n"
            "Provide a detailed explanation covering:\n"
            "1. What this vulnerability is and how it works\n"
            "2. The potential impact on container security\n"
            "3. Specific remediation steps",
        ),
    ]
)


SUGGEST_FIX_PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a container security expert specializing in vulnerability remediation. "
            "Provide specific, actionable fix suggestions prioritized by severity. "
            "Use the retrieved context for accuracy. Include exact package versions and commands.",
        ),
        (
            "human",
            "## Vulnerability Context\n{context}\n\n"
            "## Scan Results Summary\n{scan_summary}\n\n"
            "Suggest specific fixes for these vulnerabilities, prioritized by severity. "
            "For each fix, include:\n"
            "1. The exact command or Dockerfile change needed\n"
            "2. Why this fix resolves the issue\n"
            "3. Any potential breaking changes to watch for",
        ),
    ]
)


DOCKERFILE_REVIEW_PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a container security expert who reviews Dockerfiles for security best "
            "practices. Analyze the provided Dockerfile and scan results to give targeted, "
            "actionable advice. Reference specific line numbers and directives.",
        ),
        (
            "human",
            "## Retrieved Security Context\n{context}\n\n"
            "## Dockerfile Contents\n```dockerfile\n{dockerfile}\n```\n\n"
            "## Scan Vulnerabilities (if available)\n{scan_summary}\n\n"
            "Review this Dockerfile for security issues. For each issue:\n"
            "1. Identify the problematic line/directive\n"
            "2. Explain the security risk\n"
            "3. Provide the corrected version\n"
            "4. Rate severity (CRITICAL/HIGH/MEDIUM/LOW)",
        ),
    ]
)


GENERAL_QUERY_PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a container security expert. Answer the user's question using the "
            "retrieved context when relevant. Be precise and actionable. "
            "If the context doesn't fully answer the question, state what you know from "
            "the context and what would require additional information.",
        ),
        (
            "human",
            "## Retrieved Security Context\n{context}\n\n"
            "## Question\n{question}\n\n"
            "Provide a thorough answer.",
        ),
    ]
)
