"""PromptGuard Layer 1 rules (editable without touching code).

Scans untrusted content for injection attempts, hidden text, encoded blobs,
leaked secrets, and non-allowlisted URLs/email addresses.

scan(text) -> list of hits. Each hit:
    {"rule_id": str, "severity": "low"|"medium"|"high",
     "description": str, "matched": str}

Any high-severity hit should block immediately with no LLM call.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

RULES_PATH = Path(__file__).with_name("rules.yaml")

_URL_RE = re.compile(r"https?://([^\s<>\"'\\)\\]]+)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", re.IGNORECASE)


def _load_yaml() -> dict[str, Any]:
    with open(RULES_PATH, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


_DATA = _load_yaml()
_RULES: list[dict[str, Any]] = _DATA.get("rules", []) or []
SENSITIVE_TOOLS: list[str] = _DATA.get("sensitive_tools", []) or []
URL_ALLOWLIST: set[str] = {d.lower() for d in (_DATA.get("url_allowlist") or [])}
EMAIL_ALLOWLIST: set[str] = {d.lower() for d in (_DATA.get("email_allowlist") or [])}


def _domain_of_url(token: str) -> str:
    token = token.strip().rstrip(".,);}")
    if "://" in token:
        token = token.split("://", 1)[1]
    host = token.split("/", 1)[0].split(":", 1)[0]
    return host.lower()


def scan(text: str) -> list[dict[str, Any]]:
    """Return rule hits found in *text*.

    High-severity hits indicate content that should be blocked immediately
    without an LLM call. Secrets/URLs/emails are recorded by rule id only
    (the matched value is truncated and never logged by this module).
    """
    hits: list[dict[str, Any]] = []

    for rule in _RULES:
        rule_id = rule.get("id", "")
        severity = rule.get("severity", "low")
        description = rule.get("description", "")
        pattern = rule.get("pattern")
        if not pattern:
            continue

        for match in re.finditer(pattern, text, re.IGNORECASE | re.DOTALL):
            # URLs and email addresses are only hits when outside the allowlist.
            if rule_id == "URL-001":
                domain = _domain_of_url(match.group(0))
                if domain in URL_ALLOWLIST:
                    continue
            elif rule_id == "EML-001":
                token = match.group(0)
                domain = token.split("@", 1)[1].lower() if "@" in token else ""
                if domain in EMAIL_ALLOWLIST:
                    continue

            hits.append(
                {
                    "rule_id": rule_id,
                    "severity": severity,
                    "description": description,
                    "matched": match.group(0)[:120],
                }
            )

    return hits


def high_severity_hits(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only high-severity hits."""
    return [h for h in hits if h.get("severity") == "high"]


def has_high_severity(hits: list[dict[str, Any]]) -> bool:
    return any(h.get("severity") == "high" for h in hits)
