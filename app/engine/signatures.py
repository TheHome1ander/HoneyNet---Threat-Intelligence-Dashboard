"""
signatures.py — Regex-based attack signature library.

CONCEPT — Why Regex for Threat Detection?
──────────────────────────────────────────
Real WAFs (Web Application Firewalls) like ModSecurity use thousands of regex
rules (the OWASP CRS — Core Rule Set). We're building a simplified but
realistic version that covers the most common automated attack patterns.

The goal isn't to stop attacks (we're a honeypot, not a firewall) — it's to
CLASSIFY what kind of attack is being attempted so the dashboard can show
meaningful threat intelligence.

Attack categories we detect:
  1. SQL Injection (SQLi)      — attempts to manipulate SQL queries
  2. Cross-Site Scripting (XSS) — attempts to inject JavaScript
  3. Path Traversal            — attempts to escape the web root (../../etc/passwd)
  4. Command Injection (CMDi)  — attempts to run shell commands server-side
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SignatureMatch:
    """Represents a single matched attack signature."""
    category: str       # e.g. "SQLi"
    pattern: str        # The regex that matched
    matched_value: str  # The substring that triggered the match


# ── Attack Signature Definitions ─────────────────────────────────────────────
# Each tuple is (human-readable label, compiled regex).
# re.IGNORECASE is critical — attackers always try mixed-case evasion.

_SQL_INJECTION: list[tuple[str, re.Pattern]] = [
    ("SQLi", re.compile(r"union[\s\+]+select", re.IGNORECASE)),
    ("SQLi", re.compile(r"select[\s\S]+from[\s\S]+where", re.IGNORECASE)),
    ("SQLi", re.compile(r"(insert|update|delete|drop|alter|create)\s+(into|table|database)", re.IGNORECASE)),
    ("SQLi", re.compile(r"(exec|execute|xp_cmdshell|sp_executesql)\s*[\(\s]", re.IGNORECASE)),
    ("SQLi", re.compile(r"('|\")\s*(or|and)\s+('|\")?\d+('|\")?\s*=\s*('|\")?\d+", re.IGNORECASE)),
    ("SQLi", re.compile(r"--\s*(#|$)", re.IGNORECASE)),          # SQL comment terminator
    ("SQLi", re.compile(r";\s*(drop|insert|update|delete)", re.IGNORECASE)),  # Stacked queries
    ("SQLi", re.compile(r"sleep\s*\(\s*\d+\s*\)", re.IGNORECASE)),            # Blind time-based
    ("SQLi", re.compile(r"(benchmark|waitfor\s+delay)", re.IGNORECASE)),       # Blind time-based
]

_XSS: list[tuple[str, re.Pattern]] = [
    ("XSS", re.compile(r"<\s*script[\s>]", re.IGNORECASE)),
    ("XSS", re.compile(r"javascript\s*:", re.IGNORECASE)),
    ("XSS", re.compile(r"on(error|load|click|mouse\w+|key\w+|focus|blur)\s*=", re.IGNORECASE)),
    ("XSS", re.compile(r"<\s*img[^>]+src\s*=\s*[\"']?\s*javascript:", re.IGNORECASE)),
    ("XSS", re.compile(r"document\.(cookie|location|write)", re.IGNORECASE)),
    ("XSS", re.compile(r"(alert|confirm|prompt)\s*\(", re.IGNORECASE)),
    ("XSS", re.compile(r"eval\s*\(", re.IGNORECASE)),
    ("XSS", re.compile(r"<\s*iframe", re.IGNORECASE)),
    ("XSS", re.compile(r"&#x[0-9a-f]+;|&#\d+;", re.IGNORECASE)),  # HTML entity encoding evasion
]

_PATH_TRAVERSAL: list[tuple[str, re.Pattern]] = [
    ("PathTraversal", re.compile(r"\.\./|\.\.\\", re.IGNORECASE)),              # ../
    ("PathTraversal", re.compile(r"%2e%2e[%2f%5c]", re.IGNORECASE)),           # URL-encoded ../
    ("PathTraversal", re.compile(r"\.\.%2f|\.\.%5c", re.IGNORECASE)),          # Mixed encoding
    ("PathTraversal", re.compile(r"(etc/passwd|etc/shadow|proc/self/environ)", re.IGNORECASE)),
    ("PathTraversal", re.compile(r"(win\.ini|boot\.ini|system32)", re.IGNORECASE)),
]

_COMMAND_INJECTION: list[tuple[str, re.Pattern]] = [
    ("CMDi", re.compile(r";\s*(ls|cat|whoami|id|pwd|uname|wget|curl)\b", re.IGNORECASE)),
    ("CMDi", re.compile(r"\|\s*(ls|cat|whoami|id|wget|curl|bash|sh)\b", re.IGNORECASE)),
    ("CMDi", re.compile(r"`[^`]+`")),                                           # Backtick execution
    ("CMDi", re.compile(r"\$\([^)]+\)")),                                       # $() subshell
    ("CMDi", re.compile(r"(nc|netcat)\s+-[a-z]*\s+\d", re.IGNORECASE)),        # Reverse shell
    ("CMDi", re.compile(r"/bin/(bash|sh|zsh|python|perl|ruby)", re.IGNORECASE)),
]

# Master list — order doesn't matter, all patterns are always checked
ALL_SIGNATURES: list[tuple[str, re.Pattern]] = (
    _SQL_INJECTION + _XSS + _PATH_TRAVERSAL + _COMMAND_INJECTION
)


def scan(text: str) -> list[SignatureMatch]:
    """
    Scan a string against all signatures and return every match.

    We scan a single concatenated string covering the URL path, query string,
    and (truncated) request body so attackers can't hide payloads in obscure
    fields.  Deduplication by category ensures we return at most one match per
    attack type (e.g. two SQLi patterns both matching → one "SQLi" result).
    """
    if not text:
        return []

    seen_categories: set[str] = set()
    matches: list[SignatureMatch] = []

    for category, pattern in ALL_SIGNATURES:
        if category in seen_categories:
            continue  # Already found this attack type — skip further checks

        m = pattern.search(text)
        if m:
            seen_categories.add(category)
            matches.append(SignatureMatch(
                category=category,
                pattern=pattern.pattern,
                matched_value=m.group(0)[:80],  # Cap to 80 chars for safety
            ))

    return matches
