"""Sanitization utilities for mitigating injection vulnerabilities in exported reports and logs."""

from typing import Any


def sanitize_csv_formula(val: Any) -> str:
    """Mitigate CSV/Spreadsheet formula injection (OWASP / CWE-1236).

    If an untrusted string begins with '=', '+', '-', '@', horizontal tab,
    or carriage return, prepend a single quote (') to force spreadsheet
    parsers to treat the cell as raw string text rather than an executable formula.
    """
    if val is None:
        return ""
    s = str(val).strip()
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s
