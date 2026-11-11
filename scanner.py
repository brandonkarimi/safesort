"""
scanner.py - Local file inventory and risk heuristics for SafeSort.

I built this to run with no LLM and no network. It lists the files in a
folder and flags risk using simple patterns only. It reads at most the
first 64KB of a file as text, and it never executes file content.

Risk levels:
  Critical - a secret plus a suspicious marker, or a secret in an
             executable / double-extension file.
  High     - a secret, or a suspicious marker (executable extension,
             double extension, PDF with /JavaScript or embedded file).
  Medium   - PII such as an email, phone number, or SSN pattern.
  Low      - nothing flagged.
"""

import re
from pathlib import Path

MAX_READ_BYTES = 64 * 1024

EXECUTABLE_EXTS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1",
                   ".com", ".msi", ".jar", ".sh"}
DOCUMENT_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}

SECRET_PATTERNS = [
    (r"\bsk-[A-Za-z0-9\-_]{8,}\b", "API key pattern (sk-...)"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key pattern"),
    (r"\bghp_[A-Za-z0-9]{20,}\b", "GitHub token pattern"),
    (r"\bgho_[A-Za-z0-9]{20,}\b", "GitHub token pattern"),
    (r"(?i)\b(password|passwd|pwd)\s*[:=]\s*\S+", "password value in plain text"),
    (r"(?i)\b(api[_-]?key|secret|token)\s*[:=]\s*[\"']?[A-Za-z0-9\-_\.]{8,}",
     "secret or token value in plain text"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "private key block"),
]

PII_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "email address"),
    (r"(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}\b",
     "phone number"),
]

PDF_SUSPICIOUS_MARKERS = [
    ("/JavaScript", "PDF contains a /JavaScript marker"),
    ("/JS", "PDF contains a /JS marker"),
    ("/EmbeddedFile", "PDF contains an embedded file"),
    ("/Launch", "PDF contains a /Launch action"),
    ("/OpenAction", "PDF contains an /OpenAction action"),
]

RISK_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def _read_head(path):
    """Read at most the first 64KB of a file as text. Never execute it."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_READ_BYTES)
        return data.decode("utf-8", errors="ignore")
    except OSError:
        return ""


def assess_file(path):
    """Assess one file. Returns (risk, reasons list)."""
    path = Path(path)
    reasons = []
    secret = False
    suspicious = False

    ext = path.suffix.lower()
    stem = path.stem.lower()

    if ext in EXECUTABLE_EXTS:
        suspicious = True
        reasons.append(f"Executable extension {ext}")
    # Double extension: invoice.pdf.exe, report.docx.js, and similar.
    for doc_ext in DOCUMENT_EXTS:
        if stem.endswith(doc_ext):
            suspicious = True
            reasons.append(f"Double extension: {doc_ext}{ext}")
            break

    head = _read_head(path)

    for pattern, label in SECRET_PATTERNS:
        if re.search(pattern, head):
            secret = True
            reasons.append(f"Secret pattern: {label}")
            break
    for pattern, label in PII_PATTERNS:
        if re.search(pattern, head):
            reasons.append(f"PII pattern: {label}")

    if ext == ".pdf":
        for marker, label in PDF_SUSPICIOUS_MARKERS:
            if marker in head:
                suspicious = True
                reasons.append(f"Suspicious PDF marker: {label}")
                break

    has_pii = any(r.startswith("PII pattern") for r in reasons)
    if secret and suspicious:
        risk = "Critical"
    elif secret or suspicious:
        risk = "High"
    elif has_pii:
        risk = "Medium"
    else:
        risk = "Low"
    return risk, reasons


def scan_folder(base_path):
    """List files directly in base_path (top level only, no recursion).

    Returns a list of dicts with path, name, size, extension, risk,
    and reasons. Directories are skipped. Sorted by name so output is
    deterministic.
    """
    base = Path(base_path)
    if not base.is_dir():
        raise ValueError(f"Base path is not a folder: {base_path}")
    inventory = []
    for entry in sorted(base.iterdir(), key=lambda p: p.name.lower()):
        if not entry.is_file():
            continue
        risk, reasons = assess_file(entry)
        inventory.append({
            "path": str(entry.resolve()),
            "name": entry.name,
            "size": entry.stat().st_size,
            "extension": entry.suffix.lower(),
            "risk": risk,
            "reasons": reasons,
        })
    return inventory
