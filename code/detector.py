"""Rule based signature detector and traffic light verdict used by the two
detector informed defenses in Paper D.

This is deliberately simple and transparent. It scans the attacker controlled fields
of a log record for known attack signatures (SQL injection, cross site scripting, path
traversal, command injection, login scanning) using the same repaired pattern lists as
Paper B, and it also flags text that looks like an instruction aimed at a reader, which
is the hallmark of a log substrate injection. The traffic light verdict is computed here,
without any language model, so a language model used for explanation cannot change it.
"""
import re
from urllib.parse import unquote_plus

SIGNATURES = {
    "sqli": [r"union\s+select", r"or\s+1\s*=\s*1", r"'\s*or\s*'", r"--", r";\s*drop\s+table", r"information_schema"],
    "xss": [r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=", r"document\.(location|cookie)"],
    "traversal": [r"\.\./", r"/etc/passwd", r"\\windows\\system32"],
    "cmdi": [r";\s*cat\s+/", r"\|\s*(sh|bash)\b", r"%3bcat", r"`.*`"],
    "scan": [r"/wp-login", r"/phpmyadmin", r"/\.env\b", r"/admin\b"],
}
# phrases that look like an instruction to the reader rather than traffic
INJECTION_MARKERS = [
    r"ignore (the )?(above|previous)", r"classify (this|it) as benign", r"record as benign",
    r"\bwhitelisted\b", r"final classification", r'"verdict"\s*:', r"<end log>", r"\[soc admin\]",
    r"mark (this|it) (as )?benign", r"disregard",
]


def _scan(text, patterns):
    hits = []
    low = text.lower()
    dec = unquote_plus(text, encoding="latin-1").lower()     # decode first, then lower case
    for name, pats in patterns.items():
        for p in pats:
            if re.search(p, low) or re.search(p, dec):
                hits.append(name)
                break
    return hits


def analyse(record):
    """Return attack signatures found, injection markers found, and a 0 to 100 base score."""
    fields = [record.get("request", ""), record.get("user_agent", "")]
    sig = sorted(set(sum((_scan(f, SIGNATURES) for f in fields), [])))
    inj = []
    for f in fields:
        low, dec = f.lower(), unquote_plus(f, encoding="latin-1").lower()
        for p in INJECTION_MARKERS:
            if re.search(p, low) or re.search(p, dec):
                inj.append(p)
    severity = {"sqli": 90, "cmdi": 90, "traversal": 80, "xss": 75, "scan": 40}
    base = max([severity[s] for s in sig], default=0)
    if record.get("status") in (403, 500) and sig:
        base = min(100, base + 5)
    return {"signatures": sig, "injection_markers": sorted(set(inj)), "base_score": base}


def verdict(base_score):
    if base_score >= 70:
        return "RED"
    if base_score >= 30:
        return "YELLOW"
    return "GREEN"


def quarantine(record):
    """Return a copy with injection marker text removed from attacker controlled fields,
    used by the field quarantine defence. Signature text is kept so the record is still
    recognisable as an attack, only the reader directed instruction is stripped."""
    r = dict(record)
    for key in ("request", "user_agent"):
        text = r.get(key, "")
        for p in INJECTION_MARKERS:
            text = re.sub(p, "[removed]", text, flags=re.IGNORECASE)
        # also strip an obvious appended clause after a known end of line marker
        text = re.sub(r"(<end log>|final classification.*$)", "[removed]", text, flags=re.IGNORECASE)
        r[key] = text
    return r
