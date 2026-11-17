"""
features.py  - shared by train.py and scan.py
1. safe_decode(): peels URL / HTML-entity / \\uXXXX encoding in memory (text only - nothing is rendered or executed)
2. indicator_features(): small, human-readable security signals computed on the DECODED text
"""
import re, html, urllib.parse
import numpy as np

_UNI = re.compile(r"\\u([0-9a-fA-F]{4})")

def safe_decode(text, max_layers=4):
    """Repeatedly decode until the text stops changing. Returns (decoded_text, layers_used)."""
    cur, layers = text, 0
    for _ in range(max_layers):
        nxt = urllib.parse.unquote(cur)
        nxt = html.unescape(nxt)
        nxt = _UNI.sub(lambda m: chr(int(m.group(1), 16)), nxt)
        if nxt == cur:
            break
        cur, layers = nxt, layers + 1
    return cur, layers

# (name, regex, description)  - regexes run on lower-cased decoded text
INDICATORS = [
    ("script_tag",        r"<\s*/?\s*script",                           "<script> tag opened or closed"),
    ("event_handler",     r"\bon[a-z]{3,20}\s*=",                       "inline event handler (onerror=, onload= ...)"),
    ("js_protocol",       r"(javascript|vbscript)\s*:",                 "javascript:/vbscript: URL scheme"),
    ("data_uri",          r"data\s*:\s*text/html|data\s*:[^,]*;base64", "data: URI that can carry HTML/JS"),
    ("risky_tag",         r"<\s*(img|svg|iframe|object|embed|body|details|video|audio|input|marquee|meta|link|style|math|select|textarea)\b",
                                                                        "tag commonly abused as an XSS carrier"),
    ("dangerous_call",    r"\b(alert|prompt|confirm|eval|atob|fromcharcode|settimeout)\s*\(", "JS call typical of PoC payloads"),
    ("dom_access",        r"document\s*\.\s*(cookie|domain|write|location|body)|window\s*\.\s*location|\.innerhtml", "DOM / cookie / navigation access"),
    ("attr_breakout",     r"[\"']\s*>\s*<|[\"']\s+on[a-z]+\s*=|[\"'];\s*[a-z]+\(", "quote used to break out of an attribute/string"),
    ("html_comment_trick",r"<!--|-->|<!\[cdata\[",                      "comment/CDATA used to split or hide keywords"),
    ("autofocus_trick",   r"\bautofocus\b|\bopen\b\s*[/ ]*\s*on",       "auto-triggering attribute"),
]
_COMPILED = [(n, re.compile(rx), d) for n, rx, d in INDICATORS]
INDICATOR_NAMES = [n for n, _, _ in INDICATORS]
NUMERIC_NAMES = ["decode_layers", "angle_bracket_count", "special_char_ratio", "encoded_token_ratio", "log_length"]
FEATURE_NAMES = INDICATOR_NAMES + NUMERIC_NAMES

def explain(text):
    """Return list of (indicator, description) that fire on the decoded payload."""
    dec, _ = safe_decode(text)
    low = dec.lower()
    return [(n, d) for n, rx, d in _COMPILED if rx.search(low)]

def indicator_features(text):
    dec, layers = safe_decode(text)
    low = dec.lower()
    row = [1.0 if rx.search(low) else 0.0 for _, rx, _ in _COMPILED]
    n = max(len(text), 1)
    special = sum(1 for c in dec if c in "<>\"'`=();{}/\\")
    encoded = len(re.findall(r"%[0-9a-fA-F]{2}|&#x?[0-9a-fA-F]+;|\\u[0-9a-fA-F]{4}", text))
    row += [float(layers), float(dec.count("<") + dec.count(">")), special / max(len(dec), 1),
            encoded / n * 10, float(np.log1p(n))]
    return row

def feature_matrix(texts):
    return np.array([indicator_features(t) for t in texts], dtype=float)
