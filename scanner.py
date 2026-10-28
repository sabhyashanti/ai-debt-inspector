"""Fast, local, rule-based checks. These run BEFORE Gemini and also feed it context."""
import ast
import re

SECRET_PATTERNS = {
    "AWS access key": r"AKIA[0-9A-Z]{16}",
    "Google API key": r"AIza[0-9A-Za-z_\-]{35}",
    "GitHub token": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "Private key block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "JWT token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Hard-coded credential": r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*[\"'][^\"'\s]{6,}[\"']",
}

# (regex, severity, title, suggestion)
RISKY_PATTERNS = [
    (r"\beval\(", "high", "Use of eval()", "Avoid eval; use ast.literal_eval or explicit parsing."),
    (r"\bexec\(", "high", "Use of exec()", "Avoid executing dynamic code."),
    (r"shell\s*=\s*True", "high", "subprocess with shell=True", "Pass an argument list and drop shell=True."),
    (r"pickle\.loads?\(", "high", "Unsafe deserialization (pickle)", "Use JSON or a safe format for untrusted data."),
    (r"yaml\.load\((?!.*Loader)", "medium", "yaml.load without safe Loader", "Use yaml.safe_load."),
    (r"hashlib\.(md5|sha1)\(", "medium", "Weak hash algorithm", "Use SHA-256+ (or bcrypt/argon2 for passwords)."),
    (r"verify\s*=\s*False", "medium", "TLS verification disabled", "Keep certificate verification enabled."),
    (r"execute\(\s*f[\"']|execute\([\"'].*[\"']\s*[%+]", "high", "Possible SQL injection", "Use parameterized queries."),
    (r"debug\s*=\s*True", "low", "Debug mode enabled", "Disable debug mode outside local development."),
    (r"(TODO|FIXME|HACK)\b", "info", "Leftover TODO/FIXME marker", "Resolve or track it in an issue."),
]


def finding(category, severity, line, title, detail="", suggestion=""):
    return {"source": "static", "category": category, "severity": severity,
            "line": line, "title": title, "detail": detail, "suggestion": suggestion}


def scan_secrets(code):
    out = []
    for i, text in enumerate(code.splitlines(), 1):
        for name, pat in SECRET_PATTERNS.items():
            if re.search(pat, text):
                out.append(finding("secret_leak", "critical", i, f"{name} found",
                                   "A credential-like value is hard-coded in source.",
                                   "Move it to an environment variable or a secrets manager and rotate it."))
    return out


def redact(code):
    """Mask secrets so they are never sent to the LLM."""
    for name, pat in SECRET_PATTERNS.items():
        if name == "Hard-coded credential":
            code = re.sub(pat, r'\1 = "[REDACTED_SECRET]"', code)
        else:
            code = re.sub(pat, "[REDACTED_SECRET]", code)
    return code


def scan_risky(code):
    out = []
    for i, text in enumerate(code.splitlines(), 1):
        for pat, sev, title, fix in RISKY_PATTERNS:
            if re.search(pat, text):
                cat = "quality" if sev == "info" else "vulnerability"
                out.append(finding(cat, sev, i, title, text.strip()[:120], fix))
    return out


def scan_python(code):
    """AST checks: unused imports, uncalled top-level functions, very long functions."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [finding("quality", "medium", e.lineno, "Syntax error", str(e), "Fix the syntax error.")]
    out = []
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for n in ast.walk(tree):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                name = (a.asname or a.name).split(".")[0]
                if name != "*" and name not in used:
                    out.append(finding("unused_code", "low", n.lineno, f"Unused import '{name}'",
                                       "Imported but never referenced.", "Remove the import."))
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if n.name not in used and n.name != "main" and not n.decorator_list and not n.name.startswith("__"):
                out.append(finding("unused_code", "low", n.lineno, f"Function '{n.name}' is never called",
                                   "No references found in this file.", "Remove it if it is truly dead code."))
            length = (n.end_lineno or n.lineno) - n.lineno + 1
            if length > 50:
                out.append(finding("quality", "low", n.lineno, f"Long function '{n.name}' ({length} lines)",
                                   "", "Split into smaller functions."))
    return out


def run_all(code, filename=""):
    results = scan_secrets(code) + scan_risky(code)
    if filename.endswith(".py") or not filename:
        results += scan_python(code)
    return results
