"""Collecting files: GitHub repo download + shared filtering rules."""
import io
import os
import re
import zipfile

ALLOWED_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".c", ".cpp",
               ".h", ".rs", ".sh", ".sql", ".yml", ".yaml", ".json", ".html", ".css", ".env"}
SOURCE_EXT = ALLOWED_EXT - {".yml", ".yaml", ".json", ".html", ".css", ".env"}  # analyzed first
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", "vendor", "target", ".next"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock"}
MAX_FILE_BYTES = 100 * 1024
MAX_ZIP_BYTES = 30 * 1024 * 1024


def is_candidate(path, size):
    parts = path.split("/")
    name = parts[-1]
    if any(p in SKIP_DIRS for p in parts[:-1]) or name in SKIP_FILES or name.endswith(".min.js"):
        return False
    ext = os.path.splitext(name)[1].lower()
    ok = ext in ALLOWED_EXT or name.startswith(".env") or name == "Dockerfile"
    return ok and 0 < size <= MAX_FILE_BYTES


def prioritize(files, max_files):
    """Source code first, then config files; capped at max_files."""
    key = lambda f: (0 if os.path.splitext(f["path"])[1].lower() in SOURCE_EXT else 1, f["path"])
    return sorted(files, key=key)[:max_files]


def parse_github_url(url):
    m = re.match(r"^https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?"
                 r"(?:/tree/([^/]+)(?:/(.*))?)?/?$", url.strip())
    if not m:
        raise ValueError("Enter a valid GitHub URL, e.g. https://github.com/owner/repo "
                         "(or .../tree/<branch>/<folder>)")
    owner, repo, ref, sub = m.groups()
    if ref and not re.fullmatch(r"[\w./-]+", ref):
        raise ValueError("Unsupported branch name.")
    return owner, repo, ref, (sub or "").strip("/")


def extract_zip(data, subpath=""):
    """Return (candidate_files, total_files_seen) from a GitHub zipball (bytes)."""
    out, total = [], 0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            path = info.filename.split("/", 1)[-1]  # strip "owner-repo-sha/" prefix
            if subpath and not path.startswith(subpath + "/"):
                continue
            total += 1
            if not is_candidate(path, info.file_size):
                continue
            try:
                out.append({"path": path, "content": z.read(info).decode("utf-8")})
            except UnicodeDecodeError:
                pass  # binary file
    return out, total


def fetch_repo(url):
    import requests  # imported here so the rest of the app works without it

    owner, repo, ref, sub = parse_github_url(url)
    api = f"https://api.github.com/repos/{owner}/{repo}/zipball" + (f"/{ref}" if ref else "")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "code-guardian-demo"}
    if os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"

    r = requests.get(api, headers=headers, timeout=30, stream=True)
    if r.status_code == 404:
        raise ValueError("Repository or branch not found (private repos need GITHUB_TOKEN).")
    if r.status_code in (401, 403):
        raise ValueError("GitHub refused the request (rate limit or private repo). Set GITHUB_TOKEN in .env.")
    r.raise_for_status()

    buf, size = io.BytesIO(), 0
    for chunk in r.iter_content(65536):
        size += len(chunk)
        if size > MAX_ZIP_BYTES:
            raise ValueError("Repository is too large for this demo. Point to a sub-folder (/tree/<branch>/<folder>).")
        buf.write(chunk)

    files, total = extract_zip(buf.getvalue(), sub)
    return files, total, f"{owner}/{repo}" + (f"/{sub}" if sub else "")
