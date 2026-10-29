# Code Guardian

A small demo app that shows how an AI agent (**Google Gemini**) can help with:

| Capability | How it's done |
|---|---|
| Remove unused code (imports, dead functions, commented-out code) | Python AST check (project-aware) + Gemini |
| Flag out-of-scope code (debug helpers, unrelated utilities) | Gemini |
| Highlight open vulnerabilities (SQL injection, `eval`, pickle, weak hashes, ...) | Regex rules + Gemini |
| Code scan & quality check (complexity, naming, TODOs, quality score 0-100) | AST rules + Gemini |
| Secret / sensitive-data leak detection (API keys, passwords, tokens, private keys) | Regex rules (secrets are **redacted before being sent to Gemini**) |
| Produce a cleaned version of each file | Gemini |

**Three ways to feed it code:** paste a snippet, upload multiple files / a whole folder, or give a **GitHub repository link**.
It is intentionally simple: a Flask backend, one HTML page, and three small Python modules.

## How it works

```
Browser: paste code | upload files/folder | GitHub URL
        |
        v
POST /api/analyze  (app.py)
        |-- collect files   (repo.py: GitHub zipball download, extension/size/folder filters, file cap)
        |-- project context (scanner.collect_names: names used anywhere in the project)
        |-- for each file, in parallel (MAX_WORKERS):
        |      1. scanner.py     -> fast local rule checks (secrets, risky patterns, unused code)
        |      2. scanner.redact -> masks any detected secrets
        |      3. agent.py       -> redacted code + static findings + list of other files go to Gemini,
        |                           which returns JSON: summary, score, findings, cleaned_code
        v
Project overview (avg score, severity counts) + per-file findings and cleaned code,
files sorted with the riskiest first
```

## Prerequisites

- Python **3.10+**
- A Gemini API key (free tier works): https://aistudio.google.com/apikey
- Internet access (Gemini API, and GitHub if you scan repositories)

## Setup (local)

### 1. Open the project folder

```bash
cd code-guardian
```

### 2. Create a virtual environment

macOS / Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows (PowerShell):
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

macOS / Linux: `cp .env.example .env`  |  Windows: `copy .env.example .env`

Edit `.env`:

```
GEMINI_API_KEY=your-real-key
GEMINI_MODEL=gemini-2.5-flash
# GITHUB_TOKEN=ghp_xxx   # optional, for private repos / higher GitHub rate limits
# MAX_FILES=15           # optional, files analyzed per run
# MAX_WORKERS=3          # optional, parallel Gemini calls
```

| Variable | Required | Purpose |
|---|---|---|
| `GEMINI_API_KEY` | yes | Gemini API access |
| `GEMINI_MODEL` | no | Change if a model is renamed or retired |
| `GITHUB_TOKEN` | no | Private repos; avoids GitHub's anonymous rate limit |
| `MAX_FILES` | no | Cap on files per run (default 15) |
| `MAX_WORKERS` | no | Parallel Gemini calls (default 3). Lower it if you see `429` errors |

### 5. Run

```bash
python app.py
```

Open http://127.0.0.1:5000

## Using the demo

1. Pick an input tab:
   - **Paste code**: paste a snippet and optionally a filename (e.g. `app.py`).
   - **Upload files / folder**: choose several files, or a whole folder. Unsupported types, files over 100 KB and folders like `node_modules`, `.git`, `venv`, `dist` are skipped automatically.
   - **GitHub repository**: paste a link such as `https://github.com/owner/repo`. To scan one branch or folder use `https://github.com/owner/repo/tree/<branch>/<folder>`.
2. Click **Load sample project** to try 3 intentionally flawed files (`sample/`): hard-coded keys, SQL injection, `eval`, pickle, unused imports and dead code. `helpers.py` imports `hash_password` from the other file, which shows that the unused-code check understands cross-file usage.
3. Click **Analyze**.
4. Review the overview (files analyzed, average score, severity counts), pick a file on the left, then read its findings and the cleaned code (Copy button).

## Project layout

```
code-guardian/
├── app.py                 Flask server, API routes, parallel per-file review
├── repo.py                File collection: GitHub download + filtering rules
├── scanner.py             Local rule-based checks + secret redaction
├── agent.py               Gemini agent (prompt, call, retry, JSON parsing)
├── templates/index.html   Single-page UI
├── sample/                Intentionally flawed sample project
├── requirements.txt
├── .env.example
└── README.md
```

## Notes and limitations (it's a demo)

- Each file is reviewed on its own by Gemini (it only sees the other files' *names*), so cross-file refactoring is out of scope. The AST unused-code check is project-wide for Python only.
- Only the first `MAX_FILES` files are analyzed (source code is prioritized over config files). Large repos: point to a sub-folder.
- GitHub repos larger than ~30 MB are rejected. Only public repos work without `GITHUB_TOKEN`.
- Secret detection is regex-based and will miss custom formats. It is not a replacement for gitleaks, Bandit, SonarQube or Semgrep.
- Cleaned code comes from an LLM: **review it and run your tests** before using it.
- Code (with detected secrets masked) is sent to the Gemini API. Do not use this on proprietary repos unless your organization allows it.
- No auth, database or history; results live only in the browser page.

## Troubleshooting

| Problem | Fix |
|---|---|
| `GEMINI_API_KEY is not set` | Make sure `.env` exists next to `app.py` and has the key; restart the app. |
| `Gemini call failed: 404 ... model` (shown on a file) | Set a valid model name in `GEMINI_MODEL`. |
| `Gemini call failed: 429` | Rate limit. Set `MAX_WORKERS=1` and/or lower `MAX_FILES`. |
| `GitHub refused the request` | Rate limit or private repo: add `GITHUB_TOKEN` to `.env`. |
| `Repository or branch not found` | Check the URL/branch; private repos need `GITHUB_TOKEN`. |
| `No supported source files found` | The repo/folder has no supported extensions, or everything was over 100 KB or in ignored folders. |
| `JSONDecodeError` on a file | Rare malformed model output; analyze again, or try a larger model. |
| `ModuleNotFoundError` | Activate the virtual environment and re-run `pip install -r requirements.txt`. |
| Port 5000 busy (macOS AirPlay) | `PORT=5001 python app.py` (Windows: `$env:PORT=5001; python app.py`). |

## Ideas for next steps

- Side-by-side diff of original vs cleaned code, and "download all cleaned files" as a zip
- Add Bandit / Semgrep / gitleaks as extra scanners
- A repo-level Gemini summary that reasons across files
- Export findings as a PDF/JSON report
