import os
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

load_dotenv()

import agent  # noqa: E402  (after load_dotenv)
import repo  # noqa: E402
import scanner  # noqa: E402

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024  # 3 MB request body
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
MAX_FILES = int(os.getenv("MAX_FILES", 15))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", 3))


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/sample")
def sample():
    folder = os.path.join(app.root_path, "sample")
    files = []
    for name in sorted(os.listdir(folder)):
        with open(os.path.join(folder, name), encoding="utf-8") as f:
            files.append({"path": f"sample/{name}", "content": f.read()})
    return jsonify(files=files)


def review(f, all_paths, global_used):
    path, code = f["path"], f["content"]
    static = scanner.run_all(code, path, global_used)
    out = {"path": path, "lines": code.count("\n") + 1, "quality_score": None,
           "summary": "", "cleaned_code": "", "error": None}
    ai_findings = []
    try:
        ai = agent.analyze(scanner.redact(code), path, static, all_paths)  # never send raw secrets
        out.update(summary=ai.get("summary", ""), quality_score=ai.get("quality_score"),
                   cleaned_code=ai.get("cleaned_code", ""))
        ai_findings = ai.get("findings", [])
    except Exception as e:
        out["error"] = f"Gemini call failed: {e}"
    out["findings"] = sorted(static + ai_findings, key=lambda x: SEV_ORDER.get(x.get("severity"), 5))
    return out


@app.post("/api/analyze")
def analyze():
    body = request.get_json(silent=True) or {}
    if not os.getenv("GEMINI_API_KEY"):
        return jsonify(error="GEMINI_API_KEY is not set. See README."), 500

    # 1. Collect files from one of three sources
    try:
        if body.get("repo_url"):
            candidates, total, label = repo.fetch_repo(body["repo_url"])
        elif body.get("files"):
            raw = [{"path": str(f.get("path", "")).replace("\\", "/").lstrip("/"),
                    "content": str(f.get("content", ""))} for f in body["files"]]
            candidates = [f for f in raw if repo.is_candidate(f["path"], len(f["content"].encode()))]
            total, label = len(raw), "uploaded files"
        elif body.get("code", "").strip():
            name = body.get("filename") or "pasted_code.py"
            candidates, total, label = [{"path": name, "content": body["code"]}], 1, "pasted code"
        else:
            return jsonify(error="Provide code, files or a GitHub repository URL."), 400
    except ValueError as e:
        return jsonify(error=str(e)), 400
    except Exception as e:
        return jsonify(error=f"Could not fetch files: {e}"), 502

    selected = repo.prioritize(candidates, MAX_FILES)
    if not selected:
        return jsonify(error="No supported source files found (checked extensions, size and ignored folders)."), 400

    # 2. Cross-file context so "unused function" checks don't flag code used elsewhere
    all_paths = [f["path"] for f in selected]
    global_used = set()
    for f in selected:
        if f["path"].endswith(".py"):
            global_used |= scanner.collect_names(f["content"])

    # 3. Review files in parallel (static scan + Gemini)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = list(pool.map(lambda f: review(f, all_paths, global_used), selected))

    results.sort(key=lambda r: (min((SEV_ORDER.get(x["severity"], 5) for x in r["findings"]), default=9), r["path"]))
    scores = [r["quality_score"] for r in results if isinstance(r["quality_score"], (int, float))]
    counts = Counter(x["severity"] for r in results for x in r["findings"])
    return jsonify(source=label, total_files=total, analyzed=len(results), skipped=total - len(results),
                   avg_score=round(sum(scores) / len(scores)) if scores else None,
                   severity_counts=dict(counts), files=results)


if __name__ == "__main__":
    app.run(debug=False, port=int(os.getenv("PORT", 5000)))
