import os

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

load_dotenv()

import agent  # noqa: E402  (after load_dotenv)
import scanner  # noqa: E402

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024  # 200 KB
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/static-sample")
def sample():
    with open(os.path.join(app.root_path, "sample", "vulnerable_sample.py")) as f:
        return f.read(), 200, {"Content-Type": "text/plain"}


@app.post("/api/analyze")
def analyze():
    body = request.get_json(silent=True) or {}
    code = body.get("code", "")
    filename = body.get("filename", "")
    if not code.strip():
        return jsonify(error="No code provided."), 400
    if not os.getenv("GEMINI_API_KEY"):
        return jsonify(error="GEMINI_API_KEY is not set. See README."), 500

    static = scanner.run_all(code, filename)
    safe_code = scanner.redact(code)  # never send raw secrets to the LLM

    try:
        ai = agent.analyze(safe_code, filename, static)
    except Exception as e:  # keep demo errors readable
        return jsonify(error=f"Gemini call failed: {e}", static_findings=static), 502

    findings = sorted(static + ai.get("findings", []),
                      key=lambda f: SEV_ORDER.get(f.get("severity"), 5))
    return jsonify(summary=ai.get("summary", ""), quality_score=ai.get("quality_score"),
                   findings=findings, cleaned_code=ai.get("cleaned_code", ""))


if __name__ == "__main__":
    app.run(debug=False, port=int(os.getenv("PORT", 5000)))
