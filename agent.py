"""Gemini-powered review agent."""
import json
import os
import time

from google import genai
from google.genai import types

SYSTEM_PROMPT = """You are a senior code reviewer and refactoring agent.
Review the given source file and return ONLY JSON with this exact shape:
{
  "summary": "2-3 sentence overview of the file",
  "quality_score": <integer 0-100>,
  "findings": [
    {"category": "unused_code|out_of_scope|vulnerability|quality|secret_leak",
     "severity": "critical|high|medium|low|info",
     "line": <integer or null>,
     "title": "short title",
     "detail": "what is wrong",
     "suggestion": "how to fix"}
  ],
  "cleaned_code": "the full cleaned file"
}
Rules:
- unused_code: unused imports, variables, functions, commented-out code, unreachable code.
- out_of_scope: code that does not belong to the file's main purpose (debug helpers, unrelated utilities, experiments).
- vulnerability: injection, unsafe deserialization, weak crypto, missing validation, insecure defaults, etc.
- quality: naming, duplication, complexity, missing error handling, missing docstrings.
- secret_leak: hard-coded credentials, tokens, personal data, internal URLs. Values shown as [REDACTED_SECRET] were masked before sending; keep them as an environment-variable lookup in cleaned_code.
- The file may be one of many in a project. Other file paths are listed for context: do NOT mark public functions/classes/exports as unused if other files could plausibly import them, and keep the file's public API intact.
- cleaned_code must keep the file's behavior, remove dead/out-of-scope code, and fix simple security issues. Do not invent new features.
- Do not repeat findings listed under 'Already detected by static scan' unless you add new information.
"""


def analyze(code: str, filename: str, static_findings: list, project_files=None) -> dict:
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    hints = "\n".join(f"- line {f['line']}: {f['title']}" for f in static_findings) or "none"
    others = "\n".join(f"- {p}" for p in (project_files or [])[:60]) or "(single file)"
    prompt = (f"File name: {filename or 'unknown'}\n\n"
              f"Other files in the project:\n{others}\n\n"
              f"Already detected by static scan:\n{hints}\n\n"
              f"Source code:\n```\n{code}\n```")

    last_err = None
    for attempt in range(2):  # one retry helps with transient rate limits
        try:
            resp = client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    temperature=0.2,
                ),
            )
            data = json.loads(resp.text)
            for f in data.get("findings", []):
                f["source"] = "gemini"
            return data
        except Exception as e:
            last_err = e
            time.sleep(3)
    raise last_err
