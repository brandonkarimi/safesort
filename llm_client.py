"""
llm_client.py - Generative API provider logic for SafeSort.

The flow I implemented: prompt template file -> fill variables ->
call a Generative API from Python -> parse the JSON wrapper -> parse
and validate the DSL inside it -> return the plan.

Providers, in priority order:
  1. Gemini  - used when GEMINI_API_KEY is set. My primary live
               provider. Model from GEMINI_MODEL (default:
               gemini-3-flash-preview).
  2. OpenAI  - used when OPENAI_API_KEY is set (and no Gemini key).
               Model from OPENAI_MODEL (default: gpt-4o-mini).
  3. Demo    - no key set. The deterministic demo planner in
               planner_demo.py returns the SAME plan schema, so the
               demo can never fail for lack of an API key. Mode is
               always labeled "demo", never presented as live.

Only the Python standard library (urllib) is used for API calls.
The only external dependency of this project is Flask (see app.py).
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

import planner_demo
from dsl import DSL_SPEC, DSLError, check_coverage, parse_dsl

TEMPLATE_PATH = Path(__file__).parent / "prompts" / "prompt_template.txt"


class LLMError(Exception):
    """Raised when a live provider call or its parsing fails."""


# ----------------------------------------------------------------------
# Prompt template
# ----------------------------------------------------------------------

def load_prompt(inventory, base_path, instruction):
    """Fill the prompt template file with the scan results.

    Uses simple string replacement (not str.format) because the
    template intentionally contains many literal JSON braces for the
    Template pattern's output schema.
    """
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    inventory_json = json.dumps(inventory, indent=2)
    return (
        template.replace("{base_path}", str(base_path))
        .replace("{instruction}", instruction or "")
        .replace("{inventory_json}", inventory_json)
        .replace("{dsl_spec}", DSL_SPEC)
    )


# ----------------------------------------------------------------------
# Provider selection
# ----------------------------------------------------------------------

def current_mode():
    """Return 'gemini', 'openai', or 'demo' based on the environment."""
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return "demo"


# ----------------------------------------------------------------------
# Live provider calls (stdlib urllib only, one retry on 429/503)
# ----------------------------------------------------------------------

def _post_json(url, payload, headers, timeout=30):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for key, value in headers.items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise LLMError(f"Provider returned HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise LLMError(f"Could not reach the provider: {exc.reason}.") from exc


def _post_json_with_retry(url, payload, headers, timeout=30):
    """Call once, then retry once after a short backoff on 429/503."""
    try:
        return _post_json(url, payload, headers, timeout=timeout)
    except LLMError as exc:
        if "429" in str(exc) or "503" in str(exc):
            time.sleep(2)
            return _post_json(url, payload, headers, timeout=timeout)
        raise


def _call_openai(prompt):
    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    payload = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system",
             "content": "You are a cybersecurity file-triage analyst. "
                        "Respond with JSON only, matching the schema in "
                        "the user message exactly."},
            {"role": "user", "content": prompt},
        ],
    }
    result = _post_json_with_retry(
        "https://api.openai.com/v1/chat/completions",
        payload,
        {"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
    )
    try:
        return result["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError("Unexpected response shape from OpenAI.") from exc


def _call_gemini(prompt):
    model = os.environ.get("GEMINI_MODEL", "gemini-3-flash-preview")
    api_key = os.environ["GEMINI_API_KEY"]
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={api_key}"
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2},
    }
    result = _post_json_with_retry(url, payload, {})
    try:
        return result["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError("Unexpected response shape from Gemini.") from exc


# ----------------------------------------------------------------------
# Parsing / normalization (shared by all providers)
# ----------------------------------------------------------------------

def parse_model_json(raw_text):
    """Parse model output robustly: strip code fences, extract the
    outermost JSON object, and raise a clear LLMError on failure."""
    if not raw_text or not raw_text.strip():
        raise LLMError("The model returned an empty response.")
    text = raw_text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise LLMError("The model did not return a JSON object.")
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise LLMError(f"The model returned invalid JSON: {exc}.") from exc


def _extract_dsl_fallback(raw_text):
    """Last-resort fallback: pull DSL lines straight from raw text.

    Only used when the JSON wrapper cannot be parsed. Lines must start
    with a known verb. Returns None when nothing usable is found.
    """
    verbs = ("CREATE_FOLDER", "MOVE_FILE", "RENAME_FILE",
             "QUARANTINE_FILE", "LIST_FILES")
    lines = [line.strip() for line in (raw_text or "").splitlines()
             if line.strip().upper().startswith(verbs)]
    return "\n".join(lines) if lines else None


def normalize_plan(data, inventory, base_path, mode):
    """Validate a parsed live result into the exact plan schema.

    Parses and validates the DSL, checks that every inventoried file
    is covered exactly once, and rebuilds the action list from the
    validated DSL so the plan the UI shows is the plan that will run.
    """
    if not isinstance(data, dict):
        raise LLMError("The model result was not a JSON object.")
    dsl_text = data.get("dsl")
    if not isinstance(dsl_text, str) or not dsl_text.strip():
        raise LLMError("The model result has no DSL plan.")
    try:
        parsed = parse_dsl(dsl_text, base_path)
        check_coverage(parsed, inventory)
    except DSLError as exc:
        raise LLMError(f"The model plan failed validation: {exc}") from exc

    by_source = {}
    for item in data.get("actions") or []:
        if isinstance(item, dict) and item.get("source"):
            by_source[item["source"]] = item
    by_dest = {}
    for item in data.get("actions") or []:
        if isinstance(item, dict) and item.get("destination"):
            by_dest.setdefault(item["destination"], item)

    actions = []
    for action in parsed:
        meta = by_source.get(action["source"]) or by_dest.get(
            action["destination"]) or {}
        file_name = meta.get("file")
        if not file_name and action["source"]:
            file_name = Path(action["source"]).name
        actions.append({
            "id": action["id"],
            "verb": action["verb"],
            "source": action["source"],
            "destination": action["destination"],
            "file": file_name,
            "risk": str(meta.get("risk", "Low")),
            "reason": str(meta.get("reason", "")),
            "rationale": str(meta.get("rationale", "")),
        })
    return {"dsl": dsl_text.strip() + "\n", "actions": actions,
            "summary": str(data.get("summary", "")), "mode": mode}


# ----------------------------------------------------------------------
# Main entry point used by app.py
# ----------------------------------------------------------------------

def generate_plan(inventory, base_path, instruction=""):
    """Return a plan dict in the exact app schema.

    Uses a live provider when a key is configured; otherwise the demo
    planner. A live failure (provider error, bad JSON, invalid DSL, or
    coverage failure) falls back to the demo planner, and the returned
    mode is honestly labeled "demo" with a fallback_reason. Demo output
    is never presented as a live model result.
    """
    mode = current_mode()
    if mode == "demo":
        return planner_demo.plan_from_inventory(
            inventory, base_path, instruction)

    prompt = load_prompt(inventory, base_path, instruction)
    try:
        if mode == "gemini":
            raw = _call_gemini(prompt)
        else:
            raw = _call_openai(prompt)
        try:
            data = parse_model_json(raw)
        except LLMError:
            dsl_text = _extract_dsl_fallback(raw)
            if not dsl_text:
                raise
            data = {"dsl": dsl_text, "actions": [],
                    "summary": "Plan recovered from DSL lines in the "
                               "model output."}
        return normalize_plan(data, inventory, base_path, mode)
    except LLMError as exc:
        plan = planner_demo.plan_from_inventory(
            inventory, base_path, instruction)
        plan["fallback_reason"] = (
            f"Live provider failed ({exc}). This plan was made by the "
            "local demo planner instead.")
        return plan
