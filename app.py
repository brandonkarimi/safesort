"""
app.py - Flask server for SafeSort.

Architecture:
  web UI -> Flask server -> scanner (local inventory + risk flags)
  -> planner (Gemini, then OpenAI, then a clearly labeled demo
  planner) -> DSL validator -> executor -> audit log.

Routes:
  GET  /              serves the web UI (templates/index.html)
  GET  /health        returns JSON status and current mode
  POST /api/scan      {base_path} -> inventory with risk flags
  POST /api/plan      {base_path, instruction} -> plan (DSL + actions)
  POST /api/execute   {plan_id, approved_ids} -> executes only the
                       approved actions, only from a generated plan
  POST /api/rollback  {execution_id} -> restores moved files
  GET  /api/audit     returns audit log entries

Safety: nothing is executed unless the user approved it in a plan
this server generated. There is no delete anywhere in the app.
"""

import json
import os
import uuid
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

import dsl as dsl_module
import llm_client
from scanner import scan_folder

load_dotenv()

app = Flask(__name__)

BASE_DIR = Path(__file__).parent
DEMO_FOLDER = BASE_DIR / "demo_folder"
AUDIT_FILE = BASE_DIR / "audit.log"

# In-memory stores. Plans and executions live here for the session.
# The audit log is also appended to audit.log on disk.
PLANS = {}
EXECUTIONS = {}


def _default_base():
    return str(DEMO_FOLDER.resolve())


def _resolve_base(raw):
    """Resolve the requested base folder. Defaults to the demo folder."""
    raw = (raw or "").strip()
    if not raw:
        return DEMO_FOLDER.resolve()
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise ValueError("base_path must be an absolute path.")
    return path.resolve()


def _audit(event, detail):
    entry = {"event": event, "detail": detail}
    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except OSError:
        pass
    return entry


def _load_audit():
    entries = []
    try:
        with open(AUDIT_FILE, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        pass
    return entries


@app.get("/")
def index():
    return render_template("index.html",
                           default_base=_default_base())


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "safesort-quarantine-agent",
        "mode": llm_client.current_mode(),
    })


@app.post("/api/scan")
def api_scan():
    payload = request.get_json(silent=True) or {}
    try:
        base = _resolve_base(payload.get("base_path"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not base.is_dir():
        return jsonify({"error": f"Folder not found: {base}"}), 404
    try:
        inventory = scan_folder(base)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"base_path": str(base), "inventory": inventory,
                    "mode": llm_client.current_mode()})


@app.post("/api/plan")
def api_plan():
    payload = request.get_json(silent=True) or {}
    instruction = (payload.get("instruction") or "").strip()
    try:
        base = _resolve_base(payload.get("base_path"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not base.is_dir():
        return jsonify({"error": f"Folder not found: {base}"}), 404
    try:
        inventory = scan_folder(base)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not inventory:
        return jsonify({"error": "The folder is empty. Add files and try again."}), 400
    plan = llm_client.generate_plan(inventory, base, instruction)
    plan_id = str(uuid.uuid4())
    PLANS[plan_id] = {"plan": plan, "base_path": str(base),
                      "inventory": inventory}
    _audit("plan_generated",
           {"plan_id": plan_id, "base_path": str(base),
            "mode": plan.get("mode"), "actions": len(plan["actions"])})
    return jsonify({"plan_id": plan_id, "base_path": str(base),
                    "inventory": inventory, "dsl": plan["dsl"],
                    "actions": plan["actions"],
                    "summary": plan.get("summary", ""),
                    "mode": plan.get("mode"),
                    "fallback_reason": plan.get("fallback_reason")})


@app.post("/api/execute")
def api_execute():
    payload = request.get_json(silent=True) or {}
    plan_id = payload.get("plan_id")
    approved_ids = payload.get("approved_ids")
    if not plan_id or plan_id not in PLANS:
        return jsonify({"error": "Unknown plan_id. Generate a plan first."}), 404
    if not approved_ids:
        return jsonify({"error": "No actions approved. Check at least one action."}), 400
    stored = PLANS[plan_id]
    plan = stored["plan"]
    base = Path(stored["base_path"])
    # Re-parse the stored DSL so only validated actions can run.
    try:
        actions = dsl_module.parse_dsl(plan["dsl"], base)
    except dsl_module.DSLError as exc:
        return jsonify({"error": f"Stored plan failed validation: {exc}"}), 400
    approved = set(approved_ids)
    unknown = approved - {a["id"] for a in actions}
    if unknown:
        return jsonify({"error": f"Unknown action ids: {sorted(unknown)}"}), 400
    result = dsl_module.execute_actions(actions, base, approved_ids=approved)
    EXECUTIONS[result["execution_id"]] = result
    _audit("executed",
           {"execution_id": result["execution_id"], "plan_id": plan_id,
            "executed": result["executed"], "errors": result["errors"]})
    return jsonify(result)


@app.post("/api/rollback")
def api_rollback():
    payload = request.get_json(silent=True) or {}
    execution_id = payload.get("execution_id")
    if not execution_id or execution_id not in EXECUTIONS:
        return jsonify({"error": "Unknown execution_id. Nothing to roll back."}), 404
    result = dsl_module.rollback_moves(EXECUTIONS[execution_id])
    _audit("rollback",
           {"execution_id": execution_id, "restored": result["restored"],
            "errors": result["errors"]})
    return jsonify(result)


@app.get("/api/audit")
def api_audit():
    return jsonify({"entries": _load_audit()})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)
