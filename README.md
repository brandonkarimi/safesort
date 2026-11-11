# SafeSort

SafeSort is an AI agent that sorts a messy folder and quarantines
risky files. It never deletes anything.

## How it works

1. The scanner lists the files in a folder and flags risky ones.
2. The LLM (Gemini) writes a plan in a small language (DSL) with
   five commands: CREATE_FOLDER, MOVE_FILE, RENAME_FILE,
   QUARANTINE_FILE, LIST_FILES.
3. You review the plan and approve it.
4. The executor runs only the approved actions. Risky files go to
   Quarantine. Every action is logged, and rollback restores files.

The LLM never moves a file itself. It only writes the plan.

## Run it

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

For a live model, set `GEMINI_API_KEY` or `OPENAI_API_KEY` first.
With no key, it runs in demo mode and says so.

## Test it

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

## Live demo

https://muse.ai/s/safesort-quarantine-agent-og6n6lp6x0xgm/DWUU-pBPKZA-RNR9O1nQCy6XYdbAqCkoPqcvXhn7wO0
