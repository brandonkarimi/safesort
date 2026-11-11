# SafeSort Quarantine Agent

SafeSort is an AI agent that sorts a messy folder and quarantines risky
files instead of deleting them or mixing them in with clean files.

A messy Downloads folder is easy to ignore until it is not. The usual
advice from a chatbot is only text: it can suggest folders, but the
user still has to move every file by hand. Worse, a folder can hold a
risky file next to a clean one: a PDF with embedded JavaScript, or a
text file with a password in plain text. Sorting by extension alone
would file the risky file with the clean ones. SafeSort does the work,
shows the plan first, and keeps risky files separate.

## How it works

Architecture (LLM brain plus a separate actor):

```
Web UI (templates/index.html)
  -> Flask server (app.py)
    -> Scanner (scanner.py): local inventory plus risk flags, no LLM
    -> Planner (llm_client.py): Gemini, then OpenAI, then demo planner
    -> DSL validator (dsl.py): parse and validate the plan
    -> Executor (dsl.py): run only approved actions
    -> Audit log (audit.log): every plan, execution, and rollback
```

The LLM never moves a file. It only outputs DSL. The executor turns
validated DSL into real file operations.

## The DSL

One command per line. Only these five verbs exist:

```
CREATE_FOLDER <absolute path>
MOVE_FILE <absolute source> <absolute destination>
RENAME_FILE <absolute source> <absolute destination>
QUARANTINE_FILE <absolute source>
LIST_FILES <absolute path>
```

Example plan:

```
CREATE_FOLDER /home/user/Downloads/Finance
CREATE_FOLDER /home/user/Downloads/Quarantine
MOVE_FILE /home/user/Downloads/invoice.pdf /home/user/Downloads/Finance/invoice.pdf
QUARANTINE_FILE /home/user/Downloads/suspicious.pdf
LIST_FILES /home/user/Downloads
```

## Prompt design

The full template is in `prompts/prompt_template.txt`. It uses three
patterns:

1. **Persona.** "You are a cybersecurity file-triage analyst." The
   model sorts like a careful security analyst: organize clean files,
   quarantine risky ones, never delete.
2. **Few-Shot.** Three examples: a clean invoice goes to Finance, a
   research paper goes to Research, and a suspicious PDF with a leaked
   key goes to Quarantine with a reason.
3. **Template.** DSL-only output inside a JSON wrapper with an exact
   schema: `dsl`, `actions` (verb, source, destination, file, risk,
   reason, rationale), and `summary`. The DSL spec is included verbatim
   in the prompt, every path must be absolute and under the base folder,
   and every file in the inventory must be covered exactly once.

## Safety rules

- There is no DELETE verb anywhere in the app. Quarantine (move into
  `<base>/Quarantine/`) is the safe alternative to deleting a file.
- The plan is shown in the UI first. Nothing runs until the user
  approves it, and individual actions can be unchecked. Execution only
  accepts actions from a plan this server generated.
- Every path must be absolute and stay under the base folder. Paths
  with `..`, symlinks that escape the base, and paths outside the base
  are rejected at parse time and again at execution time.
- Invalid DSL lines are rejected with a clear error and never executed.
- Every move records its original path, so rollback restores files to
  where they were. Nothing is deleted by rollback either.
- The scanner reads at most the first 64KB of a file as text. It never
  executes file content.
- API keys are never in code, logs, or files. They come from the
  environment only (`GEMINI_API_KEY`, `OPENAI_API_KEY`).
- The server binds to 127.0.0.1 only. It is a local tool.

## How to run it

```bash
cd safesort
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 in a browser. The demo folder is
filled in by default. Click Scan folder, then Generate plan, review
the plan, uncheck anything you do not want, then Approve and execute.

For a live model, set one key before starting the app:

```bash
export GEMINI_API_KEY="your key here"
# or
export OPENAI_API_KEY="your key here"
```

With no key set, the app runs in demo mode. The mode badge in the UI
says Demo mode, and plans come from the local demo planner. Demo output
is never presented as a live model result. If a live provider fails
(rate limit, bad output, invalid DSL), the app falls back to the demo
planner and says so in the plan response.

## Endpoints

| Method | Route | Body | What it does |
| --- | --- | --- | --- |
| GET | `/` | | Web UI |
| GET | `/health` | | Status and current mode |
| POST | `/api/scan` | `{base_path}` | Inventory with risk flags |
| POST | `/api/plan` | `{base_path, instruction}` | Generate a plan |
| POST | `/api/execute` | `{plan_id, approved_ids}` | Run approved actions only |
| POST | `/api/rollback` | `{execution_id}` | Restore moved files |
| GET | `/api/audit` | | Audit log entries |

## The demo folder

`demo_folder/` has 10 fake files for the demo. All content is fake:

- `invoice.pdf`, `budget.csv` go to Finance
- `research-paper.pdf` goes to Research
- `resume.pdf`, `notes.txt` go to Documents
- `photo.jpg` goes to Images (a real 1x1 PNG saved as .jpg)
- `script.py` goes to Code
- `archive.zip` goes to Archives
- `suspicious.pdf` is quarantined (fake `/JavaScript` marker plus a
  fake `sk-` key)
- `credentials.txt` is quarantined (fake `password=` line)

Tests copy the demo folder to a temp folder first, so the bundled
folder is never mutated. In the UI, point the app at a copy if you
want to keep the original intact.

## Testing

```bash
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

Tests cover: the DSL validator rejecting `..`, paths outside the base,
relative paths, DELETE and unknown verbs, and symlink escapes; the
executor moving files and rollback restoring them; execution running
only approved actions; the demo planner quarantining the suspicious
file and covering every file exactly once; and the scanner flagging
secrets, suspicious PDFs, and double extensions.

## Files

- `app.py` - Flask server and routes
- `scanner.py` - local inventory and risk heuristics
- `dsl.py` - DSL spec, parser, validator, executor, rollback
- `planner_demo.py` - deterministic demo planner, same plan shape
- `llm_client.py` - Gemini, OpenAI, and demo provider logic
- `prompts/prompt_template.txt` - Persona, Few-Shot, Template
- `templates/index.html` - web UI
- `demo_folder/` - 10 fake files for the demo
- `tests/test_safesort.py` - pytest tests
