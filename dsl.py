"""
dsl.py - SafeSort DSL: spec, parser, validator, executor, rollback.

The DSL is the contract between the LLM and the actor, following
Lecture 12: the LLM outputs only this small language, and this module
turns it into real file operations. Free text from the LLM is never
executed.

Grammar, one command per line:
  CREATE_FOLDER <absolute path>
  MOVE_FILE <absolute source> <absolute destination>
  RENAME_FILE <absolute source> <absolute destination>
  QUARANTINE_FILE <absolute source>
  LIST_FILES <absolute path>

Safety rules, enforced at parse time and again at execution time:
  - Only the five verbs above exist. There is no DELETE or REMOVE
    verb. Quarantine (move into <base>/Quarantine/) is the safe
    alternative to deleting a file.
  - Every path must be absolute and must stay under the declared base
    folder. Paths containing "..", symlinks that escape the base, and
    absolute paths outside the base are rejected.
  - Invalid lines are rejected with a clear error and never executed.
  - The executor records the original path of every move, rename, and
    quarantine so rollback can restore it.
"""

import shlex
import uuid
from pathlib import Path

VERBS = ("CREATE_FOLDER", "MOVE_FILE", "RENAME_FILE", "QUARANTINE_FILE",
         "LIST_FILES")
# Arity: number of path arguments each verb takes.
VERBS_ARITY = {
    "CREATE_FOLDER": 1,
    "MOVE_FILE": 2,
    "RENAME_FILE": 2,
    "QUARANTINE_FILE": 1,
    "LIST_FILES": 1,
}
FORBIDDEN_VERBS = ("DELETE", "REMOVE", "DELETE_FILE", "REMOVE_FILE",
                   "RMDIR", "UNLINK", "EXEC", "RUN", "SHELL")

DSL_SPEC = """SafeSort DSL specification (version 1)
One command per line. Blank lines and lines starting with # are ignored.
Verbs (only these five exist):
  CREATE_FOLDER <absolute path>
  MOVE_FILE <absolute source> <absolute destination>
  RENAME_FILE <absolute source> <absolute destination>
  QUARANTINE_FILE <absolute source>
  LIST_FILES <absolute path>
Rules:
  - Every path must be an absolute path under the base folder.
  - Never use ".." in a path. Never use a path outside the base folder.
  - There is no DELETE verb. To remove a risky file from circulation,
    use QUARANTINE_FILE, which moves it to <base>/Quarantine/.
  - Every file in the inventory must be the source of exactly one
    MOVE_FILE, RENAME_FILE, or QUARANTINE_FILE action.
  - CREATE_FOLDER actions come first, then the file actions, then an
    optional final LIST_FILES for the base folder.
"""


class DSLError(ValueError):
    """Raised when DSL text or a planned action fails validation."""


def _resolve_under_base(raw_path, base):
    """Resolve a path and require it to stay under base.

    Rejects relative paths, ".." components, and symlinks that escape.
    Returns the resolved Path.
    """
    base_resolved = Path(base).resolve()
    if ".." in Path(raw_path).parts:
        raise DSLError(f"Path uses '..' and is rejected: {raw_path}")
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        raise DSLError(f"Path must be absolute: {raw_path}")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(base_resolved)
    except ValueError:
        raise DSLError(
            f"Path is outside the base folder and is rejected: {raw_path}")
    return resolved


def parse_dsl(dsl_text, base_path):
    """Parse DSL text into a list of action dicts.

    Each action has: id, verb, source (or None), destination (or None),
    and the raw line. Raises DSLError on the first invalid line.
    """
    if not dsl_text or not dsl_text.strip():
        raise DSLError("DSL text is empty. No actions to run.")
    base = Path(base_path)
    actions = []
    for lineno, raw_line in enumerate(dsl_text.strip().splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            raise DSLError(f"Line {lineno}: cannot parse line: {exc}") from exc
        if not parts:
            continue
        verb = parts[0].upper()
        if verb in FORBIDDEN_VERBS:
            raise DSLError(
                f"Line {lineno}: verb {verb} is forbidden. SafeSort has no "
                "delete verb. Use QUARANTINE_FILE to move a risky file "
                "to the Quarantine folder instead.")
        if verb not in VERBS:
            raise DSLError(
                f"Line {lineno}: unknown verb {verb}. Allowed verbs: "
                f"{', '.join(VERBS)}.")
        expected = VERBS_ARITY[verb]
        if len(parts) - 1 != expected:
            raise DSLError(
                f"Line {lineno}: {verb} takes {expected} path argument(s), "
                f"got {len(parts) - 1}.")
        action = {"id": f"a{len(actions) + 1}", "verb": verb,
                  "source": None, "destination": None, "line": line}
        if verb == "CREATE_FOLDER":
            action["destination"] = str(
                _resolve_under_base(parts[1], base))
        elif verb in ("MOVE_FILE", "RENAME_FILE"):
            action["source"] = str(_resolve_under_base(parts[1], base))
            action["destination"] = str(
                _resolve_under_base(parts[2], base))
            if action["source"] == action["destination"]:
                raise DSLError(
                    f"Line {lineno}: source and destination are the same: "
                    f"{action['source']}")
        elif verb == "QUARANTINE_FILE":
            source = _resolve_under_base(parts[1], base)
            action["source"] = str(source)
            action["destination"] = str(
                base.resolve() / "Quarantine" / source.name)
        elif verb == "LIST_FILES":
            action["destination"] = str(
                _resolve_under_base(parts[1], base))
        actions.append(action)
    if not actions:
        raise DSLError("DSL text has no actions. No actions to run.")
    return actions


def check_coverage(actions, inventory):
    """Require every inventoried file to be covered exactly once.

    A file is covered when it is the source of one MOVE_FILE,
    RENAME_FILE, or QUARANTINE_FILE action. Raises DSLError otherwise.
    """
    covered = {}
    for action in actions:
        if action["verb"] in ("MOVE_FILE", "RENAME_FILE", "QUARANTINE_FILE"):
            src = action["source"]
            covered[src] = covered.get(src, 0) + 1
    problems = []
    for item in inventory:
        count = covered.get(item["path"], 0)
        if count == 0:
            problems.append(f"{item['name']} is not covered by any action")
        elif count > 1:
            problems.append(f"{item['name']} is covered {count} times")
    for src, count in covered.items():
        if count > 1:
            continue
        if src not in {item["path"] for item in inventory}:
            problems.append(f"Action covers unknown file: {src}")
    if problems:
        raise DSLError("Coverage check failed: " + "; ".join(problems))


def actions_to_dsl(actions):
    """Render action dicts back to DSL text (one command per line)."""
    lines = []
    for action in actions:
        verb = action["verb"]
        if verb == "CREATE_FOLDER":
            lines.append(f"CREATE_FOLDER {action['destination']}")
        elif verb in ("MOVE_FILE", "RENAME_FILE"):
            lines.append(
                f"{verb} {action['source']} {action['destination']}")
        elif verb == "QUARANTINE_FILE":
            lines.append(f"QUARANTINE_FILE {action['source']}")
        elif verb == "LIST_FILES":
            lines.append(f"LIST_FILES {action['destination']}")
    return "\n".join(lines) + "\n"


def execute_actions(actions, base_path, approved_ids=None):
    """Execute approved actions only. Returns an execution record.

    approved_ids: set of action ids to run. None means run all actions.
    The record contains every move made (original path and new path)
    so rollback can restore it. LIST_FILES only lists, it changes
    nothing. Nothing is ever deleted.
    """
    base = Path(base_path).resolve()
    execution_id = str(uuid.uuid4())
    executed = []
    skipped = []
    errors = []
    moves = []
    for action in actions:
        if approved_ids is not None and action["id"] not in approved_ids:
            skipped.append(action["id"])
            continue
        verb = action["verb"]
        try:
            if verb == "CREATE_FOLDER":
                dest = _resolve_under_base(action["destination"], base)
                dest.mkdir(parents=True, exist_ok=True)
            elif verb in ("MOVE_FILE", "RENAME_FILE", "QUARANTINE_FILE"):
                src = _resolve_under_base(action["source"], base)
                dest = _resolve_under_base(action["destination"], base)
                if not src.is_file():
                    raise DSLError(f"Source file not found: {src}")
                dest.parent.mkdir(parents=True, exist_ok=True)
                if dest.exists():
                    raise DSLError(f"Destination already exists: {dest}")
                src.rename(dest)
                moves.append({"action_id": action["id"], "verb": verb,
                              "original_path": str(src),
                              "new_path": str(dest)})
            elif verb == "LIST_FILES":
                target = _resolve_under_base(action["destination"], base)
                if target.is_dir():
                    _ = sorted(p.name for p in target.iterdir())
            executed.append(action["id"])
        except (DSLError, OSError) as exc:
            errors.append({"action_id": action["id"], "error": str(exc)})
    return {"execution_id": execution_id, "executed": executed,
            "skipped": skipped, "errors": errors, "moves": moves,
            "base_path": str(base)}


def rollback_moves(execution, base_path=None):
    """Undo the moves in an execution record, newest first.

    Returns {"restored": [...], "errors": [...]}. Files are moved back
    to their original paths. Nothing is deleted.
    """
    restored = []
    errors = []
    for move in reversed(execution.get("moves", [])):
        src = Path(move["new_path"])
        dest = Path(move["original_path"])
        try:
            if not src.is_file():
                errors.append({"action_id": move["action_id"],
                               "error": f"File no longer at {src}"})
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                errors.append({"action_id": move["action_id"],
                               "error": f"Original path already exists: {dest}"})
                continue
            src.rename(dest)
            restored.append(move["action_id"])
        except OSError as exc:
            errors.append({"action_id": move["action_id"], "error": str(exc)})
    return {"restored": restored, "errors": errors}
