"""
planner_demo.py - Deterministic demo planner for SafeSort.

This is the clearly labeled demo fallback. It uses only the scanner
results, no LLM, and it returns the SAME plan shape as the live
planner: a DSL string plus one action dict per action, each with a
rationale and a risk level.

Rules:
  - High or Critical risk files are quarantined, never organized.
  - Everything else goes to a folder by category: Finance, Research,
    Images, Code, Archives, Documents, or Other.
  - Every file in the inventory is covered exactly once.
  - CREATE_FOLDER actions come first, then the file actions, then a
    final LIST_FILES for the base folder.
"""

from pathlib import Path

from dsl import actions_to_dsl

CATEGORY_FOLDERS = {
    "Finance": ("invoice", "budget", "receipt", "tax", "bank", "payroll"),
    "Research": ("research", "paper", "thesis", "study", "journal"),
}


def category_for(item):
    """Pick a destination folder for a clean file."""
    name = item["name"].lower()
    for folder, keywords in CATEGORY_FOLDERS.items():
        if any(word in name for word in keywords):
            return folder
    ext = item["extension"]
    if ext in (".jpg", ".jpeg", ".png", ".gif", ".webp"):
        return "Images"
    if ext in (".py", ".js", ".ts", ".java", ".c", ".cpp", ".html", ".css"):
        return "Code"
    if ext in (".zip", ".tar", ".gz", ".7z"):
        return "Archives"
    if ext in (".pdf", ".txt", ".md", ".csv", ".doc", ".docx", ".xls",
               ".xlsx"):
        return "Documents"
    return "Other"


def plan_from_inventory(inventory, base_path, instruction=""):
    """Build a plan dict from scanner inventory. Deterministic."""
    base = Path(base_path).resolve()
    actions = []
    folders_needed = []
    file_actions = []

    for item in inventory:
        risk = item["risk"]
        if risk in ("High", "Critical"):
            reason = "; ".join(item["reasons"]) or f"Risk is {risk}."
            file_actions.append({
                "id": "", "verb": "QUARANTINE_FILE",
                "source": item["path"],
                "destination": str(base / "Quarantine" / item["name"]),
                "file": item["name"], "risk": risk,
                "reason": reason,
                "rationale": f"Quarantine {item['name']}: {reason} "
                             "I do not organize risky files with clean ones.",
            })
            if "Quarantine" not in folders_needed:
                folders_needed.append("Quarantine")
        else:
            folder = category_for(item)
            reason = "; ".join(item["reasons"]) or "No risk flags found."
            file_actions.append({
                "id": "", "verb": "MOVE_FILE",
                "source": item["path"],
                "destination": str(base / folder / item["name"]),
                "file": item["name"], "risk": risk,
                "reason": reason,
                "rationale": f"Move {item['name']} to {folder}/ by type "
                             f"and name. Risk is {risk}.",
            })
            if folder not in folders_needed:
                folders_needed.append(folder)

    for folder in folders_needed:
        actions.append({
            "id": "", "verb": "CREATE_FOLDER",
            "source": None, "destination": str(base / folder),
            "file": None, "risk": "Low",
            "reason": "Folder needed for the plan.",
            "rationale": f"Create the {folder} folder.",
        })
    actions.extend(file_actions)
    actions.append({
        "id": "", "verb": "LIST_FILES", "source": None,
        "destination": str(base), "file": None, "risk": "Low",
        "reason": "Verify the result after the moves.",
        "rationale": "List the base folder to verify the result.",
    })

    for index, action in enumerate(actions, start=1):
        action["id"] = f"a{index}"

    dsl_text = actions_to_dsl(actions)
    summary = (
        f"Demo plan for {len(inventory)} file(s)"
        + (f" ({instruction.strip()})" if instruction and instruction.strip()
           else "")
        + ". Risky files go to Quarantine. Clean files go to folders by "
          "type and name."
    )
    return {"dsl": dsl_text, "actions": actions, "summary": summary,
            "mode": "demo"}
