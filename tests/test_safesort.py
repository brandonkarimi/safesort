"""Tests for SafeSort. Run: python -m pytest tests/ -v

All tests use tmp_path copies. They never touch the bundled
demo_folder, and they never use a live LLM or the network.
"""

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from dsl import (DSLError, check_coverage, execute_actions, parse_dsl,
                 rollback_moves)
from planner_demo import plan_from_inventory
from scanner import assess_file, scan_folder

DEMO = Path(__file__).parent.parent / "demo_folder"


@pytest.fixture()
def demo_copy(tmp_path):
    dest = tmp_path / "demo"
    shutil.copytree(DEMO, dest)
    return dest


# ----------------------------------------------------------------------
# DSL validator
# ----------------------------------------------------------------------

def test_validator_rejects_dotdot(tmp_path):
    base = tmp_path
    with pytest.raises(DSLError, match=r"\.\."):
        parse_dsl(f"MOVE_FILE {base}/a.txt {base}/../outside.txt", base)


def test_validator_rejects_path_outside_base(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    with pytest.raises(DSLError, match="outside the base folder"):
        parse_dsl(f"CREATE_FOLDER /etc/evil", base)


def test_validator_rejects_relative_path(tmp_path):
    base = tmp_path
    with pytest.raises(DSLError, match="absolute"):
        parse_dsl("CREATE_FOLDER relative/folder", base)


def test_validator_rejects_delete_verb(tmp_path):
    base = tmp_path
    with pytest.raises(DSLError, match="forbidden"):
        parse_dsl(f"DELETE {base}/a.txt", base)
    with pytest.raises(DSLError, match="forbidden"):
        parse_dsl(f"REMOVE_FILE {base}/a.txt", base)


def test_validator_rejects_unknown_verb(tmp_path):
    base = tmp_path
    with pytest.raises(DSLError, match="unknown verb"):
        parse_dsl(f"SHRED {base}/a.txt", base)


def test_validator_rejects_symlink_escape(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("x")
    link = base / "link"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(DSLError, match="outside the base folder"):
        parse_dsl(f"LIST_FILES {base}/link", base)


def test_validator_accepts_valid_dsl(tmp_path):
    base = tmp_path
    actions = parse_dsl(
        f"CREATE_FOLDER {base}/Finance\n"
        f"MOVE_FILE {base}/a.txt {base}/Finance/a.txt\n"
        f"LIST_FILES {base}\n", base)
    assert [a["verb"] for a in actions] == [
        "CREATE_FOLDER", "MOVE_FILE", "LIST_FILES"]


def test_quarantine_destination_is_under_base(tmp_path):
    base = tmp_path
    actions = parse_dsl(f"QUARANTINE_FILE {base}/bad.pdf", base)
    assert actions[0]["destination"] == str(base / "Quarantine" / "bad.pdf")


# ----------------------------------------------------------------------
# Executor + rollback
# ----------------------------------------------------------------------

def test_executor_moves_and_rollback_restores(tmp_path):
    base = tmp_path
    (base / "a.txt").write_text("hello")
    actions = parse_dsl(
        f"CREATE_FOLDER {base}/Documents\n"
        f"MOVE_FILE {base}/a.txt {base}/Documents/a.txt\n", base)
    result = execute_actions(actions, base)
    assert result["errors"] == []
    assert (base / "Documents" / "a.txt").read_text() == "hello"
    assert not (base / "a.txt").exists()
    rolled = rollback_moves(result)
    assert rolled["errors"] == []
    assert (base / "a.txt").read_text() == "hello"
    assert not (base / "Documents" / "a.txt").exists()


def test_executor_runs_only_approved_actions(tmp_path):
    base = tmp_path
    (base / "a.txt").write_text("a")
    (base / "b.txt").write_text("b")
    actions = parse_dsl(
        f"MOVE_FILE {base}/a.txt {base}/A/a.txt\n"
        f"MOVE_FILE {base}/b.txt {base}/B/b.txt\n", base)
    result = execute_actions(actions, base, approved_ids={"a1"})
    assert (base / "A" / "a.txt").exists()
    assert (base / "b.txt").exists()
    assert result["skipped"] == ["a2"]


def test_executor_never_deletes(tmp_path):
    base = tmp_path
    (base / "a.txt").write_text("a")
    actions = parse_dsl(f"LIST_FILES {base}\n", base)
    result = execute_actions(actions, base)
    assert result["errors"] == []
    assert (base / "a.txt").exists()


# ----------------------------------------------------------------------
# Demo planner
# ----------------------------------------------------------------------

def test_demo_planner_quarantines_suspicious_and_covers_every_file(demo_copy):
    inventory = scan_folder(demo_copy)
    assert len(inventory) == 10
    plan = plan_from_inventory(inventory, demo_copy)
    assert plan["mode"] == "demo"
    actions = parse_dsl(plan["dsl"], demo_copy)
    check_coverage(actions, inventory)
    by_file = {a["file"]: a for a in plan["actions"] if a.get("file")}
    assert by_file["suspicious.pdf"]["verb"] == "QUARANTINE_FILE"
    assert by_file["credentials.txt"]["verb"] == "QUARANTINE_FILE"
    assert by_file["invoice.pdf"]["verb"] == "MOVE_FILE"
    assert by_file["invoice.pdf"]["destination"].endswith(
        "Finance/invoice.pdf")
    assert by_file["research-paper.pdf"]["destination"].endswith(
        "Research/research-paper.pdf")
    # Every file covered exactly once.
    covered = [a["source"] for a in actions
               if a["verb"] in ("MOVE_FILE", "RENAME_FILE", "QUARANTINE_FILE")]
    assert sorted(covered) == sorted(item["path"] for item in inventory)


def test_demo_planner_end_to_end_on_copy(demo_copy):
    inventory = scan_folder(demo_copy)
    plan = plan_from_inventory(inventory, demo_copy)
    actions = parse_dsl(plan["dsl"], demo_copy)
    result = execute_actions(actions, demo_copy)
    assert result["errors"] == []
    assert (demo_copy / "Quarantine" / "suspicious.pdf").exists()
    assert (demo_copy / "Quarantine" / "credentials.txt").exists()
    assert (demo_copy / "Finance" / "invoice.pdf").exists()
    assert (demo_copy / "Finance" / "budget.csv").exists()
    assert (demo_copy / "Research" / "research-paper.pdf").exists()
    assert (demo_copy / "Images" / "photo.jpg").exists()
    assert (demo_copy / "Code" / "script.py").exists()
    assert (demo_copy / "Archives" / "archive.zip").exists()
    rolled = rollback_moves(result)
    assert rolled["errors"] == []
    assert (demo_copy / "suspicious.pdf").exists()
    assert (demo_copy / "invoice.pdf").exists()
    assert not (demo_copy / "Quarantine" / "suspicious.pdf").exists()


# ----------------------------------------------------------------------
# Scanner
# ----------------------------------------------------------------------

def test_scanner_flags_secret_in_text(tmp_path):
    target = tmp_path / "creds.txt"
    target.write_text("username: demo\npassword= FakePass123!\n")
    risk, reasons = assess_file(target)
    assert risk == "High"
    assert any("Secret pattern" in r for r in reasons)


def test_scanner_flags_suspicious_pdf(tmp_path):
    target = tmp_path / "bad.pdf"
    target.write_text("%PDF-1.4\n/JavaScript app.alert('x')\n"
                      "sk-FAKE1234567890EXAMPLE\n")
    risk, reasons = assess_file(target)
    assert risk == "Critical"
    assert any("JavaScript" in r for r in reasons)


def test_scanner_flags_double_extension(tmp_path):
    target = tmp_path / "invoice.pdf.exe"
    target.write_bytes(b"MZ fake")
    risk, reasons = assess_file(target)
    assert risk == "High"
    assert any("Double extension" in r for r in reasons)


def test_scanner_clean_file_is_low(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("Buy milk. Finish the demo video.\n")
    risk, _reasons = assess_file(target)
    assert risk == "Low"


def test_scanner_demo_folder_flags(tmp_path):
    inventory = scan_folder(DEMO)
    by_name = {item["name"]: item for item in inventory}
    assert by_name["suspicious.pdf"]["risk"] == "Critical"
    assert by_name["credentials.txt"]["risk"] == "High"
    assert by_name["invoice.pdf"]["risk"] == "Low"
