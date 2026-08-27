"""Task tree persistence — the engagement state must survive a restart and a rescan.

Uses a temp directory (never the real data/engagements) by pointing the module's
storage dir at tmp_path, so the test is hermetic.
"""
import silentpivot.tasktree as tasktree_mod
from silentpivot.tasktree import DONE, TaskTree


def _fresh_dir(tmp_path, monkeypatch):
    d = tmp_path / "engagements"
    monkeypatch.setattr(tasktree_mod, "ENGAGEMENTS_DIR", str(d))
    return d


_FINDING = {"template_id": "CVE-X", "name": "Test Finding",
            "severity": "CRITICAL", "matched_at": "h:1"}


def test_lead_created_and_persists_across_reload(tmp_path, monkeypatch):
    _fresh_dir(tmp_path, monkeypatch)
    t = TaskTree("target-a")
    t.ingest(nuclei=[_FINDING])
    assert len(t.leads) == 1
    t.save()
    lead_id = next(iter(t.leads))
    t.set_status(lead_id, DONE, note="tested")   # persists on its own

    # Reload fresh — simulates closing and reopening the tool.
    t2 = TaskTree("target-a")
    assert t2.leads.get(lead_id, {}).get("status") == DONE


def test_rescan_is_idempotent_and_keeps_done(tmp_path, monkeypatch):
    _fresh_dir(tmp_path, monkeypatch)
    t = TaskTree("target-b")
    t.ingest(nuclei=[_FINDING])
    lead_id = next(iter(t.leads))
    t.set_status(lead_id, DONE)

    t.ingest(nuclei=[_FINDING])   # same finding again
    assert len(t.leads) == 1                      # no duplicate
    assert t.leads[lead_id]["status"] == DONE     # not reopened


def test_slug_is_path_traversal_safe(tmp_path, monkeypatch):
    import os
    d = _fresh_dir(tmp_path, monkeypatch)
    # A traversal-style target must resolve to a file INSIDE the engagements dir.
    t = TaskTree("../../etc/passwd")
    resolved = os.path.realpath(t.path)
    assert resolved.startswith(os.path.realpath(str(d)) + os.sep)
    assert "/" not in tasktree_mod._slug("../../etc/passwd")
    assert "\\" not in tasktree_mod._slug("..\\..\\etc")


def test_ingest_survives_malformed_input(tmp_path, monkeypatch):
    _fresh_dir(tmp_path, monkeypatch)
    t = TaskTree("target-c")
    # None / missing keys / wrong types must not raise
    t.ingest(findings=[{}], nuclei=[{}], web=[{}], subdomains=[{}],
             leak={"secrets": [{}], "exposed": [{}]}, vulns=[{}], content=[{}])
    t.ingest()  # everything None
