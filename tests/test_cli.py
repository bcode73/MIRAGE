"""Tests for the main.py CLI orchestrator."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from src.main import main

from conftest import make_profile_dict


@pytest.fixture
def profile_file(tmp_path):
    data = make_profile_dict(
        allowed_hosts=["*"],
        techniques=["T1070.006"],
        dry_run_default=False,
        scope={"allowed_paths": [f"{tmp_path}/*"], "allowed_registry_keys": []},
    )
    p = tmp_path / "engagement.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


@pytest.fixture
def target_file(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text("payload", encoding="utf-8")
    return f


def _mtime_year(path) -> int:
    import os

    return datetime.fromtimestamp(os.stat(path).st_mtime, tz=timezone.utc).year


def test_backdate_then_revert(tmp_path, profile_file, target_file):
    journal = tmp_path / "run.jsonl"
    import os

    original_year = _mtime_year(target_file)

    rc = main(["timestomp", "backdate", "--profile", str(profile_file),
               "--journal", str(journal), str(target_file), "2020-01-15"])
    assert rc == 0
    assert _mtime_year(target_file) == 2020
    assert journal.exists()

    rc = main(["revert", "--profile", str(profile_file), "--journal", str(journal)])
    assert rc == 0
    assert _mtime_year(target_file) == original_year


def test_dry_run_does_not_change_file(tmp_path, profile_file, target_file):
    journal = tmp_path / "run.jsonl"
    original_year = _mtime_year(target_file)
    rc = main(["timestomp", "backdate", "--profile", str(profile_file),
               "--journal", str(journal), str(target_file), "2001-09-11", "--dry-run"])
    assert rc == 0
    assert _mtime_year(target_file) == original_year  # unchanged


def test_out_of_scope_returns_error(tmp_path, profile_file):
    # A file outside the tmp scope must be refused (exit 2).
    outside = tmp_path.parent / "outside_cli.txt"
    outside.write_text("x", encoding="utf-8")
    journal = tmp_path / "run.jsonl"
    try:
        rc = main(["timestomp", "backdate", "--profile", str(profile_file),
                   "--journal", str(journal), str(outside), "2020-01-01"])
        assert rc == 2
    finally:
        outside.unlink()


def test_report_writes_files(tmp_path, profile_file, target_file):
    journal = tmp_path / "run.jsonl"
    main(["timestomp", "backdate", "--profile", str(profile_file),
          "--journal", str(journal), str(target_file), "2020-01-15"])
    out = tmp_path / "out"
    rc = main(["report", "--journal", str(journal), "--profile", str(profile_file), "--out", str(out)])
    assert rc == 0
    assert (out / "mirage-report.json").exists()
    assert (out / "mirage-report.md").exists()
    assert (out / "mirage-report.navigator.json").exists()


def test_verify_ok(tmp_path, profile_file, target_file):
    journal = tmp_path / "run.jsonl"
    main(["timestomp", "backdate", "--profile", str(profile_file),
          "--journal", str(journal), str(target_file), "2020-01-15"])
    rc = main(["verify", "--journal", str(journal)])
    assert rc == 0


def test_missing_profile_errors(tmp_path, target_file):
    journal = tmp_path / "run.jsonl"
    rc = main(["timestomp", "backdate", "--journal", str(journal), str(target_file), "2020-01-15"])
    assert rc == 2  # ConfigError: --profile required


def test_info(tmp_path, profile_file):
    rc = main(["info", "--profile", str(profile_file)])
    assert rc == 0
