"""Tests for the log loader: field extraction and .gz parsing."""

import gzip
import json
from pathlib import Path

import pytest

from backend.services.loader import (
    _extract_index_from_path,
    _extract_tenant_from_path,
    _parse_ts,
    _pick,
)


class TestPick:
    def test_returns_first_match(self):
        doc = {"hostname": "server1", "host": "server2"}
        assert _pick(doc, ["hostname", "host"]) == "server1"

    def test_returns_none_when_no_match(self):
        assert _pick({}, ["foo", "bar"]) is None

    def test_truncates_long_values(self):
        doc = {"host": "x" * 1000}
        result = _pick(doc, ["host"])
        assert result is not None
        assert len(result) <= 512

    def test_converts_to_string(self):
        doc = {"EventID": 4624}
        assert _pick(doc, ["EventID"]) == "4624"


class TestParseTs:
    def test_iso_string(self):
        ts = _parse_ts("2026-01-01T00:00:00Z")
        assert ts is not None
        assert ts.year == 2026

    def test_epoch_millis(self):
        ts = _parse_ts("1735689600000")  # 2025-01-01 00:00:00 UTC
        assert ts is not None
        assert ts.year == 2025

    def test_epoch_seconds(self):
        ts = _parse_ts("1735689600")  # 2025-01-01 00:00:00 UTC
        assert ts is not None
        assert ts.year == 2025

    def test_none_input(self):
        assert _parse_ts(None) is None

    def test_invalid_returns_none(self):
        assert _parse_ts("not-a-date") is None


class TestPathExtraction:
    def test_extract_index_from_path(self):
        p = Path("/data/organization=abc/index=adr/tenant=xyz/2026/file.gz")
        assert _extract_index_from_path(p) == "adr"

    def test_extract_index_unknown(self):
        p = Path("/data/some/other/path/file.gz")
        assert _extract_index_from_path(p) == "unknown"

    def test_extract_tenant(self):
        p = Path("/data/index=adr/tenant=df66914f9f254b2a9f673a5a04a6c8f5/file.gz")
        assert _extract_tenant_from_path(p) == "df66914f9f254b2a9f673a5a04a6c8f5"

    def test_extract_tenant_missing(self):
        p = Path("/data/index=adr/file.gz")
        assert _extract_tenant_from_path(p) == ""


class TestLoadFile:
    def _make_gz(self, tmp_path: Path, records: list[dict], name: str = "test.gz") -> Path:
        gz_path = tmp_path / "index=adr" / "tenant=test" / name
        gz_path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(gz_path, "wt") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        return gz_path

    def test_load_file_inserts_rows(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        import duckdb

        import backend.db as db_module
        import backend.services.loader as loader_module

        conn = duckdb.connect(":memory:")
        db_module._init_schema(conn)
        monkeypatch.setattr(db_module, "_conn", conn)
        monkeypatch.setattr(loader_module, "get_conn", lambda: conn)

        records = [
            {
                "@timestamp": "2026-01-01T00:00:00Z",
                "hostname": "host1",
                "severity": "high",
                "event_type": "alert",
            },
            {"@timestamp": "2026-01-01T01:00:00Z", "hostname": "host2", "severity": "low"},
        ]
        gz_path = self._make_gz(tmp_path, records)

        from backend.services.loader import load_file

        count = load_file(gz_path)
        assert count == 2

        rows = conn.execute("SELECT count(*) FROM logs").fetchone()[0]
        assert rows == 2

    def test_load_file_skips_already_ingested(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        import duckdb

        import backend.db as db_module
        import backend.services.loader as loader_module

        conn = duckdb.connect(":memory:")
        db_module._init_schema(conn)
        monkeypatch.setattr(db_module, "_conn", conn)
        monkeypatch.setattr(loader_module, "get_conn", lambda: conn)

        records = [{"@timestamp": "2026-01-01T00:00:00Z", "hostname": "host1"}]
        gz_path = self._make_gz(tmp_path, records, name="once.gz")

        from backend.services.loader import load_file

        count1 = load_file(gz_path)
        count2 = load_file(gz_path)
        assert count1 == 1
        assert count2 == 0

    def test_load_file_handles_invalid_json_lines(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        import duckdb

        import backend.db as db_module
        import backend.services.loader as loader_module

        conn = duckdb.connect(":memory:")
        db_module._init_schema(conn)
        monkeypatch.setattr(db_module, "_conn", conn)
        monkeypatch.setattr(loader_module, "get_conn", lambda: conn)

        gz_path = tmp_path / "index=syslog" / "bad.gz"
        gz_path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(gz_path, "wt") as f:
            f.write("not json\n")
            f.write(json.dumps({"@timestamp": "2026-01-01T00:00:00Z", "hostname": "ok"}) + "\n")

        from backend.services.loader import load_file

        count = load_file(gz_path)
        assert count == 1
