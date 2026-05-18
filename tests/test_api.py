"""Integration tests for FastAPI endpoints using in-memory DuckDB."""

import pytest
from fastapi.testclient import TestClient

import backend.db as db_module
from backend.db import _init_schema

START = "2026-01-01T00:00:00+00:00"
END = "2026-12-31T23:59:59+00:00"


@pytest.fixture()
def client(monkeypatch, tmp_path):
    import duckdb

    conn = duckdb.connect(":memory:")
    _init_schema(conn)
    monkeypatch.setattr(db_module, "_conn", conn)

    conn.executemany(
        """INSERT INTO logs
           (id, index, tenant, ts, severity, host, user_name, event_type, src_ip, dst_ip, raw)
           VALUES (?, ?, ?, TIMESTAMPTZ '2026-01-01 10:00:00+00', ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                "1",
                "adr",
                "t1",
                "critical",
                "host-a",
                "alice",
                "malware",
                "1.1.1.1",
                None,
                '{"msg":"a"}',
            ),
        ],
    )
    conn.executemany(
        """INSERT INTO logs
           (id, index, tenant, ts, severity, host, user_name, event_type, src_ip, dst_ip, raw)
           VALUES (?, ?, ?, TIMESTAMPTZ '2026-01-01 11:00:00+00', ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                "2",
                "adr",
                "t1",
                "high",
                "host-b",
                "bob",
                "bruteforce",
                "2.2.2.2",
                None,
                '{"msg":"b"}',
            ),
        ],
    )
    conn.executemany(
        """INSERT INTO logs
           (id, index, tenant, ts, severity, host, user_name, event_type, src_ip, dst_ip, raw)
           VALUES (?, ?, ?, TIMESTAMPTZ '2026-01-01 12:00:00+00', ?, ?, ?, ?, ?, ?, ?)""",
        [
            ("3", "syslog", "t1", None, "host-c", None, "login", None, None, '{"msg":"c"}'),
        ],
    )
    conn.executemany(
        """INSERT INTO logs
           (id, index, tenant, ts, severity, host, user_name, event_type, src_ip, dst_ip, raw)
           VALUES (?, ?, ?, TIMESTAMPTZ '2026-01-01 13:00:00+00', ?, ?, ?, ?, ?, ?, ?)""",
        [
            ("4", "wineventlog", "t1", "low", "host-a", "alice", "4624", None, None, '{"msg":"d"}'),
        ],
    )

    from backend.main import app

    return TestClient(app)


class TestOverview:
    def test_returns_counts(self, client):
        resp = client.get("/api/kpis/overview", params={"start": START, "end": END})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_events"] == 4
        assert data["critical_high_alerts"] == 2
        assert data["unique_hosts"] == 3
        assert "adr" in data["by_index"]

    def test_filters_by_time_range(self, client):
        resp = client.get("/api/kpis/overview", params={"start": "2030-01-01", "end": "2030-12-31"})
        assert resp.status_code == 200
        assert resp.json()["total_events"] == 0


class TestAlertsTimeline:
    def test_returns_list(self, client):
        resp = client.get("/api/kpis/alerts/timeline", params={"start": START, "end": END})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        severities = {r["severity"] for r in data}
        assert "critical" in severities

    def test_granularity_day(self, client):
        resp = client.get(
            "/api/kpis/alerts/timeline", params={"granularity": "day", "start": START, "end": END}
        )
        assert resp.status_code == 200


class TestTopThreats:
    def test_returns_threats(self, client):
        resp = client.get("/api/kpis/alerts/top-threats", params={"start": START, "end": END})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        threats = [r["threat"] for r in data]
        assert "malware" in threats or "bruteforce" in threats


class TestSyslogVolume:
    def test_returns_structure(self, client):
        resp = client.get("/api/kpis/syslog/volume", params={"start": START, "end": END})
        assert resp.status_code == 200
        data = resp.json()
        assert "by_host" in data
        assert "by_event_type" in data
        assert "timeline" in data
        hosts = [r["host"] for r in data["by_host"]]
        assert "host-c" in hosts or "host-a" in hosts


class TestUsersActivity:
    def test_returns_users(self, client):
        resp = client.get("/api/kpis/users/activity", params={"start": START, "end": END})
        assert resp.status_code == 200
        data = resp.json()
        assert "top_users" in data
        users = [r["user"] for r in data["top_users"]]
        assert "alice" in users


class TestLogBrowse:
    def test_returns_paginated(self, client):
        resp = client.get(
            "/api/logs/browse", params={"page": 1, "page_size": 10, "start": START, "end": END}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 4
        assert len(data["items"]) == 4
        assert data["pages"] == 1

    def test_filter_by_index(self, client):
        resp = client.get("/api/logs/browse", params={"index": "adr", "start": START, "end": END})
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_filter_by_severity(self, client):
        resp = client.get(
            "/api/logs/browse", params={"severity": "critical", "start": START, "end": END}
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_filter_by_host(self, client):
        resp = client.get("/api/logs/browse", params={"host": "host-a", "start": START, "end": END})
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_search_text(self, client):
        resp = client.get(
            "/api/logs/browse", params={"search": "alice", "start": START, "end": END}
        )
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    def test_raw_field_returned(self, client):
        resp = client.get("/api/logs/browse", params={"start": START, "end": END})
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) > 0
        assert isinstance(items[0]["raw"], dict)


class TestLogIndexes:
    def test_returns_indexes(self, client):
        resp = client.get("/api/logs/indexes")
        assert resp.status_code == 200
        data = resp.json()
        assert "adr" in data
        assert "syslog" in data


class TestConfig:
    def test_get_config(self, client):
        resp = client.get("/api/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "s3_endpoint" in data
        assert "org_id" in data

    def test_update_config(self, client, tmp_path, monkeypatch):
        import backend.config as cfg_module

        fake_yaml = tmp_path / "config.yaml"
        fake_yaml.write_text("org_id: original\n")
        monkeypatch.setattr(cfg_module, "CONFIG_FILE", fake_yaml)

        resp = client.put("/api/config", json={"org_id": "new-org"})
        assert resp.status_code == 200
        assert "org_id" in resp.json()["updated"]


class TestIngestStatus:
    def test_status_endpoint(self, client):
        resp = client.get("/api/ingest/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "running" in data
        assert "sync_status" in data
