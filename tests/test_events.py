import json
import pytest
from pathlib import Path
from api.events import EventFeedReader, sanitize_query
from api.config import settings

def test_sanitize_query():
    assert sanitize_query(None) is None
    clean = sanitize_query("username=admin&password=secret123&action=login")
    assert "password=[REDACTED]" in clean
    assert "username=admin" in clean

    clean_token = sanitize_query("token=eyJh.bc.xyz&user=alice")
    assert "token=[REDACTED]" in clean_token

def test_event_feed_reader_ingestion(tmp_path: Path):
    log_file = tmp_path / "access.log"
    reader = EventFeedReader(log_path=log_file)

    # 1. Non-existent file handles gracefully
    assert reader.process_new_events() == 0

    # 2. Append valid JSON log entries
    entries = [
        {
            "time": "2026-10-16T15:00:00+00:00",
            "remote_addr": "127.0.0.1",
            "method": "POST",
            "path": "/login",
            "query": "username=alice",
            "status": 200,
            "rule_id": "-"
        },
        {
            "time": "2026-10-16T15:00:05+00:00",
            "remote_addr": "192.168.1.50",
            "method": "POST",
            "path": "/login",
            "query": "username=' OR 1=1 --",
            "status": 403,
            "rule_id": "F-001"
        }
    ]

    with open(log_file, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    count = reader.process_new_events()
    assert count == 2

    # Calling again without new data returns 0
    assert reader.process_new_events() == 0

    # 3. Append another entry
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "time": "2026-10-16T15:00:10+00:00",
            "method": "GET",
            "path": "/comment",
            "status": 200
        }) + "\n")

    count = reader.process_new_events()
    assert count == 1
