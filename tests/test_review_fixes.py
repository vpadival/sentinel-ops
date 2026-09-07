import json
from unittest.mock import patch

import httpx
import pytest

from backend.core.job_store import JobStore
from backend.core.llm import clean_json, call_llm_json
from backend.core.state import JobStatus
from backend.adapters.sentinel import start_agent_workflow, poll_until_complete


def test_queue_requires_key_without_consuming_alert(monkeypatch):
    from fastapi.testclient import TestClient
    from backend.api.app import app
    from backend.api.routes import _alert_queue
    monkeypatch.setenv("SENTINEL_API_KEY", "secret")
    _alert_queue.clear()
    _alert_queue.append("Alert awaiting investigation")
    client = TestClient(app)
    assert client.get("/api/v1/queue").status_code == 401
    response = client.get("/api/v1/queue", headers={"X-API-Key": "secret"})
    assert response.json()["alert"] == "Alert awaiting investigation"


def test_update_isolates_nested_values():
    store = JobStore()
    store.create("job", {"messages": []})
    update = {"messages": [{"content": "original"}]}
    store.update("job", update)
    update["messages"][0]["content"] = "changed"
    assert store.get("job")["messages"][0]["content"] == "original"


def test_json_cleanup_preserves_string_contents():
    raw = '{"payload": "a,} b,] \\\"c,}\\\"", "items": [1,],}'
    assert json.loads(clean_json(raw)) == {
        "payload": 'a,} b,] "c,}"', "items": [1],
    }


@pytest.mark.parametrize("invalid", ["null", "[]", "42", '"text"'])
def test_json_non_object_retries(invalid):
    with patch("backend.core.llm.call_llm", side_effect=[invalid, '{"ok": true}']) as call:
        assert call_llm_json("system", "user") == {"ok": True}
        assert call.call_count == 2


def test_empty_workflow_stays_failed():
    job_id = start_agent_workflow(" \x00 ")
    result = poll_until_complete(job_id, timeout_seconds=5, poll_interval=0.01)
    assert result["job_status"] == JobStatus.FAILED
    assert "Empty" in result["error"]
    assert "fact_sheet" not in result


def test_monitor_retries_failed_alert_and_sends_key(monkeypatch):
    import monitor
    monkeypatch.setattr(monitor, "submitted_alerts", set())
    monkeypatch.setenv("SENTINEL_API_KEY", "test-secret")
    with patch("monitor.httpx.post", side_effect=[
        httpx.ReadTimeout("timeout"), httpx.Response(202),
    ]) as post:
        monitor.submit_to_sentinel("Test suspicious alert", "alert")
        monitor.submit_to_sentinel("Test suspicious alert", "alert")
        monitor.submit_to_sentinel("Test suspicious alert", "alert")
    assert post.call_count == 2
    assert post.call_args.kwargs["headers"]["X-API-Key"] == "test-secret"


def test_proxy_preserves_bytes_headers_and_inspects_query(monkeypatch):
    import monitor
    from flask import Flask
    apps = []
    monkeypatch.setattr(Flask, "run", lambda self, **kwargs: apps.append(self))
    monitor.run_proxy("http://upstream", 9000)
    upstream = httpx.Response(200, content=b"decoded", headers=[
        ("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"),
    ])
    # httpx has already decoded the body when the proxy reads .content.
    upstream.headers["Content-Encoding"] = "gzip"
    with patch("monitor.httpx.request", return_value=upstream) as forward:
        with patch("monitor.analyze_request") as analyze:
            response = apps[0].test_client().post(
                "/search?q=UNION%20SELECT", data=b"\xff\x00\x80",
            )
    assert "UNION SELECT" in analyze.call_args.kwargs["path"]
    assert forward.call_args.kwargs["content"] == b"\xff\x00\x80"
    assert forward.call_args.kwargs["follow_redirects"] is False
    assert response.data == b"decoded"
    assert "Content-Encoding" not in response.headers
    assert response.headers.getlist("Set-Cookie") == ["a=1", "b=2"]


def test_proxy_counts_only_failed_authentication(monkeypatch):
    import monitor
    from collections import defaultdict
    from flask import Flask
    apps = []
    monkeypatch.setattr(Flask, "run", lambda self, **kwargs: apps.append(self))
    monkeypatch.setattr(monitor, "failed_auth", defaultdict(int))
    monitor.run_proxy("http://upstream", 9000)
    client = apps[0].test_client()
    with patch("monitor.httpx.request", return_value=httpx.Response(200)):
        for _ in range(5):
            client.post("/login")
    assert not monitor.failed_auth
    with patch("monitor.httpx.request", return_value=httpx.Response(401)):
        with patch("monitor.submit_to_sentinel") as submit:
            for _ in range(5):
                client.post("/login")
    assert monitor.failed_auth["127.0.0.1"] == 5
    assert submit.call_count == 1
