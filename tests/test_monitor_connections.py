from unittest.mock import MagicMock, patch

import httpx
import pytest
from flask import Flask

import monitor


def test_rejects_proxy_pointing_to_itself():
    with pytest.raises(ValueError, match="request loop"):
        monitor.run_proxy("http://localhost:9000", 9000)


def test_simulator_reports_connection_failure_and_uses_selected_port():
    client = MagicMock()
    client.request.side_effect = httpx.ConnectError("connection refused")
    with patch("monitor.httpx.Client") as factory, patch("monitor.log") as log:
        factory.return_value.__enter__.return_value = client
        monitor.run_simulator(interval=0, port=9010)
    assert client.request.call_args.args[1] == "http://localhost:9010/"
    assert client.request.call_count == 1
    assert any("Cannot connect to proxy" in call.args[0] for call in log.call_args_list)
    factory.return_value.__exit__.assert_called_once()


def test_proxy_recovers_after_target_connection_failure(monkeypatch: pytest.MonkeyPatch):
    apps: list[Flask] = []
    monkeypatch.setattr(Flask, "run", lambda self, **kwargs: apps.append(self))
    monitor.run_proxy("http://localhost:8000", 9000)
    client = apps[0].test_client()
    with patch("monitor.analyze_request"), patch("monitor.log") as log:
        with patch("monitor.httpx.request", side_effect=[
            httpx.ConnectError("connection refused"),
            httpx.Response(200, content=b"target restored"),
        ]):
            assert client.get("/").status_code == 502
            restored = client.get("/")
    assert restored.status_code == 200
    assert restored.data == b"target restored"
    assert any("ConnectError" in call.args[0] for call in log.call_args_list)


def test_proxy_forwards_dashboard_static_assets(monkeypatch: pytest.MonkeyPatch):
    apps: list[Flask] = []
    monkeypatch.setattr(Flask, "run", lambda self, **kwargs: apps.append(self))
    monitor.run_proxy("http://localhost:8000", 9000)
    with patch("monitor.analyze_request"), patch("monitor.httpx.request") as forward:
        forward.return_value = httpx.Response(200, content=b"/* dashboard script */")
        response = apps[0].test_client().get("/static/vendor/react-18.2.0.min.js")
    assert response.status_code == 200
    assert response.data == b"/* dashboard script */"
    assert forward.call_args.kwargs["url"] == "http://localhost:8000/static/vendor/react-18.2.0.min.js"


def test_monitor_creates_new_job_after_dedupe_window(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(monitor, "submitted_alerts", set())
    monkeypatch.setattr(monitor, "_submitted_at", {})
    with patch("monitor.time.monotonic", return_value=10) as clock:
        with patch("monitor.httpx.post", return_value=httpx.Response(202, json={"job_id": "job-1"})) as post:
            monitor.submit_to_sentinel("Synthetic test attack", "attack")
            monitor.submit_to_sentinel("Synthetic test attack", "attack")
            assert post.call_count == 1
            clock.return_value = 41
            monitor.submit_to_sentinel("Synthetic test attack", "attack")
            assert post.call_count == 2


def test_monitor_detection_starts_job_without_queue_consumer(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(monitor, "submitted_alerts", set())
    monkeypatch.setattr(monitor, "_submitted_at", {})
    with patch("monitor.httpx.post", return_value=httpx.Response(202, json={"job_id": "detected-job"})) as post:
        monitor.analyze_request("GET", "/search?q=UNION SELECT", {}, "", "192.0.2.90")
    assert post.call_count == 1
    assert post.call_args.args[0] == f"{monitor.SENTINEL_URL}/api/v1/jobs"
