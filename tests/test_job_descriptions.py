from unittest.mock import patch

from fastapi.testclient import TestClient
from backend.api.app import app
from backend.core.job_store import JobStore


def test_job_list_identifies_distinct_alerts():
    store = JobStore()
    alerts = {
        "sql-job": "SQL Injection detected from 127.0.0.1. Method: GET, Path: /search.",
        "xss-job": "XSS Attack detected from 127.0.0.1. Method: POST, Path: /comment.",
    }
    for job_id, description in alerts.items():
        store.create(job_id, {"job_id": job_id, "problem_statement": description})
    with patch("backend.api.routes.job_store", store):
        response = TestClient(app).get("/api/v1/jobs")
    assert response.status_code == 200
    assert {job["job_id"]: job["problem_statement"] for job in response.json()} == alerts
