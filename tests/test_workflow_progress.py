import threading
from unittest.mock import patch

from backend.adapters.sentinel import start_agent_workflow, poll_until_complete
from backend.core.job_store import job_store
from backend.core.state import JobStatus


def test_progress_is_visible_before_graph_finishes():
    published = threading.Event()
    release = threading.Event()

    class Graph:
        def stream(self, state, stream_mode):
            assert stream_mode == "values"
            assert state["job_status"] == JobStatus.RUNNING
            state["messages"] = [{"role": "supervisor", "content": "Classified", "timestamp": "now"}]
            yield state
            published.set()
            assert release.wait(5)
            state["job_status"] = JobStatus.COMPLETE
            yield state

    with patch("backend.adapters.sentinel.get_graph", return_value=Graph()):
        job_id = start_agent_workflow("Synthetic progress check")
        try:
            assert published.wait(5)
            snapshot = job_store.get(job_id)
            assert snapshot is not None
            assert snapshot.get("job_status") == JobStatus.RUNNING
            assert snapshot.get("messages", [])[0]["content"] == "Classified"
        finally:
            release.set()
        assert poll_until_complete(job_id, 5, 0.01)["job_status"] == JobStatus.COMPLETE


def test_stream_failure_preserves_previous_progress():
    class Graph:
        def stream(self, state, stream_mode):
            state["messages"] = [{"role": "scout", "content": "Evidence gathered", "timestamp": "now"}]
            yield state
            raise RuntimeError("Synthetic upstream failure")

    with patch("backend.adapters.sentinel.get_graph", return_value=Graph()):
        job_id = start_agent_workflow("Synthetic failure check")
        result = poll_until_complete(job_id, 5, 0.01)
    assert result["job_status"] == JobStatus.FAILED
    assert result["messages"][0]["content"] == "Evidence gathered"
    assert result["error"] == "Synthetic upstream failure"
