from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.api.app import app
from backend.core.job_store import JobStore
from backend.core.ioc_parser import extract_iocs
from backend.core.search import search_threat_intel


def test_browser_version_is_not_an_ip():
    result = extract_iocs('Request from 127.0.0.1 User-Agent: Chrome/152.0.0.0 Safari/537.36 to 8.8.8.8')
    assert result['ips'] == ['127.0.0.1', '8.8.8.8']


def test_api_returns_complete_structured_intel():
    store = JobStore()
    snippet = '8.8.8.8 ' + 'Evidence details. ' * 100
    store.create('report', {'context': {'search_snippets': [snippet], 'cve_matches': []},
                            'evidence': {'raw_logs': ['original log']}})
    with patch('backend.api.routes.job_store', store):
        result = TestClient(app).get('/api/v1/jobs/report').json()
    assert result['context']['search_snippets'] == [snippet]
    assert result['evidence']['raw_logs'] == ['original log']


def test_intel_skips_local_ips_and_preserves_relevant_text(monkeypatch):
    monkeypatch.setenv('TAVILY_API_KEY', 'fake')
    content = '8.8.8.8 ' + 'Relevant details. ' * 100
    client = MagicMock()
    client.search.return_value = {'results': [
        {'content': content, 'url': 'https://example.com/intel'},
        {'content': 'Generic definition of cybersecurity', 'url': 'https://example.com/definition'},
    ]}
    with patch('tavily.TavilyClient', return_value=client):
        result = search_threat_intel(['127.0.0.1', '192.168.1.1', '8.8.8.8'])
    assert client.search.call_count == 1
    assert len(result) == 1
    assert content in result[0]
