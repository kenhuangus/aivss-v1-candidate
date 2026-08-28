"""HTTP smoke tests for the demo dashboard."""

from __future__ import annotations

import json
import threading
from http.client import HTTPConnection

from aivss_calc.demo_server import DemoHandler
from http.server import ThreadingHTTPServer


def _with_server(test_fn):
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        test_fn(host, port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _get(host: str, port: int, path: str) -> tuple[int, bytes]:
    conn = HTTPConnection(host, port, timeout=30)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, body


def test_demo_index_and_assets():
    def run(host, port):
        for path in ("/", "/favicon.ico", "/web/style.css", "/web/app.js"):
            status, body = _get(host, port, path)
            assert status == 200, path
            assert body, path

    _with_server(run)


def test_demo_top10_api():
    def run(host, port):
        status, body = _get(host, port, "/api/top10")
        assert status == 200
        rows = json.loads(body)
        assert len(rows) == 10
        assert rows[0]["asi"] == "ASI01"
        assert "mode1_aivss" in rows[0]
        assert "escalated" in rows[0]
        # A2 at 3D ceiling: overlay_triggered but not escalated
        asi01 = next(r for r in rows if r["asi"] == "ASI01")
        assert asi01["overlay_triggered"] is True
        assert asi01["escalated"] is False

    _with_server(run)


def test_demo_scenario_api():
    def run(host, port):
        status, body = _get(host, port, "/api/scenario/ASI04")
        assert status == 200
        payload = json.loads(body)
        assert payload["report"]["risk_category"]["id"] == "ASI04"
        assert payload["report"]["scores"]["mode1_interpretation"]["status"] == "normative"
        assert payload["report"]["decision"]["ssvc"]["decision_table"] == "cisa:DT_BOD2604:1.0.0"

        missing, _ = _get(host, port, "/api/scenario/ASI99")
        assert missing == 404

    _with_server(run)
