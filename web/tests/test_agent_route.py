import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from web.app import main, scanner
from web.app.agent import llm, loop
from web.app.models import ScanDetail


def _events(text):
    return [json.loads(b[6:]) for b in text.split("\n\n") if b.startswith("data: ")]


async def fake_step(cfg, system, messages, tools, **kw):
    yield {"type": "text", "text": "hello"}
    yield {"type": "stop", "reason": "end_turn"}


class ChatRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        detail = ScanDetail(scan_id="s1", filename="a.apk", state="done", created_at="t",
                            llm_provider="ollama", platform="android")
        self.patches = [
            patch.object(main, "_require_db", return_value=("/nope", "app")),
            patch.object(scanner, "get_scan_detail", return_value=detail),
            patch.object(scanner, "_scan_dir", return_value=Path(self.tmp.name)),
            patch.object(loop, "chat_step", fake_step),
            patch.object(main.settings, "api_key", ""),
        ]
        for p in self.patches:
            p.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def test_stream_then_history_then_delete(self):
        r = self.client.post("/api/v1/scans/s1/chat", json={"message": "hi"})
        self.assertEqual(r.headers["content-type"].split(";")[0], "text/event-stream")
        evs = _events(r.text)
        self.assertEqual([e["type"] for e in evs], ["session", "token", "done"])
        sid = evs[0]["session_id"]
        self.assertNotIn(sid, main._ACTIVE_CHATS)  # flag lives inside the generator and is released
        h = self.client.get("/api/v1/scans/s1/chat").json()
        self.assertEqual(h["session_id"], sid)
        self.assertEqual([m["role"] for m in h["messages"]], ["user", "assistant"])
        # follow-up reuses the session
        r2 = self.client.post("/api/v1/scans/s1/chat", json={"message": "again", "session_id": sid})
        self.assertEqual(_events(r2.text)[0]["session_id"], sid)
        self.assertEqual(self.client.delete(f"/api/v1/scans/s1/chat/{sid}").status_code, 204)
        self.assertEqual(self.client.delete(f"/api/v1/scans/s1/chat/{sid}").status_code, 404)

    def test_validation_and_errors(self):
        self.assertEqual(self.client.post("/api/v1/scans/s1/chat", json={"message": ""}).status_code, 422)
        self.assertEqual(self.client.post("/api/v1/scans/s1/chat", json={"message": "x" * 4001}).status_code, 422)
        r = self.client.post("/api/v1/scans/s1/chat", json={"message": "x", "provider": "evil"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/api/v1/scans/s1/chat", json={"message": "x", "session_id": "nope"})
        self.assertEqual(r.status_code, 404)

    def test_auth_enforced(self):
        with patch.object(main.settings, "api_key", "secret"):
            self.assertEqual(self.client.post("/api/v1/scans/s1/chat", json={"message": "x"}).status_code, 401)
            self.assertEqual(self.client.get("/api/v1/scans/s1/chat").status_code, 401)


if __name__ == "__main__":
    unittest.main()
