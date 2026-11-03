import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from web.app import main, scanner
from web.app.agent import llm, loop
from web.app.config import settings
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
        main._CHAT_HITS.clear()
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

    def test_rename(self):
        sid = _events(self.client.post("/api/v1/scans/s1/chat", json={"message": "hi"}).text)[0]["session_id"]
        r = self.client.patch(f"/api/v1/scans/s1/chat/{sid}", json={"title": "My renamed chat"})
        self.assertEqual(r.status_code, 200)
        h = self.client.get("/api/v1/scans/s1/chat").json()
        self.assertEqual(h["sessions"][0]["title"], "My renamed chat")
        self.assertEqual(self.client.patch("/api/v1/scans/s1/chat/nope", json={"title": "x"}).status_code, 404)
        self.assertEqual(self.client.patch(f"/api/v1/scans/s1/chat/{sid}", json={"title": ""}).status_code, 422)

    def test_fork_copies_history_into_a_new_independent_session(self):
        sid = _events(self.client.post("/api/v1/scans/s1/chat", json={"message": "hi"}).text)[0]["session_id"]
        self.client.patch(f"/api/v1/scans/s1/chat/{sid}", json={"title": "Original"})
        r = self.client.post(f"/api/v1/scans/s1/chat/{sid}/fork")
        self.assertEqual(r.status_code, 200)
        new_sid = r.json()["session_id"]
        self.assertNotEqual(new_sid, sid)

        original = self.client.get(f"/api/v1/scans/s1/chat?session_id={sid}").json()
        forked = self.client.get(f"/api/v1/scans/s1/chat?session_id={new_sid}").json()
        self.assertEqual(forked["messages"], original["messages"])   # same history, copied not shared
        new_title = next(s["title"] for s in forked["sessions"] if s["id"] == new_sid)
        self.assertEqual(new_title, "Fork: Original")

        # continuing the fork must not touch the original session's history
        self.client.post("/api/v1/scans/s1/chat", json={"message": "only in the fork", "session_id": new_sid})
        original_after = self.client.get(f"/api/v1/scans/s1/chat?session_id={sid}").json()
        self.assertEqual(len(original_after["messages"]), len(original["messages"]))

        self.assertEqual(self.client.post("/api/v1/scans/s1/chat/nope/fork").status_code, 404)

    def test_validation_and_errors(self):
        self.assertEqual(self.client.post("/api/v1/scans/s1/chat", json={"message": ""}).status_code, 422)
        over_limit = settings.chat_message_max_chars + 1
        self.assertEqual(self.client.post("/api/v1/scans/s1/chat", json={"message": "x" * over_limit}).status_code, 422)
        r = self.client.post("/api/v1/scans/s1/chat", json={"message": "x", "provider": "evil"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/api/v1/scans/s1/chat", json={"message": "x", "session_id": "nope"})
        self.assertEqual(r.status_code, 404)

    def test_attachments_validation(self):
        # too many attachments
        atts = [{"kind": "text", "name": f"f{i}.txt", "content": "x"} for i in range(6)]
        r = self.client.post("/api/v1/scans/s1/chat", json={"message": "q", "attachments": atts})
        self.assertEqual(r.status_code, 422)
        self.assertIn("Too many attachments", r.json()["detail"])

        # one text attachment over the per-file limit
        big = "x" * (settings.chat_attachment_max_chars + 1)
        r = self.client.post("/api/v1/scans/s1/chat",
                             json={"message": "q", "attachments": [{"kind": "text", "name": "big.txt", "content": big}]})
        self.assertEqual(r.status_code, 422)
        self.assertIn("too long", r.json()["detail"])

        # message empty but has an attachment -> allowed (not the "empty message" 422)
        r = self.client.post("/api/v1/scans/s1/chat",
                             json={"message": "", "attachments": [{"kind": "text", "name": "a.txt", "content": "hi"}]})
        self.assertEqual(r.status_code, 200)

        # image attachment with an unsupported media type
        r = self.client.post("/api/v1/scans/s1/chat", json={"message": "q", "attachments": [
            {"kind": "image", "name": "a.bmp", "content": "AAAA", "media_type": "image/bmp"}]})
        self.assertEqual(r.status_code, 422)
        self.assertIn("unsupported image type", r.json()["detail"])

        # image attachment against a non-vision provider (default scan provider is ollama, which IS
        # vision-capable at the transport-format level — force a non-vision one explicitly)
        r = self.client.post("/api/v1/scans/s1/chat", json={
            "message": "q", "provider": "deepseek",
            "attachments": [{"kind": "image", "name": "a.png", "content": "AAAA", "media_type": "image/png"}]})
        self.assertEqual(r.status_code, 422)
        self.assertIn("does not accept image attachments", r.json()["detail"])

    def test_chat_is_rate_limited_globally_with_retry_after(self):
        with patch.object(main.settings, "chat_rate_per_min", 2):
            codes = [self.client.post("/api/v1/scans/s1/chat", json={"message": "hi"}) for _ in range(3)]
        self.assertEqual([r.status_code for r in codes], [200, 200, 429])
        self.assertGreaterEqual(int(codes[2].headers["retry-after"]), 1)

    def test_rate_limit_window_expires(self):
        with patch.object(main.settings, "chat_rate_per_min", 1):
            self.assertEqual(self.client.post("/api/v1/scans/s1/chat", json={"message": "a"}).status_code, 200)
            main._CHAT_HITS[0] -= 61   # pretend a minute passed
            self.assertEqual(self.client.post("/api/v1/scans/s1/chat", json={"message": "b"}).status_code, 200)

    def test_auth_accepts_only_the_exact_key_even_with_odd_bytes(self):
        with patch.object(main.settings, "api_key", "s3cret"):
            ok = lambda k: self.client.get("/api/v1/scans/s1/chat", headers={"X-Api-Key": k.encode("latin-1")}).status_code  # noqa: E731
            self.assertEqual(ok("s3cret"), 200)
            for bad in ("", "s3cre", "s3cret ", "S3CRET", "sécret"):
                self.assertEqual(ok(bad), 401, bad)

    def test_auth_enforced(self):
        with patch.object(main.settings, "api_key", "secret"):
            self.assertEqual(self.client.post("/api/v1/scans/s1/chat", json={"message": "x"}).status_code, 401)
            self.assertEqual(self.client.get("/api/v1/scans/s1/chat").status_code, 401)


if __name__ == "__main__":
    unittest.main()
