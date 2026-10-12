import tempfile
import unittest
from pathlib import Path

from web.app.agent import store


class StoreTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = store.path_for(Path(self.dir.name))

    def tearDown(self):
        self.dir.cleanup()

    async def test_session_roundtrip_and_cascade(self):
        sid = await store.create_session(self.path, "claude", "m")
        await store.set_title_if_empty(self.path, sid, "x" * 100)
        await store.set_title_if_empty(self.path, sid, "ignored")
        await store.append(self.path, sid, "user", [{"type": "text", "text": "hi"}])
        self.assertEqual((await store.get_session(self.path, sid))["title"], "x" * 60)
        self.assertEqual((await store.history(self.path, sid))[0]["content"][0]["text"], "hi")
        self.assertTrue(await store.delete_session(self.path, sid))
        self.assertEqual(await store.history(self.path, sid), [])  # messages cascaded
        self.assertFalse(await store.delete_session(self.path, sid))

    async def test_cache_keyed_by_tool_lib_target(self):
        await store.cache_put(self.path, "jadx", "", "a.B", "code1")
        self.assertEqual(await store.cache_get(self.path, "jadx", "", "a.B"), "code1")
        self.assertIsNone(await store.cache_get(self.path, "asc", "", "a.B"))
        await store.cache_put(self.path, "jadx", "", "a.B", "code2")
        self.assertEqual(await store.cache_get(self.path, "jadx", "", "a.B"), "code2")


if __name__ == "__main__":
    unittest.main()
