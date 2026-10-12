import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from web.app.agent import ondemand, tools
from web.app.agent.tools import Ctx


def py(code):
    return lambda *a, **k: [sys.executable, "-c", code]


class OnDemandTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.dir = Path(self._d.name)

    def tearDown(self):
        self._d.cleanup()

    async def test_parses_last_json_line_ignoring_noise(self):
        code = "print('log line'); print('{\"ok\": true, \"code\": \"X\"}')"
        with patch.object(ondemand, "_cmd", py(code)):
            self.assertEqual((await ondemand.decompile(self.dir, "asc", "a.B"))["code"], "X")

    async def test_non_json_output_becomes_error(self):
        code = "import sys; print('boom', file=sys.stderr); sys.exit(3)"
        with patch.object(ondemand, "_cmd", py(code)):
            r = await ondemand.decompile(self.dir, "asc", "a.B")
        self.assertFalse(r["ok"])
        self.assertIn("boom", r["error"])

    async def test_cancel_kills_grandchildren(self):
        with tempfile.TemporaryDirectory() as d:
            pidfile = Path(d) / "pid"
            code = ("import subprocess,time;"
                    f"p=subprocess.Popen(['sleep','300']);open({str(pidfile)!r},'w').write(str(p.pid));time.sleep(300)")
            with patch.object(ondemand, "_cmd", py(code)):
                t = asyncio.create_task(ondemand.decompile(self.dir, "jadx", "a.B"))
                for _ in range(50):
                    if pidfile.exists() and pidfile.read_text():
                        break
                    await asyncio.sleep(0.1)
                pid = int(pidfile.read_text())
                os.kill(pid, 0)  # grandchild is alive
                t.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await t
            for _ in range(30):  # SIGKILL + reaping is asynchronous
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return
                await asyncio.sleep(0.1)
            self.fail("grandchild process survived cancellation")


class HygieneTests(unittest.IsolatedAsyncioTestCase):
    async def test_child_env_has_no_secrets_and_tmpdir_is_removed(self):
        code = ("import os,json,sys;print(json.dumps({'ok':True,'code':json.dumps(dict(os.environ)),"
                "'tmp':[a for a in sys.argv]}))")
        with tempfile.TemporaryDirectory() as d, \
             patch.dict(os.environ, {"OPENAI_API_KEY": "sk-secret", "API_KEY": "srv", "JADX_HOME": "/j"}), \
             patch.object(ondemand, "_cmd", py(code)):
            r = await ondemand.decompile(Path(d), "asc", "a.B")
            env = json.loads(r["code"])
            self.assertNotIn("OPENAI_API_KEY", env)
            self.assertNotIn("API_KEY", env)
            self.assertEqual(env.get("JADX_HOME"), "/j")
            self.assertEqual([p.name for p in Path(d).iterdir()], [], "per-call tmpdir must be cleaned up")

    async def test_tmpdir_removed_even_when_cancelled(self):
        with tempfile.TemporaryDirectory() as d, patch.object(ondemand, "_cmd", py("import time; time.sleep(60)")):
            t = asyncio.create_task(ondemand.decompile(Path(d), "asc", "a.B"))
            await asyncio.sleep(0.4)
            t.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await t
            self.assertEqual(list(Path(d).iterdir()), [])


class DecompileToolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def ctx(self, platform="ANDROID"):
        return Ctx("s", "/nope", "app", platform, Path(self.tmp.name), {})

    async def test_second_call_is_cached_and_failures_are_not(self):
        ok = {"ok": True, "tool": "asc", "target": "a.B", "code": "class B {}", "error": ""}
        with patch.object(tools.ondemand, "decompile", AsyncMock(return_value=ok)) as m:
            _, first = await tools.run_tool(self.ctx(), "decompile", {"tool": "asc", "target": "a.B"})
            _, second = await tools.run_tool(self.ctx(), "decompile", {"tool": "asc", "target": "a.B"})
        self.assertEqual(m.await_count, 1)
        self.assertNotIn("(cached)", first)
        self.assertIn("(cached)", second)
        self.assertIn("class B {}", second)
        bad = {"ok": False, "error": "class not found"}
        with patch.object(tools.ondemand, "decompile", AsyncMock(return_value=bad)) as m:
            _, r1 = await tools.run_tool(self.ctx(), "decompile", {"tool": "jadx", "target": "a.C"})
            await tools.run_tool(self.ctx(), "decompile", {"tool": "jadx", "target": "a.C"})
        self.assertEqual(m.await_count, 2)
        self.assertIn("class not found", r1)

    async def test_guards_run_before_any_subprocess(self):
        with patch.object(tools.ondemand, "decompile", AsyncMock()) as m:
            cases = [
                (self.ctx("IOS"), {"tool": "asc", "target": "a.B"}, "only supports Android"),
                (self.ctx(), {"tool": "asc", "target": "../../etc/passwd"}, "invalid class name"),
                (self.ctx(), {"tool": "jadx", "target": "a b"}, "invalid class name"),
                (self.ctx(), {"tool": "ghidra", "target": "main"}, "needs lib="),
                (self.ctx(), {"tool": "ghidra", "target": "main", "lib": "../x.so"}, "needs lib="),
                (self.ctx("IOS"), {"tool": "ghidra", "target": "bad;rm"}, "invalid ghidra target"),
                (self.ctx(), {"tool": "bash", "target": "x"}, "unknown decompiler"),
                (self.ctx("IOS"), {"tool": "ghidra", "target": "-deleteProject"}, "invalid ghidra target"),
                (self.ctx(), {"tool": "ghidra", "target": "main", "lib": "-x.so"}, "needs lib="),
            ]
            for ctx, args, expect in cases:
                _, out = await tools.run_tool(ctx, "decompile", args)
                self.assertIn(expect, out, args)
        m.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
