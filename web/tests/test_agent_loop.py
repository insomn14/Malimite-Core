import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from web.app.agent import loop, store
from web.app.agent.llm import LlmCfg, LlmError
from web.app.agent.tools import Ctx

CFG = LlmCfg("claude", "m", "k", "http://x")


calls: list = []   # what the loop passed to each step() call


def scripted(*turns):
    """step() replacement: each call plays the next list of events."""
    calls.clear()
    it = iter(turns)

    async def step(cfg, system, messages, tools, **kw):
        calls.append({"system": system, "messages": messages, **kw})
        for ev in next(it):
            if isinstance(ev, Exception):
                raise ev
            yield ev
    return step


TOOL = {"type": "tool_use", "id": "t1", "name": "list_classes", "input": {}}


class LoopTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = store.path_for(Path(self.tmp.name))
        self.sid = await store.create_session(self.db, "claude", "m")
        self.ctx = Ctx("s", "/nope", "e", "android", Path(self.tmp.name), {})

    async def asyncTearDown(self):
        self.tmp.cleanup()

    async def _run(self, step, run, text="hi"):
        return [e async for e in loop.run_chat(self.ctx, self.db, self.sid, text, CFG, step=step, run=run)]

    async def test_tool_round_then_answer_persists_valid_history(self):
        async def run(ctx, name, args):
            return True, "<tool_data>[]</tool_data>"
        evs = await self._run(scripted(
            [{"type": "text", "text": "looking"}, TOOL, {"type": "stop", "reason": "tool_use"}],
            [{"type": "text", "text": "done"}, {"type": "stop", "reason": "end_turn"}]), run)
        self.assertEqual([e["type"] for e in evs],
                         ["token", "tool_call", "tool_result", "token", "done"])
        hist = await store.history(self.db, self.sid)
        self.assertEqual([m["role"] for m in hist], ["user", "assistant", "user", "assistant"])
        self.assertEqual(hist[2]["content"][0]["tool_use_id"], "t1")

    async def test_last_round_forces_a_final_answer_instead_of_an_error(self):
        async def run(ctx, name, args):
            return True, "x"
        evs_in = [[TOOL, {"type": "stop", "reason": "tool_use"}]] * 2 + [
            [{"type": "text", "text": "ringkasan akhir"}, {"type": "stop", "reason": "end_turn"}]]
        with patch.object(loop.settings, "chat_max_turns", 3):
            evs = await self._run(scripted(*evs_in), run)
        self.assertEqual(evs[-2:], [{"type": "token", "text": "ringkasan akhir"}, {"type": "done"}])
        self.assertFalse(any(e["type"] == "error" for e in evs))
        self.assertEqual([c.get("allow_tools", True) for c in calls], [True, True, False])
        self.assertIn("FINAL ROUND", calls[2]["system"])
        self.assertNotIn("FINAL ROUND", calls[0]["system"])
        hist = await store.history(self.db, self.sid)
        self.assertEqual(hist[-1]["role"], "assistant")  # ends on an answer, so the chat can simply continue

    async def test_model_that_ignores_tool_choice_none_is_not_executed(self):
        ran = []

        async def run(ctx, name, args):
            ran.append(name)
            return True, "x"
        with patch.object(loop.settings, "chat_max_turns", 1):
            evs = await self._run(scripted([{"type": "text", "text": "answer"}, TOOL]), run)
        self.assertEqual(ran, [])
        self.assertEqual(evs[-1], {"type": "done"})
        hist = await store.history(self.db, self.sid)
        self.assertEqual([b["type"] for b in hist[-1]["content"]], ["text"])  # no dangling tool_use persisted

    async def test_empty_final_answer_gets_a_fallback_that_invites_continuing(self):
        with patch.object(loop.settings, "chat_max_turns", 1):
            evs = await self._run(scripted([{"type": "stop", "reason": "end_turn"}]), None)
        self.assertIn("lanjutkan", evs[0]["text"])
        self.assertEqual(evs[-1], {"type": "done"})

    async def test_conversation_continues_after_a_wrapped_up_message(self):
        async def run(ctx, name, args):
            return True, "x"
        with patch.object(loop.settings, "chat_max_turns", 2):
            await self._run(scripted([TOOL], [{"type": "text", "text": "partial summary"}]), run)
            await self._run(scripted([{"type": "text", "text": "continued"}]), run, text="lanjutkan")
        sent = calls[0]["messages"]  # what the model saw on the follow-up
        self.assertEqual(sent[-1], {"role": "user", "content": [{"type": "text", "text": "lanjutkan"}]})
        ids = [b.get("id") or b.get("tool_use_id") for m in sent for b in m["content"] if b["type"] in ("tool_use", "tool_result")]
        self.assertEqual(sorted(ids), ["t1", "t1"])  # every tool_use still has its result: history is provider-valid

    async def test_llm_error_is_reported_not_raised(self):
        evs = await self._run(scripted([LlmError("claude returned HTTP 401")]), None)
        self.assertEqual(evs[-1], {"type": "error", "message": "claude returned HTTP 401"})

    async def test_tool_timeout_and_crash_go_back_to_model(self):
        async def slow(ctx, name, args):
            await asyncio.sleep(5)
        with patch.dict(loop._TIMEOUT, {"list_classes": lambda: 0.05}):
            evs = await self._run(scripted([TOOL], [{"type": "text", "text": "ok"}]), slow)
        res = [e for e in evs if e["type"] == "tool_result"][0]
        self.assertFalse(res["ok"])
        self.assertIn("timed out", res["preview"])

        async def boom(ctx, name, args):
            raise RuntimeError("secret detail")
        self.sid = await store.create_session(self.db, "claude", "m")
        evs = await self._run(scripted([TOOL], [{"type": "text", "text": "ok"}]), boom)
        res = [e for e in evs if e["type"] == "tool_result"][0]
        self.assertNotIn("secret detail", res["preview"])

    async def test_cancel_during_tool_leaves_history_valid(self):
        started = asyncio.Event()

        async def hang(ctx, name, args):
            started.set()
            await asyncio.sleep(30)

        async def consume():
            async for _ in loop.run_chat(self.ctx, self.db, self.sid, "q", CFG,
                                         step=scripted([TOOL]), run=hang):
                pass
        t = asyncio.create_task(consume())
        await started.wait()
        t.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await t
        hist = await store.history(self.db, self.sid)
        self.assertEqual([m["role"] for m in hist], ["user", "assistant", "user"])
        self.assertTrue(hist[2]["content"][0]["is_error"])

    async def test_answer_cut_by_the_output_limit_continues_seamlessly_and_is_saved_once(self):
        evs = await self._run(scripted(
            [{"type": "text", "text": "Temuan pertama: ** `gra"}, {"type": "stop", "reason": "length"}],
            [{"type": "text", "text": "nt` URI permission."}, {"type": "stop", "reason": "stop"}]), None, text="elaborate")
        text = "".join(e["text"] for e in evs if e["type"] == "token")
        self.assertEqual(text, "Temuan pertama: ** `grant` URI permission.")
        self.assertEqual([e["type"] for e in evs if e["type"] in ("continue", "done", "error")], ["continue", "done"])
        # the 2nd model call saw its own cut-off text plus a nudge, none of it persisted
        sent = calls[1]["messages"]
        self.assertEqual(sent[-2], {"role": "assistant", "content": [{"type": "text", "text": "Temuan pertama: ** `gra"}]})
        self.assertIn("cut off", sent[-1]["content"][0]["text"])
        self.assertNotIn("cut off", str(calls[0]["messages"]))
        hist = await store.history(self.db, self.sid)
        self.assertEqual([m["role"] for m in hist], ["user", "assistant"])   # no synthetic user turn, one assistant message
        self.assertEqual(hist[-1]["content"][0]["text"], "Temuan pertama: ** `grant` URI permission.")

    async def test_continuation_has_its_own_budget_and_ends_with_a_note(self):
        cut = [{"type": "text", "text": "x"}, {"type": "stop", "reason": "max_tokens"}]
        with patch.object(loop.settings, "chat_max_continuations", 2):
            evs = await self._run(scripted(cut, cut, cut), None)
        self.assertEqual(len(calls), 3)                                    # 1 call + 2 continuations, then give up
        self.assertEqual(evs[-1], {"type": "done"})
        self.assertIn("lanjutkan", "".join(e.get("text", "") for e in evs))  # tells the user how to go on
        hist = await store.history(self.db, self.sid)
        self.assertTrue(hist[-1]["content"][0]["text"].startswith("xxx"))

    async def test_empty_continuation_does_not_loop(self):
        with patch.object(loop.settings, "chat_max_continuations", 5):
            evs = await self._run(scripted(
                [{"type": "text", "text": "abc"}, {"type": "stop", "reason": "length"}],
                [{"type": "stop", "reason": "length"}]), None)
        self.assertEqual(len(calls), 2)
        self.assertEqual(evs[-1], {"type": "done"})

    async def test_continuations_do_not_consume_tool_rounds(self):
        async def run(ctx, name, args):
            return True, "x"
        cut = [{"type": "text", "text": "a"}, {"type": "stop", "reason": "length"}]
        with patch.object(loop.settings, "chat_max_turns", 2):
            evs = await self._run(scripted(cut, cut, [TOOL], [{"type": "text", "text": "final"}]), run)
        # 2 truncated segments + tool round + final answer: all fit in 2 turns
        self.assertFalse(any(e["type"] == "error" for e in evs))
        self.assertEqual(evs[-1], {"type": "done"})
        self.assertEqual(calls[3]["allow_tools"] if "allow_tools" in calls[3] else True, False)  # 2nd turn is the forced last
        hist = await store.history(self.db, self.sid)
        self.assertEqual([m["role"] for m in hist], ["user", "assistant", "user", "assistant"])
        self.assertEqual(hist[1]["content"][0]["text"], "aa")     # carried text joined the tool-calling message

    async def test_cancel_during_continuation_saves_what_was_written(self):
        started = asyncio.Event()

        async def step(cfg, system, messages, tools, **kw):
            calls.append({"messages": messages})
            if len(calls) == 1:
                yield {"type": "text", "text": "part1 "}
                yield {"type": "stop", "reason": "length"}
            else:
                yield {"type": "text", "text": "part2"}
                started.set()
                await asyncio.sleep(30)

        async def consume():
            async for _ in loop.run_chat(self.ctx, self.db, self.sid, "q", CFG, step=step):
                pass
        calls.clear()
        t = asyncio.create_task(consume())
        await started.wait()
        t.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await t
        hist = await store.history(self.db, self.sid)
        self.assertEqual(hist[-1]["content"][0]["text"], "part1 part2")

    def test_clip_elides_oldest_results_first(self):
        msgs = [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": str(i), "content": "x" * 1000}]}
                for i in range(3)]
        out = loop.clip(msgs, budget=2500)
        self.assertIn("elided", out[0]["content"][0]["content"])
        self.assertEqual(out[2]["content"][0]["content"], "x" * 1000)
        self.assertEqual(msgs[0]["content"][0]["content"], "x" * 1000)  # input untouched


if __name__ == "__main__":
    unittest.main()
