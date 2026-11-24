"""agent/runs.py: a chat generation must survive the request that started it going away."""
import asyncio
import unittest

from web.app.agent import runs


class RunsTests(unittest.IsolatedAsyncioTestCase):
    async def test_generation_continues_after_the_first_follower_leaves_and_can_be_reattached(self):
        gate = asyncio.Event()

        async def body():
            yield {"type": "token", "text": "a"}
            await gate.wait()
            yield {"type": "token", "text": "b"}
            yield {"type": "done"}

        run = runs.start("s1", 3, body)
        first = run.follow()
        self.assertEqual((await first.__anext__())["text"], "a")
        await first.aclose()                       # page refreshed / tab switched
        self.assertIn("s1", runs.RUNS)
        self.assertEqual(run.base, 3)
        gate.set()
        self.assertEqual([e["type"] for e in [e async for e in run.follow()]], ["token", "token", "done"])
        self.assertNotIn("s1", runs.RUNS)

    async def test_stop_cancels_and_ends_followers(self):
        async def body():
            yield {"type": "token", "text": "a"}
            await asyncio.sleep(60)

        run = runs.start("s2", 0, body)
        await run.follow().__anext__()
        self.assertTrue(runs.stop("s2"))
        self.assertEqual([e["type"] for e in [e async for e in run.follow()]], ["token"])
        self.assertFalse(runs.stop("s2"))

    async def test_failure_is_reported_and_the_hook_still_runs(self):
        seen = []

        async def body():
            yield {"type": "token", "text": "a"}
            raise RuntimeError("boom")

        async def after(run):
            seen.append(len(run.events))

        run = runs.start("s3", 0, body, after)
        self.assertEqual([e["type"] for e in [e async for e in run.follow()]], ["token", "error"])
        self.assertEqual(seen, [2])


if __name__ == "__main__":
    unittest.main()
