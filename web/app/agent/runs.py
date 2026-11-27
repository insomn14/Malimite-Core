"""Chat generations that outlive the HTTP request that started them.

A generation used to be the SSE response itself, so refreshing the page or switching menus cancelled it
mid-answer and the user came back to a chat that looked dead. Now the LLM loop runs in its own task and
buffers its events; any number of requests can follow (or re-attach to) the buffer, and only an explicit
stop() cancels it.
"""
import asyncio
import logging
from typing import AsyncIterator, Awaitable, Callable, Optional

log = logging.getLogger("malimite")


class Run:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self.base = 0   # persisted messages that precede this run's own (still-unsaved) output
        self.done = False
        self.task: Optional[asyncio.Task] = None
        self._cond = asyncio.Condition()

    async def _add(self, ev: dict) -> None:
        async with self._cond:
            self.events.append(ev)
            self._cond.notify_all()

    async def follow(self, start: int = 0) -> AsyncIterator[dict]:
        i = start
        while True:
            async with self._cond:
                await self._cond.wait_for(lambda: i < len(self.events) or self.done)
            while i < len(self.events):
                ev = self.events[i]
                i += 1
                yield ev
            if self.done:
                return


RUNS: dict[str, Run] = {}   # session id -> its live generation


def start(sid: str, base: int, body: Callable[[], AsyncIterator[dict]],
          finally_: Optional[Callable[[Run], Awaitable[None]]] = None) -> Run:
    run = Run()
    run.base = base

    async def produce() -> None:
        try:
            async for ev in body():
                await run._add(ev)
        except asyncio.CancelledError:   # stop(): the loop has already persisted what it had
            pass
        except Exception:
            log.exception("chat generation failed for session %s", sid)
            await run._add({"type": "error", "message": "internal error"})
        finally:
            RUNS.pop(sid, None)
            try:
                if finally_:
                    await finally_(run)
            except Exception:
                log.exception("chat post-run hook failed for session %s", sid)
            async with run._cond:
                run.done = True
                run._cond.notify_all()

    RUNS[sid] = run
    run.task = asyncio.ensure_future(produce())
    return run


def stop(sid: str) -> bool:
    run = RUNS.get(sid)
    if not run or not run.task:
        return False
    run.task.cancel()
    return True
