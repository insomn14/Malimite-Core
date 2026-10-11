"""Sidecar chat DB (<scan_dir>/<id>/chat.sqlite): sessions, messages, decompile cache.

Kept apart from the scan DB so the assistant can never alter scan data and the
Java SqliteStore schema/WAL setup is untouched.
"""
import json
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import aiosqlite

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ChatSessions(
    id TEXT PRIMARY KEY, title TEXT, provider TEXT, model TEXT, created REAL);
CREATE TABLE IF NOT EXISTS ChatMessages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES ChatSessions(id) ON DELETE CASCADE,
    role TEXT NOT NULL, content_json TEXT NOT NULL, created REAL);
CREATE TABLE IF NOT EXISTS AgentDecompiles(
    tool TEXT NOT NULL, lib TEXT NOT NULL DEFAULT '', target TEXT NOT NULL,
    code TEXT NOT NULL, created REAL, PRIMARY KEY(tool, lib, target));
"""


def path_for(scan_dir: Path) -> str:
    return str(scan_dir / "chat.sqlite")


@asynccontextmanager
async def _conn(path: str):
    async with aiosqlite.connect(path) as db:
        await db.execute("PRAGMA foreign_keys=ON")
        await db.executescript(_SCHEMA)
        yield db


async def create_session(path: str, provider: str, model: str) -> str:
    sid = uuid.uuid4().hex[:16]
    async with _conn(path) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("INSERT INTO ChatSessions VALUES (?,?,?,?,?)",
                         (sid, "", provider, model, time.time()))
        await db.commit()
    return sid


async def get_session(path: str, sid: str) -> Optional[dict]:
    async with _conn(path) as db:
        async with db.execute("SELECT id,title,provider,model,created FROM ChatSessions WHERE id=?", (sid,)) as c:
            r = await c.fetchone()
    return dict(zip(("id", "title", "provider", "model", "created"), r)) if r else None


async def list_sessions(path: str) -> list[dict]:
    async with _conn(path) as db:
        async with db.execute(
            "SELECT id,title,provider,model,created FROM ChatSessions ORDER BY created DESC LIMIT 50") as c:
            rows = await c.fetchall()
    return [dict(zip(("id", "title", "provider", "model", "created"), r)) for r in rows]


async def set_title_if_empty(path: str, sid: str, text: str) -> None:
    async with _conn(path) as db:
        await db.execute("UPDATE ChatSessions SET title=? WHERE id=? AND title=''", (text[:60], sid))
        await db.commit()


async def set_llm(path: str, sid: str, provider: str, model: str) -> None:
    async with _conn(path) as db:
        await db.execute("UPDATE ChatSessions SET provider=?, model=? WHERE id=?", (provider, model, sid))
        await db.commit()


async def append(path: str, sid: str, role: str, content: list[dict]) -> None:
    async with _conn(path) as db:
        await db.execute("INSERT INTO ChatMessages(session_id,role,content_json,created) VALUES (?,?,?,?)",
                         (sid, role, json.dumps(content), time.time()))
        await db.commit()


async def history(path: str, sid: str) -> list[dict]:
    async with _conn(path) as db:
        async with db.execute(
            "SELECT role, content_json FROM ChatMessages WHERE session_id=? ORDER BY id", (sid,)) as c:
            rows = await c.fetchall()
    return [{"role": r, "content": json.loads(j)} for r, j in rows]


async def delete_session(path: str, sid: str) -> bool:
    async with _conn(path) as db:
        cur = await db.execute("DELETE FROM ChatSessions WHERE id=?", (sid,))
        await db.commit()
        return cur.rowcount > 0


async def cache_get(path: str, tool: str, lib: str, target: str) -> Optional[str]:
    async with _conn(path) as db:
        async with db.execute("SELECT code FROM AgentDecompiles WHERE tool=? AND lib=? AND target=?",
                              (tool, lib, target)) as c:
            r = await c.fetchone()
    return r[0] if r else None


async def cache_put(path: str, tool: str, lib: str, target: str, code: str) -> None:
    async with _conn(path) as db:
        await db.execute("INSERT OR REPLACE INTO AgentDecompiles VALUES (?,?,?,?,?)",
                         (tool, lib, target, code, time.time()))
        await db.commit()
