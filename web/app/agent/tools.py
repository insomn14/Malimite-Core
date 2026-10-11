"""Tools the assistant can call. All read-only over the scan DB; output is untrusted data."""
import json
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from .. import db
from ..config import settings
from . import ondemand, store

CLASS_RE = re.compile(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$")


@dataclass
class Ctx:
    scan_id: str
    db_path: str
    exe: str
    platform: str
    scan_dir: Any  # Path
    meta: dict


def valid_class_name(name: str) -> bool:
    return bool(name) and len(name) <= 300 and bool(CLASS_RE.match(name))


def truncate(s: str, cap: Optional[int] = None, offset: int = 0) -> str:
    cap = cap or settings.chat_tool_cap
    chunk = s[offset: offset + cap]
    end = offset + len(chunk)
    if end < len(s):
        chunk += f"\n...[truncated {len(s) - end} chars; call again with offset={end}]"
    return chunk


def wrap(text: str) -> str:
    """Delimit tool output so the model treats it as data, not instructions."""
    return "<tool_data>\n" + text.replace("</tool_data>", "<\\/tool_data>") + "\n</tool_data>"


def _j(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=1)


def _spec(name, description, props, required=()):
    return {"name": name, "description": description,
            "schema": {"type": "object", "properties": props, "required": list(required)}}


_S = {"type": "string"}
_I = {"type": "integer"}

TOOLS = [
    _spec("scan_overview", "Platform, package, counts, vulnerability counts by severity, which decompilers "
          "produced the stored code, and whether a call graph exists. Call this first.", {}),
    _spec("list_classes", "List classes (optionally filtered by substring) with method counts.",
          {"query": _S, "limit": _I, "offset": _I}),
    _spec("search_code", "Substring search over all stored decompiled code. Returns class, function and a snippet.",
          {"query": _S, "limit": _I}, ["query"]),
    _spec("get_source", "Stored decompiled code for a class (whole body) or one function. Prefer this over decompile.",
          {"class_name": _S, "function_name": _S, "offset": _I}, ["class_name"]),
    _spec("search_strings", "Substring search over extracted strings (URLs, keys, messages).",
          {"query": _S, "limit": _I}, ["query"]),
    _spec("get_vulnerabilities", "The scan's rule-based findings exactly as the Vulnerabilities tab shows them: one "
          "entry per rule_id (unique issue) with severity, CVSS, CWE, `hits` (occurrences) and sample evidence. "
          "Pass rule_id to list every occurrence of one issue.",
          {"severity": _S, "rule_id": _S, "limit": _I}),
    _spec("get_references", "Callers or callees of a function. Only populated for Ghidra-decompiled scans.",
          {"function": _S, "direction": {"type": "string", "enum": ["callers", "callees"]}},
          ["function", "direction"]),
    _spec("decompile", "Fresh on-demand decompilation of ONE class. asc = fast (Android only), jadx = slower "
          "(Android only), ghidra = native binary function (iOS Mach-O, or Android .so with `lib`; target is a "
          "function name substring or 0x address; first call per scan is slow). Results are cached. Use only when "
          "get_source is missing/garbled or a second opinion is requested.",
          {"tool": {"type": "string", "enum": ["asc", "jadx", "ghidra"]}, "target": _S, "lib": _S, "offset": _I},
          ["tool", "target"]),
]


async def _overview(ctx: Ctx, a: dict) -> str:
    counts = await db.get_counts(ctx.db_path, ctx.exe)
    rows = await db.get_vulnerabilities_brief(ctx.db_path, ctx.exe)
    issues = db.group_issues(rows)
    sev: dict[str, int] = {}
    for g in issues:
        if g["status"] not in db._SUPPRESSED:
            sev[g["severity"]] = sev.get(g["severity"], 0) + 1
    return _j({
        "platform": ctx.platform, "executable": ctx.exe, "counts": counts,
        # same numbers as the Vulnerabilities tab: unique issues per rule_id, plus raw occurrences
        "unique_open_issues_by_severity": sev, "unique_issues": len(issues), "occurrences": len(rows),
        "code_origins": await db.origin_counts(ctx.db_path, ctx.exe),
        "call_graph_available": await db.has_references(ctx.db_path),
    })


async def _list_classes(ctx: Ctx, a: dict) -> str:
    return _j(await db.list_classes(ctx.db_path, ctx.exe, a.get("query", ""), int(a.get("limit", 50)),
                                    int(a.get("offset", 0))))


async def _search_code(ctx: Ctx, a: dict) -> str:
    return _j(await db.search_code(ctx.db_path, ctx.exe, a["query"], int(a.get("limit", 20))))


async def _get_source(ctx: Ctx, a: dict) -> str:
    rows = await db.get_source(ctx.db_path, ctx.exe, a["class_name"], a.get("function_name") or None)
    if not rows:
        return "No stored code for that class/function. Use list_classes or search_code to find the exact name."
    text = "\n\n".join(f"// {r['class']}::{r['function']} [{r['origin']}]\n{r['code']}" for r in rows)
    return truncate(text, offset=int(a.get("offset", 0)))


async def _search_strings(ctx: Ctx, a: dict) -> str:
    return _j(await db.search_strings(ctx.db_path, ctx.exe, a["query"], int(a.get("limit", 30))))


async def _vulns(ctx: Ctx, a: dict) -> str:
    rows = await db.get_vulnerabilities_brief(ctx.db_path, ctx.exe)
    issues = db.group_issues(rows)
    sev, rule = (a.get("severity") or "").upper(), a.get("rule_id") or ""
    if sev:
        issues = [g for g in issues if g["severity"] == sev]
    if rule:
        issues = [g for g in issues if g["rule_id"] == rule]
        for g in issues:  # a specific rule was asked for: show every occurrence
            g["evidence"] = [{"where": r["affected_name"], "evidence": (r["evidence"] or "")[:200]}
                             for r in rows if r["rule_id"] == rule]
    limit = max(1, min(int(a.get("limit", 30)), 100))
    return _j({"unique_issues": len(issues), "issues": issues[:limit]})


async def _refs(ctx: Ctx, a: dict) -> str:
    if not await db.has_references(ctx.db_path):
        return "No call graph for this scan (only Ghidra ingest populates it). Use search_code instead."
    return _j(await db.get_references(ctx.db_path, ctx.exe, a["function"], a["direction"]))


LIB_RE = re.compile(r"^\w[\w.\-]{0,99}\.so$")
# first char must not be '-': analyzeHeadless would parse it as one of its own options
GHIDRA_TARGET_RE = re.compile(r"^(0x[0-9a-fA-F]{1,16}|[\w$@<:\[][\w\-\[\] +:.<>$@]{0,199})$")


async def _decompile(ctx: Ctx, a: dict) -> str:
    tool, target, lib = a["tool"], a["target"], a.get("lib") or ""
    android = ctx.platform.lower() == "android"
    if tool in ("asc", "jadx"):
        if not android:
            return f"{tool} only supports Android scans; use tool=ghidra for iOS."
        if not valid_class_name(target):
            return "invalid class name: use the dotted form from list_classes (e.g. com.foo.Bar or com.foo.Bar$Inner)."
    elif tool == "ghidra":
        if not GHIDRA_TARGET_RE.match(target):
            return "invalid ghidra target: use a function name substring or a 0x address."
        if android and not LIB_RE.match(lib):
            return "Android native decompilation needs lib=<name>.so (an arm64-v8a library of this APK)."
        if not android:
            lib = ""
    else:
        return f"unknown decompiler '{tool}' (asc|jadx|ghidra)"

    chat_db = store.path_for(ctx.scan_dir)
    code = await store.cache_get(chat_db, tool, lib, target)
    head = f"// decompiled with {tool}" + (" (cached)" if code is not None else "") + f": {target}\n"
    if code is None:
        res = await ondemand.decompile(ctx.scan_dir, tool, target, lib)
        if not res.get("ok"):
            return f"decompile failed: {res.get('error') or 'unknown error'}"
        code = res["code"]
        await store.cache_put(chat_db, tool, lib, target, code)
    return truncate(head + code, offset=int(a.get("offset", 0)))


_PAGED = {"get_source", "decompile"}
_RUN: dict[str, Callable[[Ctx, dict], Awaitable[str]]] = {
    "scan_overview": _overview, "list_classes": _list_classes, "search_code": _search_code,
    "get_source": _get_source, "search_strings": _search_strings, "get_vulnerabilities": _vulns,
    "get_references": _refs, "decompile": _decompile,
}


async def run_tool(ctx: Ctx, name: str, args: dict) -> tuple[bool, str]:
    """Returns (ok, wrapped_text). Never raises: errors go back to the model as text."""
    fn = _RUN.get(name)
    if not fn:
        return False, wrap(f"unknown tool '{name}'")
    if not isinstance(args, dict):
        return False, wrap("arguments must be a JSON object")
    try:
        text = await fn(ctx, args)
        if name not in _PAGED and len(text) > settings.chat_tool_cap:  # paged tools already truncated with an offset hint
            text = text[: settings.chat_tool_cap] + "\n...[truncated; narrow the query or lower limit]"
        return True, wrap(text)
    except KeyError as e:
        return False, wrap(f"missing required argument {e}")
    except (ValueError, TypeError) as e:
        return False, wrap(f"bad arguments: {e}")
