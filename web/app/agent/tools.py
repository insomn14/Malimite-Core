"""Tools the assistant can call. All read-only over the scan DB; output is untrusted data."""
import json
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from .. import db, offensive_phases
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
    _spec("get_assessments", "The scan's Security Assessment: an inventory of protective controls (root/jailbreak, Frida, "
          "anti-debug, SSL pinning, FLAG_SECURE, backup, debuggable, obfuscation, ...), each PRESENT / PARTIAL / ABSENT / "
          "UNKNOWN with a confidence. ALWAYS use this for 'is control X implemented?' instead of inferring it from code "
          "search. UNKNOWN or LOW confidence means inconclusive, not absent.",
          {"status": {"type": "string", "enum": ["PRESENT", "PARTIAL", "ABSENT", "UNKNOWN"]}, "category": _S}),
    _spec("get_manifest", "App configuration as scanned. Android: package/SDK/debuggable/backup, permissions, components "
          "(with exported flag), deep links, native libraries. iOS: bundle/team/provisioning, Info.plist, entitlements "
          "(mobileprovision), Mach-O flags. Call without `section` for an overview and the list of sections; then ask for one.",
          {"section": _S, "query": _S, "limit": _I, "offset": _I}),
    _spec("decompile", "Fresh on-demand decompilation of ONE class. asc = fast (Android only), jadx = slower "
          "(Android only), ghidra = native binary function (iOS Mach-O, or Android .so with `lib`; target is a "
          "function name substring or 0x address; first call per scan is slow). Results are cached. Use only when "
          "get_source is missing/garbled or a second opinion is requested.",
          {"tool": {"type": "string", "enum": ["asc", "jadx", "ghidra"]}, "target": _S, "lib": _S, "offset": _I},
          ["tool", "target"]),
    _spec("recommend_hook_targets", "Recon-only ranking of symbols worth a Frida hook, for AUTHORIZED pentest work "
          "on THIS app. Built deterministically (no LLM call) from this scan's vulnerabilities and Security "
          "Assessment (SSL pinning, root/jailbreak detection, anti-debug, crypto/keychain). Does NOT generate a "
          "Frida script (the UI's Offensive Frida kit does that) — this only says where to look and why, with a "
          "confidence: HIGH = known symbol plus a call graph (who calls it), MEDIUM = known symbol but no call "
          "graph, LOW = only assessment text evidence, no symbol. Call this instead of guessing from get_source "
          "when asked where to hook for a bypass.",
          {"category": {"type": "string",
                         "enum": ["ROOT_DETECTION", "JAILBREAK", "SSL_PINNING", "CRYPTO", "BIOMETRIC"]},
           "limit": _I}),
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
_STATUS_ORDER = {"PRESENT": 0, "PARTIAL": 1, "ABSENT": 2, "UNKNOWN": 3}


async def _assessments(ctx: Ctx, a: dict) -> str:
    rows = await db.get_assessments_brief(ctx.db_path, ctx.exe)
    if rows is None:
        return ("This scan has no Security Assessment (it was disabled or the scan predates the feature). "
                "Do not conclude that controls are absent; use search_code / get_source, and say it is unverified.")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    want, cat = (a.get("status") or "").upper(), (a.get("category") or "").upper()
    shown = [r for r in rows if (not want or r["status"] == want) and (not cat or (r["category"] or "").upper() == cat)]
    shown.sort(key=lambda r: (_STATUS_ORDER.get(r["status"], 9), r["category"] or "", r["control_id"]))
    notes = []
    if any(r["control_id"] == "ASSESS-VM-OBFUSCATION" and r["status"] == "PRESENT" for r in rows):
        notes.append("The code runs inside a bytecode interpreter: checks may be hidden in the bytecode, so UNKNOWN "
                     "detection controls (jailbreak/root, Frida, anti-debug) must not be reported as absent.")
    if counts.get("UNKNOWN"):
        notes.append("UNKNOWN = the scanner could not decide. Report it as unknown, never as absent or present.")
    return _j({
        "counts_all_controls": counts,   # whole inventory, regardless of the status/category filter
        "controls": [{"id": r["control_id"], "title": r["title"], "category": r["category"], "status": r["status"],
                      "confidence": r["confidence"], "evidence": (r["evidence"] or "")[:300],
                      **({"detail": r["detail"]} if r["detail"] else {})} for r in shown],
        "notes": notes,
    })


# Scan metadata worth showing the model. Paths (dbPath, packagePath, ...) are deliberately not on the list.
_META_KEYS = ("platform", "packageName", "applicationId", "bundleIdentifier", "versionName", "versionCode", "minSdk",
              "targetSdk", "debuggable", "allowBackup", "architectures", "isSwift", "bundleTeamId",
              "provisioningProfile", "provisioningExpiry", "dexCount", "nativeLibCount", "scanScope")

# section -> (ResourceStrings types, one-line description)
_SECTIONS = {
    "ANDROID": {
        "permissions": (["manifest-permission"], "requested permissions"),
        "components": (["manifest-component"], "activities/services/receivers/providers with exported=true|false"),
        "deeplinks": (["manifest-deeplink"], "intent-filter deep links (scheme/host/path/component)"),
        "native_libs": (["native-lib", "native-elf"], "packaged .so files and ELF hardening notes"),
        "config": (["manifest"], "package, SDK levels, debuggable, allowBackup, network security config"),
        "assets": (["asset"], "packaged assets"),
    },
    "IOS": {
        "info_plist": (["plist"], "Info.plist / plist lines (one row per line)"),
        "entitlements": (["mobileprovision"], "embedded.mobileprovision lines: entitlements, team, expiry"),
        "macho_flags": (["macho-flags"], "Mach-O flags (PIE, ...)"),
        "nibs": (["nib"], "storyboard/nib resources"),
    },
}


_GENERIC_LABELS = {"Component", "Permission", "DeepLink", "AssetPath"}


def _entry(e: dict) -> str:
    """Android rows are (class, 'activity:<same class>'): show them once; iOS rows are (class, selector)."""
    cls, fn = e["class"] or "", e["function"] or ""
    if cls and fn.split(":", 1)[-1] == cls:
        return fn
    return f"{cls}.{fn}" if cls else fn


def _row(r: dict) -> str:
    """One readable line: constant labels are dropped, file paths are shortened to their last two parts."""
    rid, val = r["id"] or "", r["value"] or ""
    if "/" in rid:
        return f"{'/'.join(rid.rstrip('/').split('/')[-2:])}: {val}"
    if val.startswith(rid) or rid in _GENERIC_LABELS:
        return val
    return f"{rid}={val}"


async def _manifest(ctx: Ctx, a: dict) -> str:
    plat = "IOS" if ctx.platform.upper() == "IOS" else "ANDROID"
    sections = _SECTIONS[plat]
    section = (a.get("section") or "").strip().lower()
    counts = await db.resource_type_counts(ctx.db_path)
    if not section or section == "overview":
        meta = {k: ctx.meta[k] for k in _META_KEYS if k in ctx.meta and ctx.meta[k] not in (None, "", [])}
        config = []
        if plat == "ANDROID":
            _, cfg = await db.get_resources_by_type(ctx.db_path, ["manifest"], "", 40, 0)
            config = [_row(r) for r in cfg]
        eps = await db.get_entry_points_ro(ctx.db_path, ctx.exe)
        return _j({
            "platform": plat, "metadata": meta, "config": config,
            "entry_points": [_entry(e) for e in eps][:30],
            "sections": {k: {"rows": sum(counts.get(t, 0) for t in v[0]), "what": v[1]} for k, v in sections.items()},
            "usage": "call get_manifest(section=<name>, query=<substring>, limit, offset) for the rows",
        })
    if section not in sections:
        return f"unknown section '{section}' for {plat}; available: {', '.join(sections)}"
    types, _ = sections[section]
    limit = max(1, min(int(a.get("limit", 30)), 100))
    offset = max(int(a.get("offset", 0)), 0)
    total, rows = await db.get_resources_by_type(ctx.db_path, types, a.get("query") or "", limit, offset)
    nxt = offset + len(rows)
    return _j({"section": section, "total_matching": total, "offset": offset,
               "rows": [_row(r) for r in rows],
               **({"next_offset": nxt} if nxt < total else {})})


_HOOK_NOTE = "Recon-only recommendation for AUTHORIZED testing; verify manually before hooking anything."
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_CONF_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


async def _hook_targets(ctx: Ctx, a: dict) -> str:
    candidates = await db.get_candidate_symbols(ctx.db_path, ctx.exe)
    if not candidates:
        return _j({"targets": [], "note": "No bypass-relevant vulnerability or Security Assessment signal in this "
                   "scan. This does not mean the app has no such control, only that nothing was detected. " + _HOOK_NOTE})
    have_refs = await db.has_references(ctx.db_path)
    want = (a.get("category") or "").upper().replace("-", "_")
    limit = max(1, min(int(a.get("limit", 20)), 50))
    targets = []
    for c in candidates:
        if want and c["bucket"] != want:
            continue
        callers = await db.get_references(ctx.db_path, ctx.exe, c["symbol"], "callers") \
            if c["has_symbol"] and have_refs else []
        confidence = "HIGH" if callers else ("MEDIUM" if c["has_symbol"] else "LOW")
        targets.append({
            "symbol": c["symbol"], "class": c["class"], "category": c["bucket"],
            "phase": offensive_phases.normalize_phase({"category": c["bucket"]}),
            "confidence": confidence, "severity": c["severity"], "source": c["source"], "rule_id": c["rule_id"],
            "evidence": c["evidence"], "callers": [f"{r['class']}.{r['function']}" for r in callers[:5]],
        })
    targets.sort(key=lambda t: (_SEV_ORDER.get(t["severity"] or "INFO", 5), _CONF_ORDER.get(t["confidence"], 9)))
    return _j({"targets": targets[:limit], "note": _HOOK_NOTE})


_RUN: dict[str, Callable[[Ctx, dict], Awaitable[str]]] = {
    "scan_overview": _overview, "list_classes": _list_classes, "search_code": _search_code,
    "get_source": _get_source, "search_strings": _search_strings, "get_vulnerabilities": _vulns,
    "get_references": _refs, "get_assessments": _assessments, "get_manifest": _manifest, "decompile": _decompile,
    "recommend_hook_targets": _hook_targets,
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
