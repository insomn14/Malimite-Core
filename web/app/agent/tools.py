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


def _spec(name, description, props, required=(), requires_confirmation=False):
    """requires_confirmation is never sent to the provider (see llm.py's anthropic_tools/
    openai_tools: both build the payload from an explicit {name, description, schema} allowlist,
    not **spread) — it is read only by loop.py's run_chat() to decide whether this tool's call
    needs an explicit human approval round-trip before run_tool() actually executes it. Every
    OTHER tool in this module is read-only and runs immediately like before; only a tool with
    this flag set pauses the loop — see loop.py's PENDING_CONFIRMATION handling."""
    return {"name": name, "description": description,
            "schema": {"type": "object", "properties": props, "required": list(required)},
            "requires_confirmation": requires_confirmation}


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
          "Pass rule_id to list every occurrence of one issue — each `evidence` entry's `id` (and the issue's own "
          "top-level `id`, its representative occurrence) is the exact vuln_id apply_triage expects; never guess one.",
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
    _spec("propose_finding",
          "Adds a NEW finding to the Vulnerabilities tab, grounded in what was found during this conversation "
          "(e.g. the user asked you to investigate something and you found a real issue that no scan rule "
          "caught). This WRITES to the scan and always pauses for the user's explicit confirmation before "
          "anything is saved — you will see the result only after they approve or decline, never silently. "
          "Only call this for a concrete, evidence-backed issue you can point to specific code/evidence for; "
          "never to restate an EXISTING finding (use get_vulnerabilities to check for rule_id/title overlap "
          "first — if it's already there, discuss apply_triage on that one instead of a duplicate). "
          "description/evidence/poc_steps/remediation MUST read exactly like a scan-engine or AI Fix "
          "finding would — same terse, structured report style, not a conversational summary of the chat. "
          "Follow each field's own format rule below exactly; never speculative, never longer than asked.",
          {"title": _S, "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
           "cvss_score": {"type": "number"}, "cwe": _S, "category": _S,
           "description": {"type": "string", "description":
               "1-3 sentences stating what the vulnerability is and why it's exploitable in THIS app — "
               "same length/tone as an AI Fix description, not a narrative of how it was found in chat."},
           "evidence": {"type": "string", "description":
               "One concrete short snippet (code line, string, config value) under 300 characters, grounded "
               "in what was actually gathered — not a paragraph explaining the evidence."},
           "poc_steps": {"type": "string", "description":
               "Newline-separated numbered steps, e.g. \"1. step one\\n2. step two\\n3. step three\" — concrete "
               "and specific to this finding, each step a single short action, not prose paragraphs."},
           "remediation": {"type": "string", "description":
               "1-3 sentences of concrete, actionable fix guidance specific to this finding/evidence — same "
               "terse style as the other fields, not a design essay."},
           "reference_url": _S, "affected_class": _S, "affected_function": _S},
          ["title", "severity", "description"], requires_confirmation=True),
    _spec("apply_triage",
          "Changes ONE finding's review status, severity/CVSS override, or reviewer note — same effect as a "
          "human editing it in the Vulnerabilities tab's Triage form. This WRITES to the scan and always pauses "
          "for the user's explicit confirmation before anything is saved. vuln_id MUST be a real id from "
          "get_vulnerabilities (or from the finding the user opened this chat to discuss, if one was provided) "
          "— if you are not certain which finding the user means, call get_vulnerabilities first and ask, never "
          "guess an id. Only set the fields the user actually asked to change; leave the rest unset.",
          {"vuln_id": _I, "status": {"type": "string",
                                      "enum": ["open", "false_positive", "accepted_risk", "fixed"]},
           "override_severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", ""]},
           "override_cvss_score": {"type": "number"}, "note": _S},
          ["vuln_id"], requires_confirmation=True),
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
        for g in issues:  # a specific rule was asked for: show every occurrence, each with its own id
            # (apply_triage's vuln_id — see tools.py's _spec() — targets ONE occurrence, which may not
            # be the representative; get_vulnerabilities_brief() guarantees "id" on every row for this)
            g["evidence"] = [{"id": r["id"], "where": r["affected_name"], "evidence": (r["evidence"] or "")[:200]}
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


_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_STATUSES = {"open", "false_positive", "accepted_risk", "fixed"}

# Observed live (claude-sonnet-5 via claude-oauth): a long free-text tool argument can end with
# the model's own tool-call syntax bleeding into the string value, e.g. description ending in
# `...the key-hardcoding issue.</description>\n<parameter name="evidence">new SecretKeySpec(...`
# — a malformed-but-syntactically-valid JSON string the provider still sends as the argument.
# The confirmation UI shows the raw value before a human approves, but this is defense in depth:
# a confirmed-but-corrupted call must still fail loudly here rather than writing a report field
# that silently ends mid-sentence with leaked internal syntax. Matches regardless of which XML
# tool-call dialect leaked (Anthropic's own old XML format and others look similar enough that a
# narrow Claude-only pattern isn't worth the fragility).
_TOOL_SYNTAX_LEAK_RE = re.compile(
    r"</\s*(?:parameter|function_calls?|invoke|tool_call|antml:invoke|antml:parameter)\s*>"
    r"|<\s*(?:parameter|function_calls?|invoke|tool_call|antml:invoke|antml:parameter)\b",
    re.IGNORECASE,
)


def _reject_tool_syntax_leak(value: Optional[str], field: str) -> None:
    if value and _TOOL_SYNTAX_LEAK_RE.search(value):
        raise ValueError(
            f"{field} looks corrupted — it contains tool-call syntax that leaked into the text "
            f"(e.g. '</parameter>' or '<invoke'). This usually means the model's response got "
            f"garbled; nothing was saved. Try again, possibly with a shorter/simpler request.")


async def _propose_finding(ctx: Ctx, a: dict) -> str:
    """Only reachable after the user confirms (see loop.py) — by the time this runs, args have
    already been shown to them verbatim and approved. Still validates: a confirmed-but-malformed
    call (model sent a bad enum value despite the schema) must fail loudly, not insert garbage.
    """
    title = (a.get("title") or "").strip()
    if not title:
        raise ValueError("title is required")
    severity = str(a.get("severity") or "").upper()
    if severity not in _SEVERITIES:
        raise ValueError(f"severity must be one of {sorted(_SEVERITIES)}")
    description = (a.get("description") or "").strip()
    if not description:
        raise ValueError("description is required")
    cvss = a.get("cvss_score")
    if cvss is not None:
        cvss = float(cvss)
        if not (0.0 <= cvss <= 10.0):
            raise ValueError("cvss_score must be between 0.0 and 10.0")
    for field in ("title", "description", "evidence", "poc_steps", "remediation", "cwe",
                  "category", "reference_url", "affected_class", "affected_function"):
        _reject_tool_syntax_leak(a.get(field), field)
    new_id = await db.insert_vulnerability_manual(
        ctx.db_path, ctx.exe,
        title=title, severity=severity, cvss_score=cvss,
        cwe=a.get("cwe") or None, category=a.get("category") or None,
        description=description, evidence=a.get("evidence") or None,
        poc_steps=a.get("poc_steps") or None, remediation=a.get("remediation") or None,
        reference_url=a.get("reference_url") or None,
        affected_type="FUNCTION" if a.get("affected_function") else ("CLASS" if a.get("affected_class") else None),
        affected_name=a.get("affected_function") or a.get("affected_class") or None,
    )
    return _j({"ok": True, "vuln_id": new_id, "title": title, "severity": severity,
              "note": "Added to the Vulnerabilities tab (id={}). Tell the user it's there.".format(new_id)})


async def _apply_triage(ctx: Ctx, a: dict) -> str:
    """Same confirmed-before-reaching-here contract as _propose_finding() — see loop.py."""
    vuln_id = a.get("vuln_id")
    if not isinstance(vuln_id, int):
        raise ValueError("vuln_id must be an integer")
    row = await db.get_vulnerability_row(ctx.db_path, ctx.exe, vuln_id)
    if row is None:
        raise ValueError(f"no finding with id={vuln_id} in this scan")
    status = a.get("status")
    if status is not None and status not in _STATUSES:
        raise ValueError(f"status must be one of {sorted(_STATUSES)}")
    override_severity = a.get("override_severity")
    if override_severity is not None and override_severity != "" and override_severity.upper() not in _SEVERITIES:
        raise ValueError(f"override_severity must be one of {sorted(_SEVERITIES)} or empty to clear")
    cvss = a.get("override_cvss_score")
    if cvss is not None:
        cvss = float(cvss)
        if not (0.0 <= cvss <= 10.0):
            raise ValueError("override_cvss_score must be between 0.0 and 10.0")
    _reject_tool_syntax_leak(a.get("note"), "note")
    ok = await db.update_vulnerability_triage(
        ctx.db_path, vuln_id,
        status=status,
        override_severity=override_severity.upper() if override_severity else override_severity,
        override_cvss_score=cvss,
        override_note=a.get("note"),
    )
    if not ok:
        raise ValueError(f"no finding with id={vuln_id} in this scan")
    return _j({"ok": True, "vuln_id": vuln_id,
              "note": "Triage updated. Tell the user what changed."})


_RUN: dict[str, Callable[[Ctx, dict], Awaitable[str]]] = {
    "scan_overview": _overview, "list_classes": _list_classes, "search_code": _search_code,
    "get_source": _get_source, "search_strings": _search_strings, "get_vulnerabilities": _vulns,
    "get_references": _refs, "get_assessments": _assessments, "get_manifest": _manifest, "decompile": _decompile,
    "recommend_hook_targets": _hook_targets,
    "propose_finding": _propose_finding, "apply_triage": _apply_triage,
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
