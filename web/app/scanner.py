"""Manages scan lifecycle: create, run CLI JAR, persist state."""
import asyncio
import json
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import settings
from .models import ScanDetail, ScanMeta

log = logging.getLogger(__name__)

# Pre-rename default (Mailmite → Malimite). Migrated into settings.scan_dir on access.
_LEGACY_SCAN_DIRS = (Path("/tmp/mailmite-scans"),)


# ── helpers ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scan_dir(scan_id: str) -> Path:
    return settings.scan_dir / scan_id


def _meta_path(scan_id: str) -> Path:
    return _scan_dir(scan_id) / "meta.json"


def _read_meta(scan_id: str) -> Optional[dict]:
    p = _meta_path(scan_id)
    if not p.exists():
        return None
    return json.loads(p.read_text())


def _write_meta(scan_id: str, meta: dict) -> None:
    _meta_path(scan_id).write_text(json.dumps(meta, indent=2))


_PATH_KEYS = ("dbPath", "ipaPath", "packagePath")


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except (OSError, ValueError):
        return False


def _remap_legacy_path(raw: str, scan_dir: Path) -> Optional[str]:
    """Map a pre-rename /tmp/mailmite-scans path onto the current scan dir.

    Returns the remapped path only when it stays inside the scan directory and
    the target file exists. Existing valid paths are returned unchanged.
    """
    if not raw:
        return None
    path = Path(raw)
    if path.exists() and _is_under(path, scan_dir):
        return str(path)
    for legacy in _LEGACY_SCAN_DIRS:
        try:
            rel = path.resolve(strict=False).relative_to(legacy.resolve())
        except (OSError, ValueError):
            continue
        mapped = (settings.scan_dir / rel).resolve()
        if mapped.exists() and _is_under(mapped, scan_dir):
            return str(mapped)
    return str(path) if path.exists() and _is_under(path, scan_dir) else None


def _discover_sqlite(scan_dir: Path) -> Optional[str]:
    matches = sorted(
        p for p in scan_dir.glob("*.sqlite")
        if p.is_file() and not p.name.endswith(("-wal", "-shm"))
    )
    if len(matches) == 1 and _is_under(matches[0], scan_dir):
        return str(matches[0])
    return None


def _rewrite_legacy_scan_json(scan_id: str, data: dict) -> dict:
    """Rewrite stale Mailmite paths in scan.json and persist when they change."""
    scan_dir = _scan_dir(scan_id)
    changed = False
    for key in _PATH_KEYS:
        raw = data.get(key)
        if not isinstance(raw, str) or not raw:
            continue
        mapped = _remap_legacy_path(raw, scan_dir)
        if mapped and mapped != raw:
            data[key] = mapped
            changed = True
    if not data.get("dbPath") or not Path(str(data.get("dbPath"))).exists():
        found = _discover_sqlite(scan_dir)
        if found and data.get("dbPath") != found:
            data["dbPath"] = found
            changed = True
    if changed:
        p = scan_dir / "scan.json"
        try:
            p.write_text(json.dumps(data, indent=2) + "\n")
            log.info("Rewrote legacy scan paths in %s", p)
        except OSError as e:
            log.warning("Could not persist rewritten scan.json for %s: %s", scan_id, e)
    return data


def _read_scan_json(scan_id: str) -> Optional[dict]:
    p = _scan_dir(scan_id) / "scan.json"
    if not p.exists():
        return None
    data = json.loads(p.read_text())
    if isinstance(data, dict):
        return _rewrite_legacy_scan_json(scan_id, data)
    return data


def migrate_legacy_scan_dirs() -> int:
    """Move scan folders from legacy Mailmite paths into settings.scan_dir.

    Returns the number of scan directories migrated. Safe to call repeatedly.
    """
    settings.scan_dir.mkdir(parents=True, exist_ok=True)
    moved = 0
    try:
        dest_root = settings.scan_dir.resolve()
    except OSError:
        dest_root = settings.scan_dir

    for legacy in _LEGACY_SCAN_DIRS:
        try:
            if not legacy.exists() or not legacy.is_dir():
                continue
            if legacy.resolve() == dest_root:
                continue
        except OSError:
            continue
        for child in list(legacy.iterdir()):
            if not child.is_dir():
                continue
            dest = settings.scan_dir / child.name
            if dest.exists():
                continue
            try:
                shutil.move(str(child), str(dest))
                moved += 1
            except OSError as e:
                log.warning("Failed to migrate scan %s from %s: %s", child.name, legacy, e)
        # Remove empty legacy root when possible
        try:
            if legacy.exists() and not any(legacy.iterdir()):
                legacy.rmdir()
        except OSError:
            pass
    if moved:
        log.info("Migrated %d scan(s) from legacy Mailmite scan dirs → %s", moved, settings.scan_dir)
    rewritten = 0
    if settings.scan_dir.exists():
        for child in settings.scan_dir.iterdir():
            if child.is_dir() and (child / "scan.json").exists():
                before = (child / "scan.json").read_text()
                _read_scan_json(child.name)
                try:
                    if (child / "scan.json").read_text() != before:
                        rewritten += 1
                except OSError:
                    pass
    if rewritten:
        log.info("Rewrote legacy db/ipa paths in %d scan.json file(s)", rewritten)
    return moved


# ── public API ────────────────────────────────────────────────────────────────

def list_scans() -> list[ScanMeta]:
    migrate_legacy_scan_dirs()
    if not settings.scan_dir.exists():
        return []
    result = []
    for d in sorted(settings.scan_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        m = _read_meta(d.name)
        if m:
            result.append(ScanMeta(**m))
    return result


def get_scan_detail(scan_id: str) -> Optional[ScanDetail]:
    meta = _read_meta(scan_id)
    if not meta:
        return None
    detail = ScanDetail(**meta)
    scan_json = _read_scan_json(scan_id)
    if scan_json:
        detail.bundle_id = scan_json.get("bundleIdentifier")
        detail.bundle_executable = scan_json.get("bundleExecutable")
        detail.platform = scan_json.get("platform")
        detail.is_swift = scan_json.get("isSwift")
        detail.is_universal = scan_json.get("isUniversal")
        detail.architectures = scan_json.get("architectures", [])
        detail.db_path = scan_json.get("dbPath")
        detail.ipa_path = scan_json.get("ipaPath") or scan_json.get("packagePath")
        detail.team_id = scan_json.get("bundleTeamId")
        detail.provisioning_profile = scan_json.get("provisioningProfile")
        detail.provisioning_expiry = scan_json.get("provisioningExpiry")
        detail.min_sdk = scan_json.get("minSdk")
        detail.target_sdk = scan_json.get("targetSdk")

    d = _scan_dir(scan_id)
    detail.has_sarif = (d / "findings.sarif").exists()
    detail.has_html = (d / "report.html").exists()
    detail.has_log = (d / "analysis.log").exists()

    # DB counts filled lazily by caller when needed
    return detail


def delete_scan(scan_id: str) -> bool:
    d = _scan_dir(scan_id)
    if not d.exists():
        return False
    import shutil
    shutil.rmtree(d)
    return True


async def regenerate_report(scan_id: str) -> bool:
    """
    Re-build report.html and findings.sarif for the given scan from its current
    SQLite state. Returns True on success. Used after triage updates so reports
    reflect reviewer decisions immediately.
    """
    d = _scan_dir(scan_id)
    if not d.exists():
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            "java", "-cp", settings.cli_jar,
            "io.malimite.core.ReportRenderer", str(d),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            import logging as _logging
            _logging.getLogger("malimite").warning(
                "ReportRenderer failed for %s (rc=%s): %s",
                scan_id, proc.returncode, stderr.decode("utf-8", "replace")[:500])
            return False
        return True
    except Exception as exc:
        import logging as _logging
        _logging.getLogger("malimite").warning(
            "ReportRenderer subprocess error for %s: %s", scan_id, exc)
        return False


async def create_scan(
    ipa_bytes: bytes,
    filename: str,
    llm_enabled: bool,
    llm_provider: str,
    llm_mode: str,
    llm_model: str,
    llm_api_key: str = "",
    assessment_enabled: bool = True,
) -> ScanMeta:
    migrate_legacy_scan_dirs()
    settings.scan_dir.mkdir(parents=True, exist_ok=True)
    scan_id = str(uuid.uuid4())
    d = _scan_dir(scan_id)
    d.mkdir(parents=True)

    ext = ".apk" if filename.lower().endswith(".apk") else ".ipa"
    ipa_path = d / f"upload{ext}"
    ipa_path.write_bytes(ipa_bytes)

    meta = {
        "scan_id": scan_id,
        "filename": filename,
        "state": "queued",
        "created_at": _now(),
        "started_at": None,
        "finished_at": None,
        "exit_code": None,
        "llm_enabled": llm_enabled,
        "llm_provider": llm_provider,
        "llm_mode": llm_mode,
        "llm_model": llm_model,
        "assessment_enabled": assessment_enabled,
        # not exposed in ScanMeta — only used internally by _run
        "_llm_api_key": llm_api_key,
    }
    _write_meta(scan_id, meta)
    asyncio.create_task(_run(scan_id, ipa_path, d, meta))
    return ScanMeta(**{k: v for k, v in meta.items() if not k.startswith("_")})


# ── CLI argv ──────────────────────────────────────────────────────────────────

def _cli_cmd(ipa_path: Path, out_dir: Path, meta: dict) -> list[str]:
    """Build malimite-cli argv. Scan scope comes from --llm-mode even when LLM is off."""
    mode = (meta.get("llm_mode") or "summarize").strip() or "summarize"
    cmd = [
        "java", "-jar", settings.cli_jar,
        str(ipa_path),
        "--ghidra", settings.ghidra_home,
        "--out", str(out_dir),
        "--sarif",
        "--html",
        "--llm-mode", mode,
    ]
    if meta.get("llm_enabled") and meta.get("llm_provider") not in ("none", "", None):
        cmd += ["--llm", "--llm-provider", meta["llm_provider"]]
        if meta.get("llm_model"):
            cmd += ["--llm-model", meta["llm_model"]]
    # Default CLI assessment=true; omit the flag when enabled so older picocli
    # jars with inverted --assessment polarity cannot disable the scan.
    if not meta.get("assessment_enabled", True):
        cmd += ["--no-assessment"]
    return cmd


# ── background runner ─────────────────────────────────────────────────────────

async def _run(scan_id: str, ipa_path: Path, out_dir: Path, meta: dict) -> None:
    meta["state"] = "running"
    meta["started_at"] = _now()
    _write_meta(scan_id, meta)

    cmd = _cli_cmd(ipa_path, out_dir, meta)

    env = dict(os.environ)
    # Per-request key takes priority over the .env/settings key
    per_req_key = meta.get("_llm_api_key", "")
    provider = meta.get("llm_provider", "none")

    if provider == "openai":
        key = per_req_key or settings.openai_api_key
        if key:
            env["OPENAI_API_KEY"] = key
    elif provider == "claude":
        key = per_req_key or settings.anthropic_api_key
        if key:
            env["ANTHROPIC_API_KEY"] = key
    elif provider == "deepseek":
        key = per_req_key or settings.deepseek_api_key
        if key:
            env["DEEPSEEK_API_KEY"] = key
        if settings.deepseek_base_url:
            env["DEEPSEEK_BASE_URL"] = settings.deepseek_base_url
    elif provider == "ollama":
        env["OLLAMA_BASE_URL"] = settings.ollama_base_url or "http://localhost:11434"

    log_path = out_dir / "analysis.log"
    try:
        with open(log_path, "w") as log_fh:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=log_fh,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
            exit_code = await proc.wait()
    except Exception as exc:
        log_path.write_text(f"Failed to start CLI: {exc}\n")
        exit_code = -1

    meta["state"] = "done" if exit_code == 0 else "error"
    meta["finished_at"] = _now()
    meta["exit_code"] = exit_code
    _write_meta(scan_id, meta)
