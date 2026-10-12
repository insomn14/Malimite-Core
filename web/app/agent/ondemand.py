"""Run io.malimite.core.OnDemandDecompiler as a one-shot subprocess (argv only, no shell)."""
import asyncio
import json
import os
import shutil
import signal
import tempfile
from pathlib import Path

from ..config import settings

_sems: dict = {}


def _sem() -> asyncio.Semaphore:
    """Global limit on heavy decompile subprocesses (one semaphore per running loop)."""
    loop = asyncio.get_running_loop()
    if loop not in _sems:
        _sems.clear()
        _sems[loop] = asyncio.Semaphore(settings.heavy_concurrency)
    return _sems[loop]


_ENV_KEYS = {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "JAVA_HOME"}
_ENV_PREFIXES = ("JADX_", "ASC_", "GHIDRA_")


def _child_env() -> dict:
    """Allowlist: the decompilers parse attacker-supplied APK/IPA content, so they must not see LLM/API keys."""
    return {k: v for k, v in os.environ.items() if k in _ENV_KEYS or k.startswith(_ENV_PREFIXES)}


def _cmd(scan_dir: Path, tool: str, target: str, lib: str, tmp: Path) -> list[str]:
    cmd = ["java", f"-Djava.io.tmpdir={tmp}", "-cp", settings.cli_jar, "io.malimite.core.OnDemandDecompiler",
           str(scan_dir), tool, target]
    if tool == "ghidra":
        cmd += ["--lib", lib] if lib else []
    return cmd


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    # JADX/droidasc/Ghidra are grandchildren of java: kill the whole group, not just java.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


async def decompile(scan_dir: Path, tool: str, target: str, lib: str = "") -> dict:
    """Returns {ok, tool, target, code, error}. Cancellation kills the whole process tree."""
    env = _child_env()
    if tool == "ghidra":
        env["GHIDRA_HOME"] = settings.ghidra_home  # same install the web service gives the scan CLI
    # per-call tmpdir: SIGKILL skips the JVM's finally blocks, so we remove what it extracted ourselves
    tmp = Path(tempfile.mkdtemp(prefix=".od-", dir=scan_dir))
    try:
        async with _sem():
            proc = await asyncio.create_subprocess_exec(
                *_cmd(scan_dir, tool, target, lib, tmp),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env=env, start_new_session=True)
            try:
                out, err = await proc.communicate()
            except BaseException:
                _kill_group(proc)
                raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for line in reversed(out.decode("utf-8", "replace").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                break
    tail = err.decode("utf-8", "replace").strip().splitlines()[-1:] or [f"exit code {proc.returncode}"]
    return {"ok": False, "tool": tool, "target": target, "code": "", "error": f"decompiler failed: {tail[0][:200]}"}
