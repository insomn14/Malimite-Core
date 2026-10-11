from pathlib import Path
from pydantic_settings import BaseSettings

_WEB = Path(__file__).parent.parent
_ROOT = _WEB.parent


class Settings(BaseSettings):
    # Ghidra 12.0.4 (apt-managed). NOTE: Ghidra 12.1 has a regression with our
    # DumpClassData.java post-script (class loader change) — do not bump until
    # the script is updated to satisfy the new "public class == filename" rule.
    # Krom-class IPAs (dyld chained-fixups with null import) fail on BOTH 12.0.4
    # and 12.1 — that is a separate upstream Mach-O parser bug.
    ghidra_home: str = "/usr/share/ghidra"
    cli_jar: str = str(_ROOT / "cli/target/malimite-cli.jar")
    scan_dir: Path = Path("/tmp/malimite-scans")
    host: str = "0.0.0.0"
    port: int = 7070

    # optional auth — empty means no auth
    api_key: str = ""

    # LLM defaults (can be overridden per request)
    llm_provider: str = "none"
    llm_mode: str = "summarize"
    llm_model: str = ""
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    ollama_base_url: str = "http://localhost:11434"

    # AI Assistant (chat agent)
    chat_max_turns: int = 20
    chat_max_output_tokens: int = 8192  # per LLM call; on deepseek this also covers hidden reasoning tokens
    chat_max_continuations: int = 8     # auto-continue an answer cut off by the output limit
    chat_tool_cap: int = 12000          # max chars returned to the model per tool call
    chat_rate_per_min: int = 30         # global cap on chat requests/min: each one spends the server's LLM quota
    heavy_concurrency: int = 1          # concurrent on-demand decompile subprocesses
    ghidra_ondemand_timeout: int = 5400  # > Java import cap (60 min) so a big first import can finish

    model_config = {"env_file": str(_WEB / ".env"), "env_file_encoding": "utf-8"}


settings = Settings()
