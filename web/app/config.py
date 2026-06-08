from pathlib import Path
from pydantic_settings import BaseSettings

_WEB = Path(__file__).parent.parent
_ROOT = _WEB.parent


class Settings(BaseSettings):
    # Ghidra 12.0.4 (apt-managed). NOTE: Ghidra 12.1 has a regression with our
    # DumpClassData.java post-script (class loader change) — do not bump until
    # the script is updated to satisfy the new "public class == filename" rule.
    # some-class IPAs (dyld chained-fixups with null import) fail on BOTH 12.0.4
    # and 12.1 — that is a separate upstream Mach-O parser bug.
    ghidra_home: str = "/usr/share/ghidra"
    cli_jar: str = str(_ROOT / "cli/target/mailmite-cli.jar")
    scan_dir: Path = Path("/tmp/mailmite-scans")
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

    model_config = {"env_file": str(_WEB / ".env"), "env_file_encoding": "utf-8"}


settings = Settings()
