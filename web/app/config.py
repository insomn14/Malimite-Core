from pathlib import Path
from pydantic_settings import BaseSettings

_WEB = Path(__file__).parent.parent
_ROOT = _WEB.parent


class Settings(BaseSettings):
    # Ghidra 12.0.4 (apt-managed). NOTE: Ghidra 12.1 has a regression with our
    # DumpClassData.java post-script (class loader change) — do not bump until
    # the script is updated to satisfy the new "public class == filename" rule.
    # Some dyld chained-fixups-with-null-import IPAs fail on BOTH 12.0.4
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
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = "us-east-1"
    bedrock_model_id: str = ""
    glm_api_key: str = ""
    glm_base_url: str = "https://open.bigmodel.cn/api/paas/v4"

    # Config tab: where the "Your LLM Providers" page persists API keys/settings entered
    # through the UI (POST /api/v1/config/providers), so a user never has to re-paste a
    # key into the upload form again. Same mount/ownership story as anthropic_oauth_path
    # (shared ~/.malimite-docker volume, 0600, atomic write) — see agent/llm_config.py.
    # Values stored here take priority over the *_API_KEY env vars above, which remain a
    # valid bootstrap/CI path (operator-managed, no UI interaction needed).
    llm_config_path: str = str(Path.home() / ".malimite" / "llm-config.json")

    # Anthropic OAuth (Claude Pro/Max subscription usage, no ANTHROPIC_API_KEY needed).
    # Written by `java -jar cli/target/malimite-cli.jar claude-login` (run wherever a
    # browser is available — see AnthropicOAuthCredentials.java for the same path
    # convention on the Java side). In the shipped web-compose.yml this resolves to the
    # shared ~/.malimite-docker mount at /home/malimite/.malimite/anthropic-oauth.json.
    anthropic_oauth_path: str = str(Path.home() / ".malimite" / "anthropic-oauth.json")

    # Where to auto-detect an already-completed `claude /login` session for the
    # "Import from Claude Code CLI" button / `malimite claude-login --import`.
    # Defaults to the official claude CLI's own file; web-compose.yml overrides
    # this to a synced copy (see sync-claude-oauth.sh) because the real file is
    # 0600 and owned by the host uid, unreadable by the container's own uid.
    claude_code_credentials_path: str = str(Path.home() / ".claude" / ".credentials.json")

    # AI Assistant (chat agent)
    chat_max_turns: int = 20
    chat_max_output_tokens: int = 8192  # per LLM call; on deepseek this also covers hidden reasoning tokens
    chat_max_continuations: int = 8     # auto-continue an answer cut off by the output limit
    chat_tool_cap: int = 12000          # max chars returned to the model per tool call
    chat_rate_per_min: int = 30         # global cap on chat requests/min: each one spends the server's LLM quota
    chat_message_max_chars: int = 50000     # per-field cap on the user's own typed text (DeepSeek-Harness-sized)
    chat_attachment_max_chars: int = 50000  # per text/code file attachment
    chat_attachment_max_image_bytes: int = 5 * 1024 * 1024  # per image attachment, pre-base64 (5 MiB)
    chat_attachment_max_count: int = 5      # max attachments (text + image combined) per message
    heavy_concurrency: int = 1          # concurrent on-demand decompile subprocesses
    auto_enhance_concurrency: int = 2   # parallel LLM calls inside one Auto Enhance (bulk AI Fix) job
    ghidra_ondemand_timeout: int = 5400  # > Java import cap (60 min) so a big first import can finish

    # Full scans (POST /scans): each one spawns its own Ghidra/JADX subprocess with its own JVM
    # heap, so unbounded concurrency here is the single biggest way to OOM the host — unlike
    # heavy_concurrency above (cheap on-demand single-function decompiles), a full scan can run
    # for minutes and use several GB. Requests beyond this limit queue (state stays "queued")
    # rather than being rejected, so a burst of CI uploads doesn't need its own retry logic.
    max_concurrent_scans: int = 3
    # Separate from chat_rate_per_min (LLM quota): this caps raw scan *starts* regardless of LLM
    # usage, so one team/pipeline can't flood the queue with uploads. 0 disables the limit.
    scan_rate_per_min: int = 30

    # Scans accumulate on disk with no automatic cleanup otherwise — a single scan can be well
    # over 1GB (Ghidra project + decompiled source + sqlite), so a server fed continuously by CI
    # pipelines will eventually fill its disk without this. 0 disables retention entirely (keep
    # every scan forever — the previous, and still-default-safe, behavior). Checked once at
    # startup and then on a daily timer (see main.py's lifespan) — not aggressive enough to need
    # finer-grained scheduling.
    scan_retention_days: int = 0

    model_config = {"env_file": str(_WEB / ".env"), "env_file_encoding": "utf-8"}


settings = Settings()
