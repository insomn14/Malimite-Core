package io.malimite.core;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;
import java.util.function.Supplier;

/**
 * On-disk record of an Anthropic OAuth token pair (access + refresh), the
 * same shape Claude Code itself persists after {@code claude /login}.
 *
 * <p>Stored at {@code ~/.malimite/anthropic-oauth.json} with {@code 0600}
 * permissions where POSIX permissions are supported. This file is a bearer
 * credential: anyone who reads it can act as your Claude Pro/Max session
 * until the refresh token is revoked.</p>
 *
 * <p>{@code expiresAtMillis} already has Anthropic's own 5-minute safety
 * margin baked in by the exchange/refresh call that produced it (see
 * {@link AnthropicOAuthLogin}), so callers just compare it to
 * {@link System#currentTimeMillis()} with no extra slack needed.</p>
 */
public final class AnthropicOAuthCredentials {

    private static final Logger log = LoggerFactory.getLogger(AnthropicOAuthCredentials.class);

    public final String accessToken;
    public final String refreshToken;
    public final long   expiresAtMillis;

    public AnthropicOAuthCredentials(String accessToken, String refreshToken, long expiresAtMillis) {
        this.accessToken     = accessToken;
        this.refreshToken    = refreshToken;
        this.expiresAtMillis = expiresAtMillis;
    }

    /** True once we're inside the expiry margin and a refresh is due. */
    public boolean isExpired() {
        return System.currentTimeMillis() >= expiresAtMillis;
    }

    public static Path storePath() {
        String home = System.getProperty("user.home");
        return Path.of(home, ".malimite", "anthropic-oauth.json");
    }

    /** Returns {@code null} when no credential has been stored yet. */
    public static AnthropicOAuthCredentials load() {
        Path path = storePath();
        if (!Files.isRegularFile(path)) return null;
        try {
            String raw = Files.readString(path, StandardCharsets.UTF_8);
            JSONObject obj = new JSONObject(raw);
            return new AnthropicOAuthCredentials(
                    obj.getString("access_token"),
                    obj.getString("refresh_token"),
                    obj.getLong("expires_at_millis"));
        } catch (Exception e) {
            log.warn("Failed to read {}: {}", path, e.toString());
            return null;
        }
    }

    /**
     * Atomically writes this credential to {@link #storePath()}, creating the
     * parent directory if needed and restricting permissions to the owner
     * where the filesystem supports POSIX permissions.
     */
    public void save() throws IOException {
        Path path = storePath();
        Files.createDirectories(path.getParent());

        JSONObject obj = new JSONObject()
                .put("access_token", accessToken)
                .put("refresh_token", refreshToken)
                .put("expires_at_millis", expiresAtMillis);

        Path tmp = Files.createTempFile(path.getParent(), "anthropic-oauth-", ".tmp");
        try {
            Files.writeString(tmp, obj.toString(2), StandardCharsets.UTF_8,
                    StandardOpenOption.TRUNCATE_EXISTING);
            restrictToOwner(tmp);
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(tmp); // no-op once the move above succeeded
        }
        restrictToOwner(path);
    }

    private static void restrictToOwner(Path p) {
        try {
            Set<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(p, perms);
        } catch (UnsupportedOperationException e) {
            // Non-POSIX filesystem (e.g. some Windows setups) — nothing to restrict to.
        } catch (IOException e) {
            log.warn("Could not chmod 600 {}: {}", p, e.toString());
        }
    }

    public static void delete() throws IOException {
        Files.deleteIfExists(storePath());
    }

    // ── Cross-process refresh lock ──────────────────────────────────────────
    //
    // Anthropic's refresh_token is SINGLE-USE: once spent, the server invalidates
    // it (confirmed by direct 400 errors in production and by other projects
    // hitting the identical symptom — e.g. github.com/router-for-me/CLIProxyAPI
    // issue #6288 "refresh retry resends a single-use refresh token", and
    // elizaOS/eliza issue #29954 "serialize OAuth2 PKCE token refresh so
    // concurrent loops don't double-spend the single-use refresh token").
    //
    // Malimite has TWO independent OS processes that can both decide a token
    // needs refreshing at the same moment: the Java CLI (scan enrichment,
    // ClaudeOAuthProvider) and the Python web service (AI Assistant chat,
    // anthropic_oauth.py). Each already serializes its OWN concurrent callers
    // with an in-process lock (a plain Object monitor in Java, asyncio.Lock in
    // Python) — but neither process can see the other's lock, so if both reach
    // "token is expired, let's refresh" within the same window, both fire a
    // refresh request with the same (soon-to-be-stale) refresh_token. Anthropic
    // honors whichever request lands first and 400s the other.
    //
    // The fix is an OS-level file lock — java.nio.channels.FileLock, backed by
    // flock(2) on Linux — taken on a SEPARATE ".lock" file next to the real
    // credential (never lock the credential file itself: save() replaces it via
    // atomic rename, which would orphan a lock held on the old inode). Python's
    // anthropic_oauth.py takes the identical flock on the identical path, so a
    // Java and a Python process racing to refresh serialize against the SAME
    // kernel-level lock regardless of which language holds it first.

    private static Path refreshLockPath() {
        Path store = storePath();
        return store.resolveSibling(store.getFileName() + ".lock");
    }

    /**
     * Runs {@code action} while holding an exclusive, cross-process file lock on
     * {@link #refreshLockPath()}. Blocks (does not busy-wait) until the lock is
     * available; callers are expected to re-check whether a refresh is still
     * needed immediately after entering, in case another process already
     * refreshed while this one was waiting for the lock.
     */
    static <T> T withRefreshLock(Supplier<T> action) throws IOException {
        Path lockPath = refreshLockPath();
        Files.createDirectories(lockPath.getParent());
        try (FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
             FileLock lock = channel.lock()) { // blocking; shared=false (exclusive) by default
            return action.get();
        }
    }

    // ── Import (no browser/local-callback-server needed) ───────────────────

    /**
     * Where the official {@code claude} CLI (Claude Code) stores its own OAuth
     * session after {@code claude /login}. Reading this lets Malimite reuse an
     * already-completed login instead of running its own browser flow — useful
     * inside a container, which has no browser to open and whose loopback
     * callback server at {@code localhost:53692} the host browser can't reach
     * anyway.
     *
     * <p>Overridable via {@code CLAUDE_CODE_CREDENTIALS_PATH}: the real file is
     * correctly {@code 0600} and owned by the host uid, unreadable from inside
     * a container running as a different uid. {@code web-compose.yml} points
     * this at a synced copy instead (see {@code sync-claude-oauth.sh} at the
     * repo root) — the Python web service's {@code anthropic_oauth.py} honors
     * the same env var for the same reason.</p>
     */
    public static Path claudeCodeCredentialsPath() {
        String override = System.getenv("CLAUDE_CODE_CREDENTIALS_PATH");
        if (override != null && !override.isBlank()) return Path.of(override);
        String home = System.getProperty("user.home");
        return Path.of(home, ".claude", ".credentials.json");
    }

    /**
     * Reads the official Claude Code CLI's own stored session, if present and
     * well-formed. Returns {@code null} rather than throwing when the file is
     * absent or doesn't have the expected {@code claudeAiOauth} shape — this is
     * a convenience auto-detect, not a hard dependency.
     */
    public static AnthropicOAuthCredentials fromClaudeCodeCredentials() {
        Path path = claudeCodeCredentialsPath();
        if (!Files.isRegularFile(path)) return null;
        try {
            String raw = Files.readString(path, StandardCharsets.UTF_8);
            JSONObject root = new JSONObject(raw);
            if (!root.has("claudeAiOauth")) return null;
            JSONObject oauth = root.getJSONObject("claudeAiOauth");
            return new AnthropicOAuthCredentials(
                    oauth.getString("accessToken"),
                    oauth.getString("refreshToken"),
                    oauth.getLong("expiresAt"));
        } catch (Exception e) {
            log.warn("Failed to read Claude Code credentials from {}: {}", path, e.toString());
            return null;
        }
    }
}
