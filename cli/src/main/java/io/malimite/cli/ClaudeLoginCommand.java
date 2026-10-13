package io.malimite.cli;

import io.malimite.core.AnthropicOAuthCredentials;
import io.malimite.core.AnthropicOAuthLogin;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.concurrent.Callable;

/**
 * {@code malimite claude-login} — Anthropic OAuth sign-in, three ways.
 *
 * <ol>
 *   <li><b>Interactive (default)</b>: Authorization Code + PKCE, the same flow
 *       Claude Code itself uses — opens a browser and runs a local callback
 *       server. Requires a browser on the machine running this command, so it
 *       does not work inside a headless container.</li>
 *   <li><b>{@code --import}</b>: reuses an already-completed login from the
 *       official {@code claude} CLI's own credentials file
 *       ({@link AnthropicOAuthCredentials#claudeCodeCredentialsPath()}). Run
 *       {@code claude /login} once wherever a browser exists (the host, say),
 *       then import it here — no browser needed on this side at all.</li>
 *   <li><b>{@code --access-token} / {@code --refresh-token} / {@code --expires-at-ms}</b>:
 *       accepts the same three values pasted directly, for when the Claude
 *       Code credentials file isn't local to this machine either (e.g. you
 *       read it on your laptop and this command runs inside a remote
 *       container).</li>
 * </ol>
 *
 * <p>Whichever path is used, the result is stored at
 * {@link AnthropicOAuthCredentials#storePath()}. Afterward, run analysis
 * with {@code --llm --llm-provider claude-oauth} (or
 * {@code LLM_PROVIDER=claude-oauth}) to authorize Messages API requests
 * against your Claude Pro/Max subscription instead of a separately-billed
 * {@code ANTHROPIC_API_KEY}.</p>
 */
@Command(name = "claude-login",
         description = "Sign in with your Claude account (OAuth) to use Claude Pro/Max "
                 + "subscription usage instead of an ANTHROPIC_API_KEY.")
public class ClaudeLoginCommand implements Callable<Integer> {

    @Option(names = {"-t", "--timeout-minutes"},
            description = "How long to wait for the browser sign-in to complete (default: 5)",
            defaultValue = "5")
    private int timeoutMinutes;

    @Option(names = "--logout", description = "Remove the stored Anthropic OAuth credential instead of signing in")
    private boolean logout;

    @Option(names = "--status", description = "Print whether a credential is stored, then exit")
    private boolean status;

    @Option(names = "--import",
            description = "Skip the browser flow: reuse the session already stored by the official "
                    + "'claude' CLI (claude /login), read from ~/.claude/.credentials.json. "
                    + "Use this inside a container, which has no browser.")
    private boolean importFromClaudeCode;

    @Option(names = "--access-token", description = "Manually supply an OAuth access token "
            + "(sk-ant-oat...) instead of running any login flow. Requires --refresh-token and --expires-at-ms.")
    private String manualAccessToken;

    @Option(names = "--refresh-token", description = "Paired with --access-token.")
    private String manualRefreshToken;

    @Option(names = "--expires-at-ms", description = "Paired with --access-token: epoch milliseconds "
            + "the access token expires at (the value Claude Code calls expiresAt).")
    private Long manualExpiresAtMs;

    @Override
    public Integer call() throws Exception {
        if (logout) {
            AnthropicOAuthCredentials.delete();
            System.out.println("Removed " + AnthropicOAuthCredentials.storePath());
            return 0;
        }
        if (status) {
            AnthropicOAuthCredentials creds = AnthropicOAuthCredentials.load();
            if (creds == null) {
                System.out.println("No Anthropic OAuth credential stored.");
                return 1;
            }
            System.out.println("Credential stored at " + AnthropicOAuthCredentials.storePath()
                    + " — " + (creds.isExpired() ? "access token expired (will auto-refresh on next use)"
                                                   : "access token valid"));
            return 0;
        }

        if (manualAccessToken != null || manualRefreshToken != null || manualExpiresAtMs != null) {
            return importManual();
        }
        if (importFromClaudeCode) {
            return importFromClaudeCode();
        }

        try {
            AnthropicOAuthLogin.login(timeoutMinutes);
            return 0;
        } catch (Exception e) {
            System.err.println("error: Anthropic sign-in failed: " + e.getMessage());
            return 1;
        }
    }

    private Integer importManual() throws Exception {
        if (manualAccessToken == null || manualRefreshToken == null || manualExpiresAtMs == null) {
            System.err.println("error: --access-token, --refresh-token and --expires-at-ms must all be given together.");
            return 2;
        }
        if (!manualAccessToken.startsWith("sk-ant-oat")) {
            System.err.println("error: --access-token doesn't look like an OAuth token (expected it to start with 'sk-ant-oat').");
            return 2;
        }
        AnthropicOAuthCredentials creds =
                new AnthropicOAuthCredentials(manualAccessToken, manualRefreshToken, manualExpiresAtMs);
        creds.save();
        System.out.println("Imported manually-supplied token. Stored at " + AnthropicOAuthCredentials.storePath()
                + " — " + (creds.isExpired() ? "already expired (will auto-refresh on next use)" : "valid"));
        return 0;
    }

    private Integer importFromClaudeCode() throws Exception {
        AnthropicOAuthCredentials creds = AnthropicOAuthCredentials.fromClaudeCodeCredentials();
        if (creds == null) {
            System.err.println("error: No Claude Code session found at "
                    + AnthropicOAuthCredentials.claudeCodeCredentialsPath()
                    + ". Run 'claude /login' first (wherever a browser is available), then retry.");
            return 1;
        }
        // Compare against whatever was already stored BEFORE overwriting it: if the
        // access_token is byte-for-byte identical, this import did nothing new. In
        // production this happened because ./sync-claude-oauth.sh (which refreshes
        // AnthropicOAuthCredentials.claudeCodeCredentialsPath()'s source file) hadn't
        // finished writing a fresh token yet when --import ran — the command still
        // "succeeds" (nothing about the copy itself failed), but silently re-imports
        // the same old/possibly-invalid token. Flag that distinctly instead of
        // printing the same "valid" message either way.
        AnthropicOAuthCredentials previous = AnthropicOAuthCredentials.load();
        boolean changed = previous == null || !previous.accessToken.equals(creds.accessToken);
        creds.save();
        if (changed) {
            System.out.println("Imported a NEW session from " + AnthropicOAuthCredentials.claudeCodeCredentialsPath()
                    + ". Stored at " + AnthropicOAuthCredentials.storePath()
                    + " — " + (creds.isExpired() ? "already expired (will auto-refresh on next use)" : "valid"));
        } else {
            System.out.println("Imported the SAME token that was already stored at "
                    + AnthropicOAuthCredentials.storePath() + " — nothing changed. If scans/chat still fail, "
                    + "re-run sync-claude-oauth.sh on the host and wait for it to finish before retrying --import.");
        }
        return 0;
    }
}
