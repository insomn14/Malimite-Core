package io.malimite.bot;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CountDownLatch;

/**
 * Unified entry point. Starts every bot whose env vars are present.
 *
 * Telegram : TELEGRAM_BOT_TOKEN
 * Discord  : DISCORD_BOT_TOKEN          (enable MESSAGE_CONTENT privileged intent in Dev Portal)
 * Slack    : SLACK_APP_TOKEN (xapp-...) + SLACK_BOT_TOKEN (xoxb-...)
 *
 * Required for all: MALIMITE_API_URL
 * Optional for all: MALIMITE_API_KEY
 */
public class BotLauncher {

    private static final Logger log = LoggerFactory.getLogger(BotLauncher.class);

    public static void main(String[] args) throws InterruptedException {
        String apiUrl = System.getenv("MALIMITE_API_URL");
        if (apiUrl == null || apiUrl.isBlank())
            throw new IllegalStateException("MALIMITE_API_URL is required");
        String apiKey = System.getenv("MALIMITE_API_KEY");

        int started = 0;

        String tgToken = System.getenv("TELEGRAM_BOT_TOKEN");
        if (tgToken != null && !tgToken.isBlank()) {
            final String tok = tgToken, url = apiUrl, key = apiKey;
            daemon("telegram-bot", () -> { try { TelegramBot.run(tok, url, key); } catch (Exception e) { throw new RuntimeException(e); } });
            log.info("Telegram bot started");
            started++;
        }

        String discordToken = System.getenv("DISCORD_BOT_TOKEN");
        if (discordToken != null && !discordToken.isBlank()) {
            daemon("discord-bot", new DiscordBot(discordToken, apiUrl, apiKey));
            log.info("Discord bot started");
            started++;
        }

        String slackApp = System.getenv("SLACK_APP_TOKEN");
        String slackBot = System.getenv("SLACK_BOT_TOKEN");
        if (slackApp != null && !slackApp.isBlank() && slackBot != null && !slackBot.isBlank()) {
            daemon("slack-bot", new SlackBot(slackApp, slackBot, apiUrl, apiKey));
            log.info("Slack bot started");
            started++;
        }

        if (started == 0) {
            log.error("No bots configured. Set at least one of: " +
                      "TELEGRAM_BOT_TOKEN | DISCORD_BOT_TOKEN | SLACK_APP_TOKEN+SLACK_BOT_TOKEN");
            System.exit(1);
        }

        log.info("{} bot(s) running", started);
        new CountDownLatch(1).await(); // keep JVM alive; daemon threads do the work
    }

    private static void daemon(String name, Runnable task) {
        Thread t = new Thread(() -> {
            try {
                task.run();
            } catch (Exception e) {
                log.error("{} crashed", name, e);
            }
        }, name);
        t.setDaemon(true);
        t.start();
    }
}
