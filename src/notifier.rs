use graphcast_sdk::bots::{DiscordBot, SlackBot, TelegramBot};
use tracing::warn;

use crate::config::Config;

#[derive(Clone)]
pub struct Notifier {
    pub radio_name: String,
    pub slack_token: Option<String>,
    pub slack_channel: Option<String>,
    pub discord_webhook: Option<String>,
    pub telegram_token: Option<String>,
    pub telegram_chat_id: Option<i64>,
}

impl Notifier {
    pub fn from_config(radio_name: String, config: &Config) -> Self {
        let slack_token = config.slack_token.clone();
        let slack_channel = config.slack_channel.clone();
        let discord_webhook = config.discord_webhook.clone();
        let telegram_token = config.telegram_token.clone();
        let telegram_chat_id = config.telegram_chat_id;

        Notifier {
            radio_name,
            slack_token,
            slack_channel,
            discord_webhook,
            telegram_token,
            telegram_chat_id,
        }
    }

    pub async fn notify(self, content: String) {
        if let (Some(token), Some(channel)) = (&self.slack_token, &self.slack_channel) {
            if let Err(e) =
                SlackBot::send_webhook(token.to_string(), channel, &self.radio_name, &content).await
            {
                warn!(
                    err = tracing::field::debug(e),
                    "Failed to send notification to Slack"
                );
            }
        }

        if let Some(webhook_url) = self.discord_webhook.clone() {
            if let Err(e) = DiscordBot::send_webhook(&webhook_url, &self.radio_name, &content).await
            {
                warn!(
                    err = tracing::field::debug(e),
                    "Failed to send notification to Discord"
                );
            }
        }

        if let (Some(token), Some(chat_id)) = (self.telegram_token.clone(), self.telegram_chat_id) {
            let telegram_bot = TelegramBot::new(token);
            if let Err(e) = telegram_bot
                .send_message(chat_id, &self.radio_name, &content)
                .await
            {
                warn!(
                    err = tracing::field::debug(e),
                    "Failed to send notification to Telegram"
                );
            }
        }
    }
}
