const TELEGRAM_TOKEN_REGEX = /^\d+:[A-Za-z0-9_-]{20,}$/;
const TELEGRAM_CHAT_ID_REGEX = /^-?\d+$/;
const DISCORD_WEBHOOK_REGEX = /^https:\/\/(canary\.|ptb\.)?discord\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+$/;

export function isTelegramTokenValid(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return true;
  }
  return TELEGRAM_TOKEN_REGEX.test(trimmed);
}

export function isTelegramChatIdValid(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return true;
  }
  return TELEGRAM_CHAT_ID_REGEX.test(trimmed);
}

export function isDiscordWebhookValid(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return true;
  }
  return DISCORD_WEBHOOK_REGEX.test(trimmed);
}
