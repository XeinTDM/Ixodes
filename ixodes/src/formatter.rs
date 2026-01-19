pub const TELEGRAM_MESSAGE_LIMIT: usize = 4096;

#[derive(Debug, Clone)]
pub struct FormattedMessage {
    pub text: String,
    #[allow(dead_code)]
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct MessageFormatter {
    max_length: usize,
}

impl MessageFormatter {
    pub fn new() -> Self {
        Self {
            max_length: TELEGRAM_MESSAGE_LIMIT,
        }
    }

    pub fn with_max_length(mut self, length: usize) -> Self {
        self.max_length = length;
        self
    }

    pub fn format<I, S>(&self, parts: I) -> FormattedMessage
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let raw = self.compose(parts);
        let char_count = raw.chars().count();
        let truncated = char_count > self.max_length;
        let text = if truncated {
            truncate_to_length(&raw, self.max_length)
        } else {
            raw
        };

        FormattedMessage { text, truncated }
    }

    fn compose<I, S>(&self, parts: I) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut buffer = String::new();
        for part in parts.into_iter() {
            let line = part.as_ref();
            if line.is_empty() {
                continue;
            }

            if !buffer.is_empty() {
                buffer.push('\n');
            }
            buffer.push_str(line);
        }

        buffer
    }
}

fn truncate_to_length(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }

    text.chars().take(limit).collect()
}
