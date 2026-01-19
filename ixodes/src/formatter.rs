use serde::Serialize;

pub const TELEGRAM_MESSAGE_LIMIT: usize = 4096;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum ParseMode {
    MarkdownV2,
    Html,
}

impl ParseMode {
    pub(crate) fn escape(&self, text: &str) -> String {
        match self {
            ParseMode::MarkdownV2 => escape_markdown(text),
            ParseMode::Html => escape_html(text),
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "html" => Some(ParseMode::Html),
            "markdown" | "markdown_v2" | "markdownv2" => Some(ParseMode::MarkdownV2),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FormattedMessage {
    pub text: String,
    #[allow(dead_code)]
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct MessageFormatter {
    max_length: usize,
    parse_mode: Option<ParseMode>,
    prefix: Option<String>,
}

impl MessageFormatter {
    pub fn new() -> Self {
        Self {
            max_length: TELEGRAM_MESSAGE_LIMIT,
            parse_mode: None,
            prefix: None,
        }
    }

    pub fn with_parse_mode(mut self, mode: ParseMode) -> Self {
        self.parse_mode = Some(mode);
        self
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    pub fn parse_mode(&self) -> Option<ParseMode> {
        self.parse_mode
    }

    pub fn format<I, S>(&self, parts: I) -> FormattedMessage
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let raw = self.compose(parts);
        let escaped = if let Some(mode) = self.parse_mode {
            mode.escape(&raw)
        } else {
            raw.clone()
        };
        let char_count = escaped.chars().count();
        let truncated = char_count > self.max_length;
        let text = if truncated {
            truncate_to_length(&escaped, self.max_length)
        } else {
            escaped
        };

        FormattedMessage { text, truncated }
    }

    fn compose<I, S>(&self, parts: I) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut buffer = String::new();
        if let Some(prefix) = &self.prefix {
            buffer.push_str(prefix);
        }

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

fn escape_markdown(text: &str) -> String {
    let mut formatted = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '_' | '*' | '[' | ']' | '(' | ')' | '~' | '`' | '>' | '#' | '+' | '-' | '=' | '|'
            | '{' | '}' | '.' | '!' => {
                formatted.push('\\');
                formatted.push(ch);
            }
            other => formatted.push(other),
        }
    }
    formatted
}

fn escape_html(text: &str) -> String {
    let mut formatted = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => formatted.push_str("&amp;"),
            '<' => formatted.push_str("&lt;"),
            '>' => formatted.push_str("&gt;"),
            other => formatted.push(other),
        }
    }
    formatted
}
