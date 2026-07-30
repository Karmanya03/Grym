//! Redaction helpers used before evidence leaves memory.

use url::Url;

/// Replaces common credential-bearing assignments with a stable placeholder.
pub fn redact_text(input: &str) -> String {
    input
        .lines()
        .map(redact_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_line(line: &str) -> String {
    let lowercase = line.to_ascii_lowercase();
    if let Some(position) = lowercase.find("bearer ") {
        let prefix = &line[..position];
        return format!("{prefix}Bearer [REDACTED]");
    }
    let sensitive = [
        "authorization",
        "api_key",
        "api-key",
        "access_token",
        "refresh_token",
        "secret",
        "password",
        "passwd",
        "cookie",
    ];
    let is_sensitive = sensitive.iter().any(|key| lowercase.contains(key));
    let delimiter = line.find(':').or_else(|| line.find('='));
    if is_sensitive
        && let Some(position) = delimiter {
            return format!(
                "{}{}[REDACTED]",
                &line[..position],
                &line[position..=position]
            );
        }
    line.to_owned()
}

/// Removes sensitive query values and URL userinfo before audit or report output.
pub fn redact_url(url: &Url) -> String {
    let mut safe = url.clone();
    let _ = safe.set_username("");
    let _ = safe.set_password(None);

    let retained = safe
        .query_pairs()
        .map(|(key, value)| {
            let normalized = key.to_ascii_lowercase();
            let sensitive = ["token", "key", "secret", "password", "code", "session"]
                .iter()
                .any(|needle| normalized.contains(needle));
            if sensitive {
                (key.into_owned(), "[REDACTED]".to_owned())
            } else {
                (key.into_owned(), value.into_owned())
            }
        })
        .collect::<Vec<_>>();

    if retained.is_empty() {
        safe.set_query(None);
    } else {
        let mut query = safe.query_pairs_mut();
        query.clear();
        query.extend_pairs(
            retained
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        );
    }
    safe.into()
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::{redact_text, redact_url};

    #[test]
    fn redacts_common_secrets() {
        let redacted = redact_text("Authorization: Bearer abc.def api_key=super-secret");
        assert!(!redacted.contains("abc.def"));
        assert!(!redacted.contains("super-secret"));
    }

    #[test]
    fn redacts_sensitive_query_values() -> Result<(), url::ParseError> {
        let url = Url::parse("https://example.test/path?token=abc&view=full")?;
        let redacted = redact_url(&url);
        assert!(redacted.contains("token=%5BREDACTED%5D"));
        assert!(redacted.contains("view=full"));
        Ok(())
    }
}
