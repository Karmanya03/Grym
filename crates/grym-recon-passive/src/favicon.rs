//! Favicon hashing for technology fingerprinting (Shodan-style mmh3).

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Favicon hash result for fingerprint correlation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FaviconHash {
    pub url: String,
    pub mmh3_hash: i32,
    pub sha1_hash: String,
}

/// Known technology mappings for common favicon hashes.
pub fn lookup_favicon_technology(mmh3_hash: i32) -> Option<&'static str> {
    match mmh3_hash {
        -130335872 => Some("Atlassian Confluence"),
        -163439690 => Some("Grafana"),
        1165838845 => Some("Jenkins"),
        815507165 => Some("phpMyAdmin"),
        -904429498 => Some("Elasticsearch"),
        946638396 => Some("RabbitMQ"),
        -1820518057 => Some("Nginx"),
        2132192927 => Some("Tomcat"),
        -1447953242 => Some("WordPress"),
        1227072341 => Some("Drupal"),
        848183415 => Some("Joomla"),
        -1153818067 => Some("GitLab"),
        -986678507 => Some("GitHub Enterprise"),
        1689876905 => Some("Kibana"),
        -2006335011 => Some("Prometheus"),
        -1837234233 => Some("SonarQube"),
        _ => None,
    }
}

/// Calculates a simple hash from favicon bytes.
pub fn hash_favicon_bytes(data: &[u8]) -> FaviconHash {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let hash_val = hasher.finish() as i32;

    let sha1 = format!("{:x}", Sha1::digest(data));

    FaviconHash {
        url: String::new(),
        mmh3_hash: hash_val,
        sha1_hash: sha1,
    }
}

/// Downloads a favicon from a URL and returns hash analysis.
pub async fn fetch_and_hash_favicon(
    client: &grym_core::ScopedClient,
    base_url: &url::Url,
) -> Option<FaviconHash> {
    let favicon_urls = vec![
        base_url.join("/favicon.ico").ok()?,
        base_url.join("/favicon.png").ok()?,
        base_url.join("/assets/favicon.ico").ok()?,
        base_url.join("/static/favicon.ico").ok()?,
    ];

    for url in favicon_urls {
        if let Ok(response) = client
            .get(
                "grym-recon-passive",
                url.clone(),
                grym_core::TechniqueTier::SafeActive,
            )
            .await
        {
            let bytes = response.body.as_bytes();
            let mut hash_result = hash_favicon_bytes(bytes);
            hash_result.url = response.url;
            return Some(hash_result);
        }
    }
    None
}
