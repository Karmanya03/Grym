//! JWT attack surface detection — algorithm confusion, weak secrets, missing validation.

use base64::Engine;
use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use regex::Regex;
use serde_json::Value;
use url::Url;

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

const COMMON_JWT_SECRETS: &[&str] = &[
    "secret",
    "password",
    "123456",
    "admin",
    "changeme",
    "secret123",
    "pass",
    "token",
    "jwt_secret",
    "my_secret",
    "key",
    "test",
    "test123",
    "super_secret",
    "changethis",
    "s3cr3t",
    "p@ssw0rd",
    "letmein",
    "abc123",
    "1234567890",
];

#[derive(Debug)]
struct JwtParts {
    header: String,
    payload: String,
    _signature: String,
    header_json: Value,
    _payload_json: Value,
    algorithm: String,
}

fn decode_jwt(token: &str) -> Option<JwtParts> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let decode_b64 = |input: &str| -> Option<String> {
        let padded = match input.len() % 4 {
            0 => input.to_string(),
            n => format!("{}{}", input, &"=".repeat(4 - n)),
        };
        let bytes = base64::engine::general_purpose::URL_SAFE
            .decode(&padded)
            .ok()?;
        String::from_utf8(bytes).ok()
    };

    let header_str = decode_b64(parts[0])?;
    let payload_str = decode_b64(parts[1])?;
    let header_json: Value = serde_json::from_str(&header_str).ok()?;
    let payload_json: Value = serde_json::from_str(&payload_str).ok()?;
    let alg = header_json["alg"].as_str()?.to_string();

    Some(JwtParts {
        header: header_str,
        payload: payload_str,
        _signature: parts[2].to_string(),
        header_json,
        _payload_json: payload_json,
        algorithm: alg,
    })
}

fn is_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3 && !parts[0].is_empty() && !parts[1].is_empty() && !parts[2].is_empty()
}

pub async fn check_jwt_config(
    client: &ScopedClient,
    _url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let Ok(response) = client
        .get(
            "grym-web-scanner",
            _url.clone(),
            TechniqueTier::StandardDetection,
        )
        .await
    else {
        return Ok(findings);
    };

    let auth_header = response
        .headers
        .get("authorization")
        .or_else(|| response.headers.get("x-authorization"));

    if let Some(auth_value) = auth_header {
        let token = auth_value.trim_start_matches("Bearer ").trim();
        if is_jwt(token)
            && let Some(jwt) = decode_jwt(token)
        {
            let mut jwt_finding = Finding::new(
                "JWT token detected in Authorization header",
                AssetRef {
                    identifier: response.url.clone(),
                    kind: "web".into(),
                },
                Severity::Info,
                Confidence::Confirmed,
                "grym-web-scanner",
            );
            jwt_finding
                .categories
                .push("A07:2025-Authentication-Failures".into());

            if jwt.algorithm.to_uppercase() == "NONE" {
                let mut alg_finding = Finding::new(
                    "JWT with 'none' algorithm — authentication bypass possible",
                    AssetRef {
                        identifier: response.url.clone(),
                        kind: "web".into(),
                    },
                    Severity::Critical,
                    Confidence::Confirmed,
                    "grym-web-scanner",
                );
                alg_finding
                    .categories
                    .push("A07:2025-Authentication-Failures".into());
                alg_finding.cwe_ids.push(287);
                alg_finding.evidence.push(Evidence::redacted(
                    "jwt-none-alg",
                    "JWT uses 'none' algorithm",
                    &jwt.header,
                ));
                alg_finding.remediation =
                    "Disable the 'none' algorithm and always validate algorithm in server code."
                        .into();
                alg_finding.references.push(
                    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
                        .into(),
                );
                findings.push(alg_finding);
            }

            if jwt.algorithm.to_uppercase().starts_with("HS") {
                for secret in COMMON_JWT_SECRETS {
                    let msg = format!("{}.{}", jwt.header, jwt.payload);
                    if let Some(true) =
                        try_hmac_verify(&msg, secret, &jwt._signature, &jwt.algorithm)
                    {
                        let mut weak_finding = Finding::new(
                            format!("Weak JWT secret cracked: '{}'", secret),
                            AssetRef {
                                identifier: response.url.clone(),
                                kind: "web".into(),
                            },
                            Severity::Critical,
                            Confidence::Confirmed,
                            "grym-web-scanner",
                        );
                        weak_finding
                            .categories
                            .push("A07:2025-Authentication-Failures".into());
                        weak_finding.cwe_ids.push(287);
                        weak_finding.evidence.push(Evidence::redacted(
                            "jwt-weak-secret",
                            format!("Cracked secret: {}", secret),
                            format!("Algorithm: {}, Header: {}", jwt.algorithm, jwt.header),
                        ));
                        weak_finding.remediation = "Use a strong, randomly generated HMAC secret (256+ bits) and consider using RS256 instead of HS256.".into();
                        findings.push(weak_finding);
                        break;
                    }
                }
            }

            jwt_finding.evidence.push(Evidence::redacted(
                "jwt-header",
                "JWT Authorization header present",
                format!("Algorithm: {}", jwt.algorithm),
            ));
            findings.push(jwt_finding);
        }
    }

    let body_lower = response.body.to_lowercase();
    if let Ok(re) = Regex::new(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")
        && let Some(jwt_match) = re.find(&body_lower)
    {
        let token = jwt_match.as_str();
        if let Some(jwt) = decode_jwt(token) {
            let mut finding = Finding::new(
                "JWT token found in response body",
                AssetRef {
                    identifier: response.url.clone(),
                    kind: "web".into(),
                },
                Severity::High,
                Confidence::Confirmed,
                "grym-web-scanner",
            );
            finding
                .categories
                .push("A02:2025-Security-Misconfiguration".into());
            finding.cwe_ids.push(200);
            finding.evidence.push(Evidence::redacted(
                "jwt-exposure",
                "JWT exposed in response body",
                format!(
                    "Algorithm: {}, Claims: {}",
                    jwt.algorithm,
                    &jwt.payload.chars().take(100).collect::<String>()
                ),
            ));
            finding.remediation =
                "Never expose JWT tokens in responses. Use them only in Authorization headers."
                    .into();
            findings.push(finding);
        }
    }

    Ok(findings)
}

fn try_hmac_verify(msg: &str, secret: &str, signature: &str, algorithm: &str) -> Option<bool> {
    let algo = algorithm.to_uppercase();
    match algo.as_str() {
        "HS256" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
            mac.update(msg.as_bytes());
            let code = mac.finalize().into_bytes();
            let sig = base64::engine::general_purpose::URL_SAFE.encode(code);
            Some(sig == signature || sig.trim_end_matches('=') == signature)
        }
        "HS384" => {
            let mut mac = Hmac::<Sha384>::new_from_slice(secret.as_bytes()).ok()?;
            mac.update(msg.as_bytes());
            let code = mac.finalize().into_bytes();
            let sig = base64::engine::general_purpose::URL_SAFE.encode(code);
            Some(sig == signature || sig.trim_end_matches('=') == signature)
        }
        "HS512" => {
            let mut mac = Hmac::<Sha512>::new_from_slice(secret.as_bytes()).ok()?;
            mac.update(msg.as_bytes());
            let code = mac.finalize().into_bytes();
            let sig = base64::engine::general_purpose::URL_SAFE.encode(code);
            Some(sig == signature || sig.trim_end_matches('=') == signature)
        }
        _ => None,
    }
}
