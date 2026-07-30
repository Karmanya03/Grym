use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use url::Url;

const GRAPHQL_PATHS: &[&str] = &[
    "/graphql",
    "/gql",
    "/query",
    "/api",
    "/api/graphql",
    "/graph",
    "/v1/graphql",
    "/v2/graphql",
    "/graphql/console",
    "/graphiql",
];

const PROBE_QUERY: &str = "{__typename}";
const INTROSPECTION_QUERY: &str = "query{__schema{queryType{name}}}";
const DEEP_NESTED_QUERY: &str =
    "{a{b{c{d{e{f{g{h{i{j{k{l{m{n{o{p{q{r{s{t{u{v{w{x{y{z}}}}}}}}}}}}}}}}}}}}}}}}";
const EXPENSIVE_QUERY: &str = "{a b c d e f g h i j k l m n o p q r s t u v w x y z}";

fn build_query_url(base: &Url, path: &str, query: &str) -> Option<Url> {
    let mut u = base.join(path).ok()?;
    let encoded = urlencoding(query);
    u.set_query(Some(&format!("query={}", encoded)));
    Some(u)
}

fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'{' | b'}' | b'(' | b')' | b':' | b'@' | b'!' | b'$' | b'\'' => {
                out.push(char::from(byte));
            }
            b' ' => out.push_str("%20"),
            b'#' => out.push_str("%23"),
            b'&' => out.push_str("%26"),
            b'/' => out.push_str("%2F"),
            b'\\' => out.push_str("%5C"),
            b'\"' => out.push_str("%22"),
            b'<' => out.push_str("%3C"),
            b'>' => out.push_str("%3E"),
            b'=' => out.push_str("%3D"),
            b'?' => out.push_str("%3F"),
            b'`' => out.push_str("%60"),
            b'%' => out.push_str("%25"),
            _ if byte.is_ascii_alphanumeric()
                || byte == b'-'
                || byte == b'_'
                || byte == b'.'
                || byte == b'~' =>
            {
                out.push(char::from(byte));
            }
            _ => {
                out.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    out
}

fn is_graphql_response(body: &str) -> bool {
    body.contains("\"data\"") || body.contains("\"errors\"") || body.contains("__typename")
}

async fn probe_endpoint(
    client: &ScopedClient,
    base: &Url,
    path: &str,
) -> Result<bool, ScopedClientError> {
    let probe_url = build_query_url(base, path, PROBE_QUERY);
    match probe_url {
        Some(u) => {
            if let Ok(response) = client
                .get("grym-web-scanner", u, TechniqueTier::SafeActive)
                .await
            {
                if response.status == 200 && is_graphql_response(&response.body) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        None => Ok(false),
    }
}

async fn fetch_body(client: &ScopedClient, base: &Url, path: &str, query: &str) -> Option<String> {
    let url = build_query_url(base, path, query)?;
    client
        .get("grym-web-scanner", url, TechniqueTier::SafeActive)
        .await
        .ok()
        .map(|r| r.body)
}

fn add_introspection_finding(body: &str, endpoint: &str, findings: &mut Vec<Finding>) {
    if body.contains("__schema") {
        let mut finding = Finding::new(
            format!("GraphQL introspection is enabled at {}", endpoint),
            AssetRef {
                identifier: endpoint.to_string(),
                kind: "web".into(),
            },
            Severity::High,
            Confidence::Confirmed,
            "grym-web-scanner",
        );
        finding
            .categories
            .push("A01:2025-Broken-Access-Control".into());
        finding.cwe_ids.push(200);
        finding.evidence.push(Evidence::redacted(
            "graphql-introspection",
            format!("Introspection query succeeded at {}", endpoint),
            format!("Endpoint: {}, Response includes __schema", endpoint),
        ));
        finding.remediation = "Disable GraphQL introspection in production. Set the introspection flag to false in your GraphQL configuration.".into();
        finding
            .references
            .push("https://graphql.org/learn/introspection/".into());
        findings.push(finding);
    }
}

fn add_depth_limiting_finding(body: &str, endpoint: &str, findings: &mut Vec<Finding>) {
    if body.contains("\"data\"") {
        let mut finding = Finding::new(
            format!("GraphQL depth limiting may be missing at {}", endpoint),
            AssetRef {
                identifier: endpoint.to_string(),
                kind: "web".into(),
            },
            Severity::Medium,
            Confidence::Possible,
            "grym-web-scanner",
        );
        finding
            .categories
            .push("A01:2025-Broken-Access-Control".into());
        finding.cwe_ids.push(770);
        finding.evidence.push(Evidence::redacted(
            "graphql-depth",
            format!("Deeply nested query (26 levels) succeeded at {}", endpoint),
            format!("Endpoint: {}, Deep query returned data", endpoint),
        ));
        finding.remediation = "Implement query depth limiting. Use a library like graphql-depth-limit or configure max_depth in your GraphQL server.".into();
        finding
            .references
            .push("https://graphql.org/learn/security/#depth-limit".into());
        findings.push(finding);
    }
}

fn add_cost_analysis_finding(body: &str, endpoint: &str, findings: &mut Vec<Finding>) {
    if body.contains("\"data\"") {
        let mut finding = Finding::new(
            format!("GraphQL query cost analysis may be missing at {}", endpoint),
            AssetRef {
                identifier: endpoint.to_string(),
                kind: "web".into(),
            },
            Severity::Medium,
            Confidence::Possible,
            "grym-web-scanner",
        );
        finding
            .categories
            .push("A01:2025-Broken-Access-Control".into());
        finding.cwe_ids.push(770);
        finding.evidence.push(Evidence::redacted(
            "graphql-cost",
            format!("Expensive query (26 fields) succeeded at {}", endpoint),
            format!("Endpoint: {}, Wide query returned data", endpoint),
        ));
        finding.remediation = "Implement query cost analysis to limit expensive queries. Use libraries like graphql-query-cost or graphql-validation-complexity.".into();
        finding
            .references
            .push("https://graphql.org/learn/security/#query-cost-analysis".into());
        findings.push(finding);
    }
}

fn add_batching_finding(body: &str, endpoint: &str, findings: &mut Vec<Finding>) {
    if body.contains("\"data\"") && body.matches("\"__typename\"").count() > 1 {
        let mut finding = Finding::new(
            format!("GraphQL batching may be allowed at {}", endpoint),
            AssetRef {
                identifier: endpoint.to_string(),
                kind: "web".into(),
            },
            Severity::Medium,
            Confidence::Possible,
            "grym-web-scanner",
        );
        finding
            .categories
            .push("A01:2025-Broken-Access-Control".into());
        finding.cwe_ids.push(770);
        finding.evidence.push(Evidence::redacted(
            "graphql-batching",
            format!("Multiple queries in one request succeeded at {}", endpoint),
            format!(
                "Endpoint: {}, Batch response contains multiple results",
                endpoint
            ),
        ));
        finding.remediation = "Disable or rate-limit GraphQL query batching to prevent batch attacks. Consider implementing query whitelisting.".into();
        finding
            .references
            .push("https://graphql.org/learn/security/#batching".into());
        findings.push(finding);
    }
}

pub async fn check_graphql(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    for path in GRAPHQL_PATHS {
        let found = probe_endpoint(client, url, path).await?;
        if !found {
            continue;
        }
        let endpoint_str = format!(
            "{}://{}{}",
            url.scheme(),
            url.host_str().unwrap_or("unknown"),
            path
        );

        if let Some(body) = fetch_body(client, url, path, INTROSPECTION_QUERY).await {
            add_introspection_finding(&body, &endpoint_str, &mut findings);
        }

        if let Some(body) = fetch_body(client, url, path, DEEP_NESTED_QUERY).await {
            add_depth_limiting_finding(&body, &endpoint_str, &mut findings);
        }

        if let Some(body) = fetch_body(client, url, path, EXPENSIVE_QUERY).await {
            add_cost_analysis_finding(&body, &endpoint_str, &mut findings);
        }

        if let Some(body) = fetch_body(client, url, path, PROBE_QUERY).await {
            add_batching_finding(&body, &endpoint_str, &mut findings);
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graphql_paths_are_valid() {
        assert_eq!(GRAPHQL_PATHS.len(), 10);
        for p in GRAPHQL_PATHS {
            assert!(p.starts_with('/'), "path {} must start with /", p);
        }
    }

    #[test]
    fn test_graphql_response_detection() {
        let body = r#"{"data":{"__typename":"Query"}}"#;
        assert!(is_graphql_response(body));

        let body = r#"{"errors":[{"message":"bad"}]}"#;
        assert!(is_graphql_response(body));

        let body = r#"{"ok":true}"#;
        assert!(!is_graphql_response(body));
    }

    #[test]
    fn test_introspection_detection() {
        let mut findings = Vec::new();
        let body = r#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#;
        add_introspection_finding(body, "http://test/graphql", &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);

        let mut findings = Vec::new();
        let body = r#"{"data":{"__typename":"Query"}}"#;
        add_introspection_finding(body, "http://test/graphql", &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_depth_limiting_detection() {
        let mut findings = Vec::new();
        let body = r#"{"data":{"a":{"b":{"c":{}}}}}"#;
        add_depth_limiting_finding(body, "http://test/graphql", &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);

        let mut findings = Vec::new();
        let body = r#"{"errors":[{"message":"query too deep"}]}"#;
        add_depth_limiting_finding(body, "http://test/graphql", &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_cost_analysis_detection() {
        let mut findings = Vec::new();
        let body = r#"{"data":{"a":"1","b":"2"}}"#;
        add_cost_analysis_finding(body, "http://test/graphql", &mut findings);
        assert_eq!(findings.len(), 1);

        let mut findings = Vec::new();
        let body = r#"{"errors":[{"message":"query too expensive"}]}"#;
        add_cost_analysis_finding(body, "http://test/graphql", &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_batching_detection() {
        let mut findings = Vec::new();
        let body = r#"{"data":[{"__typename":"Query"},{"__typename":"Query"}]}"#;
        add_batching_finding(body, "http://test/graphql", &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);

        let mut findings = Vec::new();
        let body = r#"{"data":{"__typename":"Query"}}"#;
        add_batching_finding(body, "http://test/graphql", &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_url_encoding() {
        let query = "{__typename}";
        let encoded = urlencoding(query);
        assert_eq!(encoded, "{__typename}");
        assert_eq!(urlencoding("a b"), "a%20b");
    }

    #[test]
    fn test_build_query_url() {
        let Ok(base) = Url::parse("http://example.com") else {
            return;
        };
        let result = build_query_url(&base, "/graphql", "{__typename}");
        assert!(result.is_some());
        if let Some(url) = result {
            assert_eq!(url.path(), "/graphql");
            if let Some(q) = url.query() {
                assert!(q.contains("query="));
            }
        }
    }
}
