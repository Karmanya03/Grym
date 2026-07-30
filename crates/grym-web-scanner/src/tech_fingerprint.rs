//! Technology fingerprinting — from headers, body, cookies, and behavior.

use regex::Regex;
use url::Url;
use grym_core::{Confidence, Finding, AssetRef, Severity, Evidence,
                ScopedClient, ScopedClientError, TechniqueTier};

const TECH_HEADER_SIGNATURES: &[(&str, &str)] = &[
    (r"Server: Apache(?:/([\d.]+))?", "Apache HTTP Server"),
    (r"Server: nginx(?:/([\d.]+))?", "Nginx"),
    (r"Server: Microsoft-IIS(?:/([\d.]+))?", "Microsoft IIS"),
    (r"Server: Tomcat(?:/([\d.]+))?", "Apache Tomcat"),
    (r"Server: Jetty(?:/([\d.]+))?", "Jetty"),
    (r"Server: Caddy(?:/([\d.]+))?", "Caddy"),
    (r"Server: GSE", "Google Search Appliance"),
    (r"X-Powered-By: PHP(?:/([\d.]+))?", "PHP"),
    (r"X-Powered-By: ASP\.NET", "ASP.NET"),
    (r"X-Powered-By: Express", "Express.js"),
    (r"X-Powered-By: Flask", "Flask"),
    (r"X-Powered-By: Django", "Django"),
    (r"X-Powered-By: Rails", "Ruby on Rails"),
    (r"X-Powered-By: Laravel", "Laravel"),
    (r"X-Powered-By: Play", "Play Framework"),
    (r"X-Runtime: Ruby", "Ruby on Rails"),
    (r"X-Runtime: ([\d.]+)", "Framework runtime header"),
    (r"X-Framework: ([\w.]+)", "Framework header"),
    (r"X-Generator: Drupal", "Drupal"),
    (r"X-Generator: WordPress", "WordPress"),
    (r"X-Generator: Joomla", "Joomla"),
    (r"X-Drupal-Cache", "Drupal"),
    (r"X-Drupal-Dynamic-Cache", "Drupal"),
    (r"X-Varnish", "Varnish Cache"),
    (r"CF-Ray", "Cloudflare CDN"),
    (r"X-Cache", "Caching Layer"),
    (r"X-Amz-Cf-Id", "AWS CloudFront"),
    (r"Set-Cookie: .*PHPSESSID", "PHP Session"),
    (r"Set-Cookie: .*JSESSIONID", "Java/J2EE Session"),
    (r"Set-Cookie: .*ASP.NET_SessionId", "ASP.NET Session"),
    (r"Set-Cookie: .*laravel_session", "Laravel Session"),
    (r"Set-Cookie: .*connect.sid", "Express.js Session"),
    (r"Set-Cookie: .*symfony", "Symfony Session"),
    (r"Set-Cookie: .*rack.session", "Ruby/Rack Session"),
    (r"Set-Cookie: .*.AspNetCore.", "ASP.NET Core Session"),
    (r"X-AspNet-Version", "ASP.NET"),
    (r"X-AspNetMvc-Version", "ASP.NET MVC"),
    (r"Access-Control-Allow-Origin: \*", "CORS Wildcard"),
    (r"Strict-Transport-Security", "HSTS enabled"),
    (r"Content-Security-Policy", "CSP enabled"),
];

const BODY_TECH_PATTERNS: &[(&str, &str)] = &[
    (r"wp-content|wp-includes|wordpress", "WordPress"),
    (r"drupal\.js|drupal\.css|Drupal\.settings", "Drupal"),
    (r"Joomla!", "Joomla"),
    ("var jsn|\"joomla\"", "Joomla"),
    (r"Shopify\.sdk", "Shopify"),
    (r"window\.Shopify", "Shopify"),
    (r"bootstrap\.min\.css|bootstrap\.css", "Bootstrap"),
    (r"angular\.js|angular\.min\.js", "Angular"),
    (r"react\.js|react\.min\.js|React\.createElement", "React"),
    (r"vue\.js|vue\.min\.js|Vue\.component", "Vue.js"),
    (r"jquery\.js|jquery\.min\.js|jQuery\(|jQuery\.", "jQuery"),
    (r"lodash\.js|lodash\.min\.js|underscore", "Lodash/Underscore"),
    (r"moment\.js|moment\.min\.js", "Moment.js"),
    (r"chart\.js|Chart\.min\.js|new Chart", "Chart.js"),
    (r"d3\.js|d3\.min\.js|d3\.scale", "D3.js"),
    (r"swagger|openapi\.json|swagger-ui", "Swagger/OpenAPI"),
    (r"graphql|graphiql|__graphql", "GraphQL"),
    (r"websocket|socket\.io", "WebSockets/Socket.IO"),
];

pub async fn fingerprint_tech(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let response = client
        .get("grym-web-scanner", url.clone(), TechniqueTier::SafeActive)
        .await?;

    // Check header signatures
    for (pattern, tech_name) in TECH_HEADER_SIGNATURES {
        for (header_name, header_value) in &response.headers {
            let combined = format!("{}: {}", header_name, header_value);
            if let Ok(re) = Regex::new(pattern)
                && re.is_match(&combined) {
                    let mut f = Finding::new(
                        format!("Technology detected: {} via response header", tech_name),
                        AssetRef { identifier: url.to_string(), kind: "web".into() },
                        Severity::Info, Confidence::Confirmed, "grym-web-scanner",
                    );
                    f.categories.push("Fingerprinting".into());
                    f.evidence.push(Evidence::redacted("tech-header", format!("Header matched: {}", header_name), combined));
                    f.references.push("https://www.w3.org/Protocols/".into());
                    findings.push(f);
                }
        }
    }

    // Check body signatures
    for (pattern, tech_name) in BODY_TECH_PATTERNS {
        if let Ok(re) = Regex::new(pattern)
            && re.is_match(&response.body) {
                let mut f = Finding::new(
                    format!("Technology detected: {} from response body", tech_name),
                    AssetRef { identifier: url.to_string(), kind: "web".into() },
                    Severity::Info, Confidence::Confirmed, "grym-web-scanner",
                );
                f.categories.push("Fingerprinting".into());
                f.evidence.push(Evidence::redacted("tech-body", format!("Body pattern: {}", pattern), response.body.chars().take(200).collect::<String>()));
                findings.push(f);
            }
    }

    Ok(findings)
}