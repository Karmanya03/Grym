//! Insecure Direct Object Reference (IDOR) / BOLA detection.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use url::Url;

pub async fn check_idor(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let id_params = [
        "id",
        "user_id",
        "userid",
        "account_id",
        "accountid",
        "customer_id",
        "customerid",
        "order_id",
        "orderid",
        "product_id",
        "productid",
        "item_id",
        "itemid",
        "file_id",
        "fileid",
        "document_id",
        "documentid",
        "profile_id",
        "profileid",
        "uid",
        "pid",
        "cid",
        "oid",
        "eid",
        "sid",
        "token",
    ];

    let test_ids = ["1", "2", "3", "100", "1000", "9999999", "admin", "0"];

    let base_query: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    for (param_name, _value) in &base_query {
        if !id_params.contains(&param_name.as_str().to_lowercase().as_str()) {
            continue;
        }

        for test_id in &test_ids {
            let mut test_url = url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in &base_query {
                    let val = if k == param_name {
                        test_id.to_string()
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
                && response.status == 200
            {
                let body_lower = response.body.to_lowercase();
                let has_user_data = body_lower.contains("profile")
                    || body_lower.contains("account")
                    || body_lower.contains("welcome")
                    || body_lower.contains("dashboard")
                    || body_lower.contains("email")
                    || body_lower.contains("user:")
                    || body_lower.contains("name")
                    || body_lower.contains("address");

                if has_user_data {
                    let mut finding = Finding::new(
                        format!(
                            "Potential IDOR in parameter '{}' with value '{}'",
                            param_name, test_id
                        ),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::High,
                        Confidence::Possible,
                        "grym-web-scanner",
                    );
                    finding
                        .categories
                        .push("A01:2025-Broken-Access-Control".into());
                    finding.cwe_ids.push(639);
                    finding.evidence.push(Evidence::redacted(
                        "idor-probe",
                        format!(
                            "Parameter: {}, Value: {}, Status: {}",
                            param_name, test_id, response.status
                        ),
                        response.body.chars().take(200).collect::<String>(),
                    ));
                    finding.remediation = "Implement proper access control checks. Use unpredictable identifiers (UUIDs) instead of sequential integers.".into();
                    finding.references.push(
                        "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"
                            .into(),
                    );
                    findings.push(finding);
                }
            }
        }
    }

    Ok(findings)
}
