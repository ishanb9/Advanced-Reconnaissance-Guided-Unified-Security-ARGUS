---
id: wonderware-historian
technology: "AVEVA Wonderware Historian"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [12011, 12012]
  banners: ["Wonderware Historian", "AVEVA Historian", "IndustrialSQL"]
  markers: ["IndustrialSQL", "insql", "wonderware-historian", "wwHistClient", "Runtime!"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p12011,12012 -sV {host}", safety: safe, note: "Wonderware Historian client protocol ports; banner identifies IndustrialSQL version." }
  - { cmd: "nmap -Pn -sT -p1433 --script ms-sql-info,ms-sql-empty-password {host}", safety: safe, note: "Wonderware Historian stores data in SQL Server (IndustrialSQL); check version and blank SA password." }
  - { cmd: "nmap -Pn -sT -p1433 --script ms-sql-config {host}", safety: safe, note: "Enumerate SQL Server configuration and linked servers on the Historian host." }
  - { cmd: "<SQL query against Runtime! database for tag history>", safety: intrusive, note: "GATED — querying IndustrialSQL Runtime! database reads historical process data; active SQL connection." }
references: ["CVE-2021-26414", "CVE-2019-18244", "AVEVA Security Bulletin AVEVA-2021-003", "ICS-CERT ICSA-19-274-01"]
mitre: "T0817 / ICS T0852"
---
# AVEVA Wonderware Historian

Wonderware Historian (formerly IndustrialSQL Server, now AVEVA Historian) is a purpose-built
process historian widely deployed in oil & gas, power, chemical, and manufacturing plants
globally. It stores time-series process data in a specialized SQL Server database called the
**Runtime!** database using a compressed storage engine optimized for high-frequency OT data.
Access is provided via a custom client protocol on TCP **12011/12012**, ODBC/OLEDB using the
Wonderware Historian Client driver, and SQL queries against the `Runtime!` catalog using the
IndustrialSQL extension to T-SQL. The Historian acts as the plant's process memory — it
aggregates data from SCADA/HMI systems, PLCs, and field devices for trending, reporting,
and compliance.

**Attack surface.** The underlying SQL Server instance hosting the `Runtime!` database is often
the main attack surface. IndustrialSQL historically required the SQL Server SA account to be
enabled for installation and maintenance, and deployment guides document default credentials.
CVE-2019-18244 (insecure permissions in Wonderware Historian client) allows local privilege
escalation. The SQL Server instance may have linked server connections to other plant databases,
enabling lateral movement via SQL Server's `xp_cmdshell` (if enabled) or linked server
queries. Historian data — timestamped process variables for months or years — provides
invaluable intelligence for planning targeted physical attacks or understanding operating limits.

**Safe-first testing.** Enumerate the SQL Server instance hosting the Historian using
`ms-sql-info` (banner, version) and check for blank SA password with `ms-sql-empty-password`.
These NSE scripts are read-only. Check ports 12011/12012 for banner information. Do not execute
`xp_cmdshell` or other OS-access T-SQL procedures. Do not write to the Runtime! database —
while the Historian is not a control system, injecting false historical data can corrupt process
records, compliance logs, and operator trend analysis relied upon for safety decisions.

**Remediation.** Disable or rename the SQL Server SA account; use a named service account with
minimum required permissions for Wonderware Historian. Restrict TCP 1433 to known Historian
client hosts and Wonderware application servers. Restrict 12011/12012 to known HMI clients.
Apply AVEVA Historian patches per AVEVA Security Bulletins. Disable `xp_cmdshell` and other
extended stored procedures on the SQL instance. Enable SQL Server Audit to log all schema-level
and data-access events on the `Runtime!` database.
