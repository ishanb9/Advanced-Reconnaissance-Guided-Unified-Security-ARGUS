---
id: os-esxi-vsphere
technology: "VMware ESXi / vSphere Hypervisor"
domain: IT
category: os
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [902, 9080]
  banners: ["VMware", "ESXi", "vSphere", "VMkernel"]
  markers: ["vmware-authd", "ESXi", "/sdk", "/ui/#/login", "Server: VMware"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p443,902,9080 --script vmware-version {host}", safety: safe, note: "Enumerate ESXi version, build number, and vSphere API endpoint — read-only." }
  - { cmd: "curl -sk https://{host}/sdk | grep -i 'vmware\\|esxi\\|version'", safety: safe, note: "Probe the vSphere SDK endpoint for version disclosure — read-only HTTP probe." }
  - { cmd: "nmap -Pn -p443 --script http-title,http-headers {host}", safety: safe, note: "Retrieve ESXi Web UI title and server headers to fingerprint version — read-only." }
  - { cmd: "curl -sk -u 'root:<password>' https://{host}/rest/vcenter/vm", safety: intrusive, note: "List all VMs via vSphere REST API — GATED; requires credentials, logs API call." }
  - { cmd: "python3 esxitool.py --host {host} --user root --password '<pw>' --list-vms", safety: intrusive, note: "Enumerate running VMs and snapshots — GATED; requires authentication." }
references: ["CVE-2021-21985 (vCenter RCE)", "CVE-2021-22005 (vCenter CEIP RCE)", "CVE-2021-21974 (ESXi OpenSLP heap overflow)", "CVE-2022-31696", "KEV CVE-2021-22005", "CISA Advisory AA22-138A"]
mitre: "T1190"
---
# VMware ESXi / vSphere Hypervisor

VMware ESXi is the bare-metal hypervisor deployed in the vast majority of enterprise data centres globally. ESXi listens on **443/tcp** (vSphere Web Client, REST API, SDK), **902/tcp** (VMware Authentication Daemon — vmware-authd), and **9080/tcp** (vSphere Replication). Compromising an ESXi host is extremely high-impact: an attacker gains administrative control over every virtual machine running on that hypervisor — effectively owning the entire guest estate from one foothold.

**Critical CVEs.** CVE-2021-22005 (vCenter Analytics service arbitrary file upload, pre-auth RCE) was weaponized within hours of disclosure and is in CISA's KEV. CVE-2021-21985 (vSphere Client RCE via VMRC plugin, pre-auth) and CVE-2021-21974 (ESXi OpenSLP heap overflow enabling guest-to-host escape) have both been exploited by ransomware groups. CISA advisory AA22-138A documented widespread ransomware targeting unpatched ESXi. The ESXiArgs ransomware campaign (2023) encrypted thousands of unpatched ESXi servers exposed on the internet.

**Safe-first testing.** Fingerprint via the SDK endpoint (`/sdk`), `/ui/` web interface, and Nmap's `vmware-version` NSE to obtain the exact build number — cross-reference against VMware's Security Advisories (vmsa.vmware.com) for CVE applicability. Probe HTTP headers for `Server: VMware` and check `/rest/com.vmware.cis.session` for API availability. Never attempt to power off, snapshot, or modify VMs unless explicitly in scope; even read API calls enumerate sensitive infrastructure.

**Remediation.** Apply VMware Security Advisories on an emergency timeline for critical CVEs; disable ESXi Shell and SSH when not actively used (or restrict to management VLAN); place vCenter and ESXi management interfaces on isolated management VLANs with no internet access; enforce MFA for vSphere SSO; review OpenSLP (port 427) and disable if unused; enable ESXi audit logging; and follow VMware's hardening guides for each major release.
