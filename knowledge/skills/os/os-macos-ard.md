---
id: os-macos-ard
technology: "macOS Apple Remote Desktop / Screen Sharing"
domain: IT
category: os
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [5900, 5988]
  banners: ["RFB 003", "Apple Remote Desktop", "RFB 003.008"]
  markers: ["Apple Remote Desktop", "ARD", "RFB 003.008", "Mac OS X"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p5900,5988 --script vnc-info,vnc-brute --script-args 'brute.mode=user' {host}", safety: safe, note: "Enumerate VNC/ARD protocol version and auth types — read-only enumeration." }
  - { cmd: "nmap -Pn -p5900 --script vnc-info {host}", safety: safe, note: "Read RFB server version and security types without authentication attempt." }
  - { cmd: "ssh -p22 user@{host} 'system_profiler SPSoftwareDataType; sudo -l; ls /var/root'", safety: intrusive, note: "Post-access macOS enumeration via SSH — GATED; requires valid SSH credentials." }
  - { cmd: "vncviewer {host}:5900", safety: intrusive, note: "Attempt VNC session (will prompt for password if set) — GATED; active connection attempt." }
references: ["CVE-2017-13872 (macOS High Sierra root bug)", "CVE-2021-30869", "CVE-2022-22583", "Apple Security Advisory HT208315"]
mitre: "T1021.005"
---
# macOS Apple Remote Desktop / Screen Sharing

Apple Remote Desktop (ARD) and the built-in Screen Sharing feature on macOS use the **VNC/RFB protocol** on **5900/tcp**. ARD also uses **5988/tcp** for its management agent. When enabled, ARD provides full graphical remote control of the macOS desktop — equivalent to sitting at the keyboard. On macOS, SSH (22/tcp) commonly coexists with ARD for CLI-based remote access, and the two surfaces are frequently both exposed on macOS devices in enterprise or education environments.

**Common exposures.** A notorious 2017 macOS High Sierra bug (CVE-2017-13872) allowed anyone to authenticate as `root` with a blank password via the login screen and ARD — a zero-effort takeover. ARD is commonly left enabled with weak VNC passwords or no authentication in creative/education environments (art departments, labs). macOS also exposes SIP (System Integrity Protection) bypass chains, TCC (Transparency, Consent, and Control) bypasses, and launchd agent persistence paths that are high-value post-exploitation targets.

**Safe-first testing.** Use Nmap's `vnc-info` script to read the RFB protocol version and the offered authentication types (None, VNC auth, Apple ARD auth) — this is fully read-only. If SSH access is in scope, enumerate macOS-specific paths: SIP status (`csrutil status`), sudo rules, LaunchAgents/LaunchDaemons, and TCC database at `~/Library/Application Support/com.apple.TCC/TCC.db`. Avoid graphical screen-sharing connections unless explicitly in scope; they generate prominent on-screen notifications to the logged-in user.

**Remediation.** Disable Screen Sharing and ARD when not actively needed; use macOS MDM (Mobile Device Management) to enforce this at scale; require strong VNC passwords or switch to SSH-only access; enable Firewall in macOS System Settings; enroll in Apple Business Manager for centralized management; monitor `/var/log/system.log` for ARD authentication events; and keep macOS fully patched via Software Update.
