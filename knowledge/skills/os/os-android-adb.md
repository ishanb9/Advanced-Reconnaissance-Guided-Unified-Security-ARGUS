---
id: os-android-adb
technology: "Android ADB (Android Debug Bridge)"
domain: IT
category: os
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [5555]
  banners: ["CNXN", "device::", "adb server"]
  markers: ["adb_auth", "adb connect", "emulator-5554"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p5555 --script banner {host}", safety: safe, note: "Banner-grab to confirm ADB TCP listener presence and version string — read-only." }
  - { cmd: "adb connect {host}:5555 && adb shell id", safety: intrusive, note: "Connect to exposed ADB and run whoami — GATED; establishes device shell without user consent if auth disabled." }
  - { cmd: "adb connect {host}:5555 && adb shell getprop ro.build.version.release", safety: intrusive, note: "Retrieve Android OS version via ADB shell — GATED; active device connection." }
  - { cmd: "adb connect {host}:5555 && adb shell pm list packages -f", safety: intrusive, note: "List all installed packages with APK paths — GATED; full app inventory exposure." }
references: ["CVE-2019-2215 (Android kernel use-after-free)", "CVE-2020-0069 (MediaTek su backdoor)", "CISA ICS-CERT on mobile attack surface", "Android Security Bulletins"]
mitre: "T1437"
---
# Android ADB (Android Debug Bridge)

Android Debug Bridge (ADB) on **5555/tcp** provides a full, unauthenticated (or weakly-authenticated) shell to Android devices when the TCP ADB listener is enabled. Originally designed for developer debugging, ADB over TCP is frequently left enabled on Android-based industrial panels, point-of-sale terminals, kiosk devices, smart TVs, Android-based IP cameras, and development handsets. A single `adb connect <ip>:5555` followed by `adb shell` yields a shell with the `shell` user (or sometimes `root` if the device is rooted) — complete read/write filesystem access, package installation, and screen control.

**Common exposures.** ADB over TCP is found massively on Shodan (hundreds of thousands of exposed devices globally). Industrial Android panels (Advantech, B&R, Siemens HMI tablets), smart TVs (Samsung Tizen with ADB enabled during factory testing), retail POS devices, and Android-based IoT controllers frequently expose 5555. MediaTek devices shipped a hidden `su` backdoor (CVE-2020-0069) that persisted in ROMs for years. Many low-cost Android devices have no ADB authentication (RSA key pairing) enforced.

**Safe-first testing.** Confirm the ADB port with a banner grab or Nmap service scan — the ADB CNXN banner is distinctive. Before running `adb connect`, verify scope authorization; the connection itself constitutes device access. Once connected, read-only commands (`getprop`, `pm list packages`, `logcat -d`) enumerate the device without modifying state. Avoid running `adb install`, writing to `/sdcard`, or triggering `am start` without explicit authorization as these modify device state.

**Remediation.** Disable ADB over TCP on all production, retail, and OT-facing Android devices (`adb tcpip` should never be run on production images); enforce USB ADB only in developer builds gated behind build type; require RSA key pairing for any ADB connections; network-segment Android-based panels onto isolated VLANs with no outbound internet; apply Android Security Bulletins monthly; and audit devices with Shodan monitoring for 5555/tcp exposure.
