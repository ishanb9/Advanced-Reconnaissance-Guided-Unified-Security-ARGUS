# Making ARGUS Efficient Across All Technology Types — OT, IoT, and IT (Crestron-class and Beyond)

> **Research report** · 2026-06-20 · Basis for the #5 implementation plan (capability-module expansion)
> Scope: a per-domain technology map (OT / IoT / IT) + an architecture and roadmap to extend ARGUS's IT operator-brain to industrial, building-automation, consumer/enterprise-IoT, vertical OT-IoT, and IT-frontier targets.
> Status: research complete; facts corrected per adversarial verification (see §7 and inline ⚠ notes).

---

## 1. Executive summary

ARGUS today is a strong **IT operator-brain** platform: an LLM operator that composes `nmap`/`rustscan`/`gobuster`/`ffuf`/`nuclei`/web-exploit/Metasploit/shell actions over TCP/IP, with stateful HTTP, CVE lookup, and a report engine. It already has the *seed* of a multi-domain design: the `agents/avot` Crestron capability module (`detect()` fingerprint + `finding_for()` record), wired into the engine via `MasterAgent._avot_capability_scan()` (`agents/master_agent.py:4147`). The question this report answers is **how to generalize that one module into full OT / IoT / IT coverage** — efficiently, and without making ARGUS dangerous to fragile industrial equipment.

**The landscape splits into three classes with fundamentally different testing physics:**

| Class | Defining property | What ARGUS needs |
|---|---|---|
| **OT / ICS / SCADA** | Protocols designed for isolated, trusted networks — **no auth, no encryption, no integrity** by default. *Reachability = control.* Probing can **crash PLCs and trip breakers**. Much traffic is **Layer-2** (GOOSE/SV/PROFINET-DCP) with no IP port. | Read-only protocol decoders, a **port→protocol fingerprint map**, a **CRITICAL fragile-device safe mode** (read-only function codes, rate-limited, passive-first), a Layer-2/SPAN capture path, and findings mapped to **CISA ICS advisories / OT:ICEFALL**, not just CVE/CVSS. |
| **IoT (IP + RF)** | Two tiers: **(a) IP-reachable** services (MQTT, CoAP, UPnP/SSDP, mDNS, ONVIF/RTSP, IPP/PJL, NAS, CPE) ARGUS can already reach and mostly needs new probes + IoT credential corpora; **(b) RF** (Zigbee, Z-Wave, BLE, Thread/Matter, LoRaWAN, sub-GHz) ARGUS **cannot reach at all** without SDR/radio hardware. | UDP/multicast discovery probes, an IoT default-credential store, firmware extraction (binwalk), and an **RF/SDR hardware-bridge** abstraction (the largest single gap). |
| **IT frontier** | Beyond classic web/SSH/RDP: cloud control plane (IMDS/S3/IAM), containers/K8s, Active Directory (SMB/Kerberos/LDAP), modern APIs (GraphQL/gRPC), message queues, databases, **VPN/edge appliances** (the #1 mass-exploited initial-access vector of 2024–2025), and Wi-Fi. | **Credential-aware, stateful workflows** (SSRF→IMDS→IAM; AD foothold→Kerberoast→crack→lateral), non-HTTP protocol speakers, cloud/orchestrator API clients, and a continuously-updated edge-CVE feed. |

**Headline recommendation.** Do **not** bolt protocol parsers into the engine. Instead, **generalize the `agents/avot` pattern into a domain-tagged capability-module registry plus an external fingerprint registry**, governed by a **safety-class taxonomy** that is *safe-by-default for OT*. Concretely:

1. **Capability-module registry** — each technology family is a self-contained module (like `agents/avot`) exposing `detect(intel) → detection` and `finding_for(detection) → record`. The engine iterates registered detectors after recon (exactly as `_avot_capability_scan` does today) and stays content-agnostic. This satisfies the existing guard `test_no_hardcoded_attack_content`.
2. **Fingerprint registry as data** — externalize `port + probe → response pattern → technology → CPE → applicable-capability` into a versioned data file (the Nmap `nmap-service-probes` / Rapid7 `Recog` pattern), so OT/IoT match rules import wholesale and ship on their own cadence, decoupled from engine releases.
3. **Safety-class field gating every action** — every capability declares `safe` / `intrusive` / `disruptive` (the NSE `safe`/`intrusive`/`dos`/`exploit` taxonomy). The operator brain **auto-dispatches only `safe` modules against OT targets** unless an engagement explicitly authorizes intrusive writes — reusing the engagement-integrity authorization model (sub-project #1) and the fuzzer's existing `--authorized` + `--scope-allow` + circuit-breaker scaffolding.
4. **Passive-first for OT** — a SPAN/PCAP ingest mode (the GRASSMARLIN doctrine) that runs the same fingerprint lookups without sending a single packet, preferred whenever a target is classified OT/fragile.
5. **Transport adapters** for the non-IP tiers (Layer-2 raw sockets, CAN/serial, SDR/RF) behind a uniform module interface so the operator brain stays transport-agnostic (the Caring Caribou pattern).

**Prioritization** (full roadmap in §6): lead with the technologies that are **IP-reachable, high-prevalence, mature-tooled, and IT-adjacent** — OPC-UA, BACnet/IP, Modbus, S7, EtherNet/IP, Niagara Fox, ONVIF/RTSP, IPP/PJL printers, MQTT/CoAP, UPnP/SSDP/mDNS, and the IT frontier (IMDS/S3, K8s/Docker, AD/Kerberos/LDAP, GraphQL/gRPC, VPN-edge). Defer the RF/serial/CAN tiers (Zigbee/Z-Wave/BLE/LoRaWAN/Wiegand/OSDP/CAN) that require new hardware to P2.

This report covers **~70 technology families** (deduplicated; see matrix §2) with **~120 source references** (§8).

---

## 2. Master coverage matrix

Every technology family from the research, deduplicated, corrected per verification. Ports/protocols trimmed for width; full detail in the deep-dives (§3–§5). **Safety class** is the recommended default action-gate (S = safe/read-only, I = intrusive enumeration, D = disruptive/write — D always gated).

### 2a. OT / ICS / SCADA

| Family | Cat | Protocols | Default ports | Fingerprint | Existing tools | Key risks | ARGUS gap | Integration |
|---|---|---|---|---|---|---|---|---|
| **Modbus / Modbus-TCP** | OT | Modbus TCP, RTU-over-TCP ⚠*(not UDP — no Modbus/UDP standard)* | **502/tcp** ⚠*(502/udp reserved at IANA but non-standard)* | MBAP header + read FC; **FC 43 / MEI 14** = Read Device ID (vendor/product/fw) | nmap `modbus-discover`, `modicon-info`(Redpoint); MSF `modbusclient` (R/W), `modbusdetect` ⚠*(presence check only, not version)*; plcscan, smod, ICSSPLOIT, pymodbus | No auth/enc; write coils/registers shut down internet-exposed M340 PLCs; ~tens-of-thousands on Shodan | No Modbus speaker / 502 fingerprint | Read-only FC 0x01/0x03/0x2B by default; **hard-gate writes 0x05/06/0F/10** (D) |
| **Siemens S7comm / S7comm-Plus** | OT | S7comm (ISO-on-TCP/COTP, RFC1006), S7comm-Plus | **102/tcp** | COTP CR → S7 SZL read (SZL 0x0011/0x001C) → module/serial/fw. Disambiguate from MMS by **post-COTP payload byte (S7 PDU `0x32` vs MMS/ACSE)**, not the port | nmap `s7-info`, Redpoint `s7-enumerate`, plcscan, moki-ics s7 MSF modules, snap7/python-snap7, PLCinject, ISF | Unauth CPU STOP / mem R-W on S7-300/400; crafted-packet DoS on 1200/1500; Stuxnet path | No COTP/S7 speaker | SZL read (S); STOP/START/write gated (D); map to Siemens ProductCERT SSA |
| **DNP3** | OT | DNP3/TCP, DNP3/UDP, DNP3-SAv5 | **20000/tcp+udp**, 19999 (TLS) | Data-link frame `0x05 0x64` + read; parse link addrs; Class-0 poll | nmap `dnp3-info`(Redpoint, same script), opendnp3, scapy DNP3, Wireshark; ⚠*no MSF DNP3 module exists*; ⚠*Aegis fuzzer is private* | No auth/enc on legacy; ~30 attack classes; Kepware master infinite-loop DoS (ICSA-13-226-01) | No DNP3 decoder | Class-0 read poll (S); operate/CROB control objects gated (D); dominant in US power/water |
| **EtherNet/IP + CIP** | OT | ENIP encapsulation, CIP, PCCC, CIP-Security (TLS/DTLS) | **44818/tcp**, 2222/udp (I/O), 44818/udp (browse) | ENIP **ListIdentity (0x63)** → vendor/device/product/serial | nmap `enip-info`, Redpoint `enip-enumerate`, MSF `admin/scada/multi_cip_command` (CPU STOP/crash), cpppo, pycomm3, ISF | No auth/enc default; unauth CIP CPU STOP / crash Ethernet card; PCCC MicroLogix DoS (CVE-2017-7924) | No ENIP/CIP speaker | ListIdentity (S); forward-open/STOP gated (D). ⚠*CIP ≠ an OT:ICEFALL headline vendor — it shares the insecure-by-design class* |
| **OPC-UA** | OT | OPC UA Binary (opc.tcp), UA HTTPS (binary/JSON) ⚠*(SOAP deprecated v1.03)*, PubSub | **4840/tcp**, 4843 (TLS), 49320 (KEPServerEX), 62541 (ref stack), 48050 (UaGateway) ⚠*(443 is generic HTTPS, not UA-assigned)* | opc.tcp HELLO/ACK → GetEndpoints → policies (None/Basic256Sha256), cert | OpalOPC, Claroty Team82 OPC-UA Exploit Framework, FreeOpcUa (python-opcua/asyncio), UaExpert; ⚠*MSF modules are 3rd-party `COMSYS/msf-opcua`, not built-in; no Nmap OPC-UA NSE script exists* | Anonymous + SecurityPolicy None rampant; cert-trust bypass; stack overflows→RCE (ICSA-17-243-01) | No opc.tcp handshake | **Highest-value first OT integration** (most IT-like). GetEndpoints + None-policy + cert test (S) |
| **IEC 61850 (MMS / GOOSE / SV)** | OT | MMS (ISO-on-TCP), GOOSE (L2 **0x88B8**), SV (L2 **0x88BA**), IEC 62351 | **102/tcp** (MMS); **L2 multicast** (GOOSE/SV — no port) | MMS: COTP+Initiate→GetNameList. GOOSE/SV: SPAN capture by Ethertype/APPID/gocbRef/stNum | libiec61850, Wireshark MMS/GOOSE/SV, scapy GOOSE injectors (`goosestalker`, `goose-IEC61850-scapy`) | GOOSE has no auth; one spoofed frame trips a breaker; predictable stNum/sqNum; L2 → IP firewalls can't filter | (1) MMS speaker; (2) **passive L2 capture** | MMS GetNameList (S); GOOSE injection ultra-gated (D, physically trips equipment) — passive-only by default |
| **PROFINET** | OT | PROFINET IO-RT (raw **0x8892**), DCP (L2), RPC over UDP | **34962-34964/udp** (+53247), raw L2 0x8892 (+0x88E3 MRP) | **DCP Identify-All** = L2 broadcast → station/IP/MAC/vendor; 34964 RPC mapper | scapy `pnio.py`/`pnio_rpc.py`, profinet-dcp scanners, Wireshark pn-dcp/pn-io, Siemens PRONETA | No auth; spoofed DCP Set reassigns IP/name → DoS; inherits L2 attacks. ⚠*CBA/DCOM removed from IEC 61784-1 (2014) — legacy only* | Critical traffic is **L2, invisible to IP sockets** | On-segment L2 DCP Identify (S, but needs raw-socket/SPAN); ⚠*Profibus proper is serial — separate entry* |
| **BACnet/IP** | OT | BACnet/IP (BVLC), /Ethernet, MS/TP | **47808/udp** (0xBAC0), 47808-47823 (multi-net) | **Who-Is**→I-Am or ReadProperty(Device) → vendor/model/fw/location | nmap `bacnet-info`, Redpoint `BACnet-discover-enumerate`, BAC0, bacpypes, MSF `bacnet_l3`, Wireshark | Stateless no-auth; WriteProperty overrides setpoints / unlocks doors / disables fire alarms; ~18,700 on Shodan; UDP amplification (BAF ~20-30) | No BACnet speaker | **Flagship building OT.** Who-Is/ReadProperty (S); WriteProperty gated (D, actuates HVAC/fire/access) |
| **Niagara Fox / Tridium** | OT | Fox (plaintext), Foxs (TLS), foxwss (4.15+) | **1911/tcp** (Fox), **4911/tcp** (Foxs) ⚠*(3011/5011 non-standard, not defaults)* | Fox `fox a 0` hello banner → version/host/IP/OS/TZ/station | nmap `fox-info`(Redpoint), Shodan; ⚠*no maintained MSF Fox module — exploitation is PoC code (CVE-2012-4701/4027 traversal+cred disclosure)* | Banner pre-auth info leak; Nozomi 2025 13-CVE chain → root RCE; ~20k US Shodan / 50k+ buildings | No Fox banner grabber | **Trivial, high-value recon** (S). 1911/4911 banner parser; map to Nozomi CVE set |
| **IEC 60870-5-104** | OT | IEC-104 (APCI/ASDU/TCP), IEC-101 (serial parent) | **2404/tcp** (+TLS variant) | STARTDT_act → STARTDT_con; Interrogation **C_IC_NA_1 (type 100, QOI=20)** → IOA/CASDU | nmap `iec-identify`, MSF `auxiliary/client/iec104/iec104`, lib60870, QTester104, scapy, Wireshark | Plaintext no-auth; spoofed control (C_SC/C_DC/C_RC) opens breakers; source-IP spoof accepted | No IEC-104 decoder | STARTDT + read interrogation (S); control ASDUs gated (D). Non-US grids (EU/China) |
| **CODESYS Runtime** | OT | CODESYS V2, V3 | ⚠**V2 = 1200/2455/tcp; V3 = 11740/tcp (+1217, udp 1740-1743)** *(2455 is V2, not V3)* | Redpoint `codesys-v2-discover` (1200/2455); banner reveals OEM PLC | Redpoint NSE, MSF codesys aux modules, Team82/Nozomi PoCs; ⚠*ICSSPLOIT has no CODESYS module* | Unauth (Festo CVE-2022-3079 DoS); V3 SDK overflows→RCE (16 CVEs, 2023); Nozomi 2025 chain (41658/59/60) | No CODESYS probe | **One hit ⇒ whole OEM fleet** (WAGO/Festo/Beckhoff…). Priority fingerprint for unknown PLCs (S) |
| **OMRON FINS** | OT | FINS/TCP, FINS/UDP | **9600/tcp+udp** | FINS CPU Unit Data Read (0x0501) → model/fw/area sizes | Redpoint `omrontcp-info`/`omronudp-info`, nmap `omron-info`, ISF, Wireshark | Auth bypass by spoofing / capture-replay (ICSA-19-346-02, CVE-2019-18259); mem R-W | No FINS speaker | CPU-data-read (S); memory/program write gated (D). Major Asian/global vendor |
| **HART-IP** | IoT | HART-IP (TCP/UDP), WirelessHART (IEC 62591) | **5094/tcp+udp** *(session-init port; may move to server-selected port)* | HART **Command 0** (Read Unique ID) → mfr/device-type/ID/rev | **nmap `hartip-info`** *(omitted from research; the best off-the-shelf tool)*, Wireshark HART-IP, hipserver, DTM tools | CVE-2020-16209 (CVSS 9.8) hipserver overflow→RCE (ICSA-20-287-04); DTM XML injection | No HART-IP support | Command-0 enum of field instruments behind gateway (S); writes hard-gated (D, deepest/most fragile tier) |
| **Vendor PLC long-tail** (GE-SRTP, PC Worx, ProConOS, MELSEC/SLMP, FANUC FOCAS) | OT | GE-SRTP, PC Worx, ProConOS, MELSEC/SLMP, FOCAS | 18245, 1962, 20547, 5006-5007, 5002 | Redpoint per-protocol NSE native ID query → model/fw | Redpoint (`pcworx-info`, `proconos-info`, ge-srtp), plcscan, ISF, w3h/icsmaster NSE, ITI ICS-Security-Tools PORTS.md | Family weaknesses: no/weak auth, plaintext, unauth read, malformed-packet DoS; OT:ICEFALL-class | **Zero coverage of the long-tail** | Ingest full **Redpoint + w3h/icsmaster NSE corpus + plcscan** + ITI port table (S) |

### 2b. Building automation / AV (BAS/BMS, AV control, lighting, access, building RF)

| Family | Cat | Protocols | Default ports | Fingerprint | Existing tools | Key risks | ARGUS gap | Integration |
|---|---|---|---|---|---|---|---|---|
| **Crestron (CIP/CTP)** ✅*template* | IoT | CIP, CTP, secure CIP (TLS) | 41794/udp+tcp, 41795/tcp | UDP 0x14 probe → ~394-byte 0x15 response (host/fw/MAC); CTP banner | **`agents/avot`** (recon+SAST+fuzzer), `crestron_getsudopwd`, MSF CVE-2019-3929, AMP-Research CIP probe | CVE-2018-11229 unauth CTP RCE; CVE-2018-13341 crengsuperuser; CVE-2019-3929 RCE; UDP amplification | **Already covered** — the reference module | Existing template (§4) |
| **AMX NetLinx (ICSP)** | IoT | ICSP, ICSP/TLS, telnet | 1319/tcp+udp, 1320 (TLS) | ICSP on 1319; NetLinx telnet/HTTP banner | nmap, telnet/HTTP grab, NetLinx Studio | **CVE-2016-1984 hardcoded backdoor** ('BlackWidow'/'1988', ICSA-16-049-02) | No ICSP probe | 1319/1320 fingerprint + backdoor-cred check (I) |
| **Extron IPCP (SIS)** | IoT | SIS over telnet/TCP, HTTP/SSH | 23, 80, 443, 22 | Telnet/HTTP banner; SIS ASCII command interface | nmap+banner, MSF CVE-2019-3929, netcat SIS | CVE-2019-3929 (shared AV-box RCE); default/no telnet password | No SIS fingerprint | SIS banner + shared CVE-2019-3929 module (I) |
| **Lutron lighting (LIP)** | IoT | LIP/telnet, LEAP (TLS) | 23, 443 | Telnet → `GNET>` LIP prompt (default IP .50) | telnet/nmap, OpenVAS default-creds, raw LIP scripting | Default creds `lutron/integration`, `nwk/nwk2`; plaintext full light/shade control | No LIP fingerprint | LIP banner + default-cred check (I); control = D |
| **Savant (RacePoint)** | IoT | RacePoint Blueprint, HomeKit, HTTP | 80, 443, 22 | Web admin + RPM + mDNS/Bonjour; macOS host | nmap, mDNS enum, default-cred, web-stack pentest | Default RPM creds / unauth Local-User; macOS host surface | No Savant fingerprint | Bonjour+web fingerprint + default-cred (I) |
| **KNX / KNXnet/IP** | OT | KNXnet/IP (tunnel+routing), KNX Secure | **3671/udp+tcp**, mcast 224.0.23.12 | nmap `knx-gateway-discover` (Search Req to mcast); `knx-gateway-info` Description Req → addr/MAC/name | nmap KNX NSE, **KNXmap**, knxd/EIBD, Wireshark | No auth; plaintext passwords; any client R/W group addresses (lights/HVAC/doors); restart DoS | No KNX UDP/mcast discovery | Search/Description discovery (S) + KNXmap bus enum; group write/restart gated (D) |
| **LonWorks / LonTalk (IP-852)** | OT | LonTalk (CEA-709.1), IP-852, OMA digest | 1628/1629 udp+tcp | IP-852 router traffic; Neuron/program ID; L-IP/i.LON banner | Wireshark CEA-709.1, LonScanner, SNMP/HTTP enum | Single shared key; unencrypted app data; OMA digest key-recovery (2015); gateway default creds | No LON coverage | 1628/1629 discovery + Neuron-ID enum + gateway default-cred (I) |
| **DALI / DALI-2 / DALI+** | OT | DALI (2-wire bus), DALI+ (IP/wireless), gateways→Modbus/BACnet/KNX | via gateway: 502, 47808, 80/443 | Fingerprint the **DALI-IP gateway** (web/Modbus regs/BACnet objects/mDNS) | gateway web pentest, Modbus/BACnet/KNX tools, physical bus tap | Wired DALI no auth (incl. **emergency/egress lighting**); gateways inherit north-side weak auth + default web creds | No DALI gateway recognition | Pivot via Modbus/BACnet/KNX parsers; gateway default-cred (I) |
| **OSDP access control** | OT | OSDP (RS-485), Secure Channel (AES-128) | RS-485 serial (no IP) | Poll/ack + capability (osdp_CAP); SCBK presence = encryption state | **Bishop Fox `mellon`**, LibOSDP, RS-485 tap | DEF CON 31 'Badge of Shame' >12 vulns: downgradable encryption, **SCBK-D hardcoded key**, persistent install-mode | **RS-485/physical — outside IP model** | Serial/OSDP-over-IP adapter (P2); findings for install-mode/SCBK-D (I) |
| **Legacy Wiegand** | OT | Wiegand (D0/D1 one-way) | GPIO/serial (no IP) | 26/37-bit pulse framing inline | **ESPKey**, BLEKey, Proxmark3 | Unencrypted one-way; inline implant logs+replays badges; clonable prox | Physical-only — outside IP scope | Physical-engagement playbook (P2); recommend OSDP-Secure migration |
| **Z-Wave (building)** | IoT | Z-Wave (G.9959), S0/S2 | RF 908.42/868.42 MHz (no IP) | RF capture; home-id/node-id; unencrypted NIF carries security class | EZ-Wave, scapy-radio, HackRF/RTL-SDR, Z-Force | **Z-Shave** S2→S0 downgrade; all-zero key sniff at pairing; ~100M chips | **No sub-GHz RF** | SDR hardware-bridge (P2) |
| **Zigbee (building)** | IoT | 802.15.4, Zigbee PRO/ZHA/ZLL, EZSP | RF 2.4 GHz ch 11-26 (no IP) | Channel scan; PAN-ID/TC addr; sniff join/transport-key | **KillerBee** (zbstumbler/zbdump/zbreplay), Attify, Wireshark | Default TC link key 'ZigBeeAlliance09' → NWK key sniff at join; replay; unauth OTA | **No 802.15.4 RF** | 802.15.4 radio bridge (P2) |
| **Elevators / lifts (BMS-integrated)** | OT | BACnet/Modbus gateways, CANopen-Lift, Niagara | 47808, 502, 1911/4911, 80/443 | Gateway BACnet objects ('Elevator'/'Lift'/dispatch); vendor web | BACnet/Modbus/Niagara tools, vendor web pentest | Writable BACnet/Modbus points → recall/disable cars; **life-safety actuation** | Reached via existing parsers, but… | **Strict life-safety classifier** (elevators/fire/egress/locks = read-only, no actuation without explicit auth) (D) |

### 2c. Consumer / enterprise IoT

| Family | Cat | Protocols | Default ports | Fingerprint | Existing tools | Key risks | ARGUS gap | Integration |
|---|---|---|---|---|---|---|---|---|
| **MQTT** | IoT | MQTT 3.1.1/5 (TCP/TLS/WS) | **1883**, 8883 (TLS), 8080/9001 (WS) | CONNECT→CONNACK; subscribe `#`/`$SYS/#` → broker version/clients. *1883 not in nmap top-1000* | nmap `mqtt-subscribe`, mosquitto_sub/pub, MQTT-PWN, MQTTSA | No auth by default; anonymous connect + wildcard `#` exposes all telemetry/commands; plaintext injection | No MQTT probe (treats 1883 as unknown) | Anonymous CONNECT + topic enum + writable-topic flag (S→I) |
| **CoAP** | IoT | CoAP/UDP, CoAPs/DTLS, CoAP/TCP | **5683/udp**, 5684 (DTLS) | CON GET `/.well-known/core` → CoRE Link resources | nmap `coap-resources`, libcoap `coap-client`, aiocoap | Reflection/amp DDoS (27-34×); no-auth resource enum; weak/disabled DTLS | No UDP CoAP probe | GET `/.well-known/core` + amp-factor measure (S) |
| **AMQP / RabbitMQ** | IoT/IT | AMQP 0-9-1/1.0, TLS | **5672**, 5671 (TLS), **15672** (mgmt) | Connection.Start → product/version/SASL; 15672 mgmt UI/`/api` | nmap `amqp-info`, rabbitmqadmin, kcat, MSF | Default `guest:guest` (remote-enabled in many Docker/IoT images); queue secrets; message injection; Kafka JndiLoginModule RCE (CVE-2025-27819) | No AMQP/Kafka speaker | Banner + default-cred + vhost/queue enum (I) |
| **UPnP / SSDP** | IoT | SSDP (HTTPU/UDP), UPnP SOAP, GENA | **1900/udp**, 49152-49160/80/5000 (HTTP) | M-SEARCH→LOCATION rootDesc.xml→SCPD services | nmap `upnp-info`, Miranda, MSF `upnp_igd_soap_portmapping`, evilSSDP | IGD AddPortMapping pivot; SSDP amplification; CallStranger (CVE-2020-12695); spoof/phish | No SSDP discovery | M-SEARCH + rootDesc fetch + IGD abuse + CallStranger (S→I) |
| **mDNS / DNS-SD** | IoT | mDNS (UDP), DNS-SD | **5353/udp** (224.0.0.251) | `_services._dns-sd._udp.local` → PTR/SRV/TXT service inventory | nmap `dns-service-discovery`, Pholus, bettercap zerogod, Responder, avahi-browse | Leaks host/service/OS inventory; mDNS poisoning → NTLM capture | No mDNS stage (huge recon win) | Service-inventory harvest (S) + Responder-style poisoning (I) |
| **ONVIF / RTSP cameras + NVRs** | IoT | ONVIF (SOAP/WS), WS-Discovery, RTSP, RTP | **554** (RTSP), **3702/udp** (WS-Disc), 80/8000/8080/37777(Dahua)/8000(Hik) | WS-Discovery Probe→scopes; RTSP OPTIONS/DESCRIBE; ONVIF GetDeviceInformation | **Cameradar**, nmap `rtsp-url-brute`/`rtsp-methods`, ONVIF Device Mgr, Ingram, hydra | Default creds; Hikvision/Dahua backdoors+RCE (CVE-2017-7923/2018-6414); ONVIF token replay (CVE-2022-30563); Mirai | No WS-Discovery / RTSP brute | WS-Discovery + RTSP path/cred brute + camera CVE/cred KB (I) |
| **Network printers (IPP/PJL/JetDirect)** | IoT | IPP, PJL, PostScript/PCL, Raw 9100, SNMP, LPD | **9100**, 631 (IPP), 515 (LPD), 161 (SNMP) | 9100 `@PJL INFO ID`; IPP Get-Printer-Attributes; SNMP Printer-MIB | **PRET**, praeda, nmap ipp/pjl, snmpwalk | PJL path traversal (steal jobs/creds), NVRAM tamper, persistent firmware; CUPS RCE (CVE-2024-47176) | No printer module | PJL INFO + PRET FS/config + IPP + Printer-MIB (I) |
| **NAS (Synology/QNAP/WD/…)** | IoT/IT | SMB/AFP/NFS, DSM/QTS web, FTP, rsync, iSCSI | 445/139, 548, 2049, 5000-5001, 8080/443 | Web-admin banner (DSM/QTS) + version; mDNS/SSDP | nmap smb/http NSE, enum4linux, MSF synology/qnap, searchsploit | DeadBolt/eCh0raix ransomware (CVE-2022-27593, 2021-28799); Netatalk RCE; weak creds | NAS-aware fingerprint + curated CVE/cred KB | DSM/QTS version extraction + NAS CVE map (I) — transport already in wheelhouse |
| **Smart-home hubs (Hue/SmartThings/Tuya/Tapo/HA)** | IoT | REST/HTTP, MQTT, CoAP (Tuya 6668), mDNS/SSDP, RF bridges | 80/443, 1883/8883, 6668, 8123, 5353/1900 | mDNS/SSDP → model+API URL; Hue `/api`+`/description.xml`; HA `/api`; Tuya 6668 | curl/Postman, tinytuya, mosquitto_sub, binwalk, frida | Cleartext token/key storage (Tapo H200); unauth local APIs; **IP→RF mesh pivot** | Hub fingerprint + token-exposure + firmware extract | mDNS/SSDP+HTTP fingerprint; treat compromised hub as RF pivot (I) |
| **Routers / CPE (TR-069/CWMP)** | IoT/IT | CWMP (SOAP/HTTP), web admin, telnet/SSH, UPnP IGD | **7547** (CWMP), 80/443, 23, 22, 1900 | 7547 HTTP server header (RomPager/AllegroSoft); web-admin/telnet banner | **RouterSploit**, nmap, MSF misfortune_cookie, binwalk+FMK, hydra | TR-069 RCE (Mirai/DT 900k outage); Misfortune Cookie; default ACS/admin creds; firmware backdoors | CPE module + firmware-analysis pipeline | 7547 fingerprint + RouterSploit autopwn + binwalk (I) |
| **BLE** | IoT | BLE LL, GAP/ATT/GATT, SMP | RF 2.4 GHz (no IP) | Advertising scan → MAC/name/UUIDs; GATT enum | hcitool/gatttool, bettercap ble.*, Btlejack, nRF Connect, SweynTooth | Just-Works no MitM; unauth GATT R/W; KNOB (CVE-2019-9506); SweynTooth; relay | **No BLE hardware** | HCI/Ubertooth bridge + GATT engine (P2) |
| **Thread / Matter** | IoT | Thread (802.15.4/6LoWPAN), Matter (UDP 5540, mDNS) | RF 802.15.4; UDP 5540; 5353/udp | Matter mDNS `_matterc._udp` → discriminator/VID/PID; PASE/SPAKE2+ | chip-tool, OpenThread, Wireshark, KillerBee, BH-EU24 PoCs | 'Breaking Matter' (BH-EU24); open-commissioning passcode guessing; multi-fabric surface | **Split**: mDNS is IP (P1), Thread mesh RF (P2) | mDNS Matter-discovery (S) + passcode-guess + RF bridge (P2) |
| **LoRaWAN** | IoT | LoRa PHY, LoRaWAN MAC v1.0.x/1.1, OTAA/ABP | RF 868/915 MHz; backend MQTT/HTTP | Air: Join-Req/Accept frames (DevEUI/DevAddr). Backend over IP | **LAF (IOActive)**, LoRattack, ChirpStack, HackRF/LoStik, gr-lora | v1.0 replay (DevNonce); weak AppKey brute from Join MIC; v1.1→1.0 downgrade | **Split**: RF air (P2), backend IP (P1) | RF bridge + AppKey brute (P2); recognize backend servers (P1) |

### 2d. Vertical OT-IoT (medical, automotive/transport, maritime/rail, energy, physical, industrial wireless)

| Family | Cat | Protocols | Default ports | Fingerprint | Existing tools | Key risks | ARGUS gap | Integration |
|---|---|---|---|---|---|---|---|---|
| **DICOM (PACS/modalities)** | IoT | DUL/DIMSE (C-ECHO/STORE/FIND/MOVE), DICOMweb | **104**, **11112**, 2762 (TLS), 4242, 443/8042 (web) | Partial C-ECHO (A-ASSOCIATE-RQ) → impl-class UID; AET-check detection | nmap `dicom-ping`/`dicom-brute`, DCMTK, pydicom/pynetdicom, IOActive tooling | No TLS (PHI plaintext); AET brute/disabled; unauth C-STORE inject; PE-DICOM polyglot; ~3.6-5.3k exposed | No DICOM parser | dicom-ping/brute + AET enum + read-only C-ECHO + PHI classifier (S→I) |
| **HL7 v2.x over MLLP** | IT | HL7 v2.x (ER7), MLLP framing | **2575**, often 5000-6999 | MLLP frame (0x0B…0x1C 0x0D) + MSH segment; ACK on crafted MSH | HAPI, python-hl7, Mirth, netcat, Wireshark hl7 | Cleartext no-auth; forged orders/results; EHR data poisoning | Treated as generic TCP | MLLP framer + HL7 segment parser + read-only ACK probe (S) |
| **HL7 FHIR / SMART-on-FHIR** | IT | FHIR REST (HTTPS), OAuth2/SMART, IHE | 443, 80, 8080 | `/metadata` CapabilityStatement; `/.well-known/smart-configuration` | Burp/ZAP, Inferno, Postman FHIR, fhir-validator | OAuth scope creep; BOLA/IDOR on `/Patient/{id}`; missing rate-limit | No FHIR-aware module | FHIR cap-statement parse + scope/BOLA cases — **extends web-vuln subagent** (I) |
| **Networked medical devices (pumps/monitors/programmers)** | IoT | Vendor TCP/UDP, embedded web/telnet/SSH, HL7/DICOM uplinks, RF (MICS/WMTS) | 23/21/80/443/161, vendor UDP | Embedded banner/SNMP; vendor OUI→model; CISA/FDA advisory→CVE | nmap+http/telnet/snmp, Armis/Medigate (ref), binwalk | Contec CMS8000 backdoor+UDP RCE; CVE-2021-33882 no-auth pump commands; MedJack pivot; **safety-of-life** | Asset-classification + FDA/ICS-Medical feed | OUI+banner→model + advisory feed + **strict passive/read-only** (S — active probes crash devices) |
| **CAN bus + UDS** | OT | CAN/CAN-FD, ISO-TP, UDS, OBD-II, DoIP | OBD-II pins; **DoIP 13400/tcp+udp**; raw CAN (serial) | Passive CAN sniff; UDS 0x10/0x3E; 0x22 (VIN/fw); 0x27 seed/key | **Caring Caribou** ('nmap of automotive'), can-utils, ICSim, NetHunter CARsenal, MSF HWBridge | CAN no auth (every node trusts every frame); weak UDS seed-key; ECU reflash; bus-off DoS | **No CAN/serial transport** | SocketCAN/HWBridge adapter + UDS scanner; **passive-first** (S); DoIP 13400 probe (P1) |
| **SAE J1939 (heavy vehicle)** | OT | J1939 (PGN/SPN), TP.CM/BAM, DM diagnostics, telematics | Deutsch connector (CAN); telematics MQTT/HTTPS | Passive 29-bit ID sniff; address-claim PGN 60928; DM1/DM2 | can-utils J1939, Caring Caribou, TruckDevil, Wireshark J1939 | Fleet-scale CAN trust flaw; TP.CM/BAM abuse; telematics→bus remote entry; one exploit → many makes | Same CAN gap + J1939 decode | J1939 PGN/SPN decode + telematics IP correlation (P2) |
| **DLMS/COSEM (smart meters/AMI)** | OT | DLMS/COSEM (IEC 62056), OBIS, TCP/HDLC/PLC/RF | **4059/tcp+udp** (4060-4063) | AARQ→AARE (security level); OBIS logical-device-name read | **Gurux DLMS**, pydlms, CyTAL, Wireshark DLMS | Unencrypted headers; LLS plaintext password; mass remote disconnect (load-shed); billing fraud | No DLMS/OBIS stack | 4059 AARQ + security-level + OBIS enum + default-pw (I); RF/PLC link (P2) |
| **Maritime (NMEA/AIS/ECDIS)** | OT | NMEA 0183/2000, AIS (VHF), ECDIS | NMEA-over-IP ~10110; ECDIS Windows host; AIS RF | Sniff NMEA `$GP*/$AI*`; ECDIS = Windows host; AIS AIVDM/MMSI | gr-ais+RTL-SDR, canboat, OpenCPN, Windows pentest stack, Wireshark NMEA/AIS | Plaintext no source-auth; GPS/heading injection grounds vessels; AIS ghost ships; ECDIS outdated OS | Can scan ECDIS host; no NMEA/AIS/CAN/VHF | NMEA-over-IP parse (P1) + NMEA-2000 CAN + AIS SDR (P2) |
| **Rail (ETCS/CBTC/balise)** | OT | ETCS (EuroRadio/GSM-R), Eurobalise (FSK), CBTC (Wi-Fi/IP), interlocking PLC | CBTC wayside IP/Wi-Fi; balise 4.234 MHz; GSM-R | nmap wayside PLCs (Siemens/Hitachi/Thales); SDR balise/EuroRadio | RTL-SDR/HackRF+GNU Radio, ICS modules, PLCScan/snap7 | Balise jamming; EuroRadio MITM→collision; CBTC zone-controller exposure; **safety-of-life** | IP/PLC layer via ICS ext; no SDR/GSM-R | ICS PLC probes on wayside (P1) + SDR (P2) + rail risk model |
| **IP cameras (surveillance)** | IoT | *(see ONVIF/RTSP §2c — same family, deduplicated)* | 554, 3702/udp, 80/8000/37777 | WS-Discovery + RTSP + ONVIF GetDeviceInformation | Cameradar, nmap rtsp NSE, MSF hik/dahua, Ingram | Dahua/Hik backdoors+RCE; ONVIF replay; Mirai; surveillance compromise | (merged with ONVIF/RTSP) | (merged) — ONVIF/RTSP module (I) |
| **Physical access (badge readers)** | IoT | Wiegand, OSDP, 125 kHz prox, 13.56 MHz | RS-485/2-wire (no IP); panel web/telnet | RFID/NFC UID; Wiegand tap; OSDP Secure-Channel state; panel banner | **Proxmark3**, **Flipper Zero**, ESPKey, mfcuk/mfoc, LibOSDP | 40-yr plaintext Wiegand skim/replay; ~70% clonable prox; MIFARE crack; OSDP w/o Secure Channel | Reader = RF/RS-485 (no cap); CAN scan the IP panel | RFID/Wiegand/OSDP HW adapter + panel-CVE KB (P2); scan IP panel (P1) |
| **WirelessHART (IEC 62591)** | OT | WirelessHART, 802.15.4 TSCH, AES-128 | RF 2.4 GHz; gateway Modbus 502 / HART-IP 5094 | 802.15.4 TSCH sniff; gateway HART-IP/Modbus banner | KillerBee+CC2531, ApiMote, GNU Radio, HART-IP/Modbus tools | AES protects payload but TSCH schedule enables selective jamming; join-flood DoS; gateway = soft pivot | No 802.15.4 RF; reach via gateway IP | Gateway HART-IP/Modbus probe (P1) + 802.15.4 SDR (P2) |
| **ISA100.11a (IEC 62734)** | OT | ISA100.11a, 802.15.4, 6LoWPAN/IPv6/UDP, 2-tier AES | RF 2.4 GHz; gateway Modbus 502 / OPC-UA 4840 | 802.15.4 sniff (6LoWPAN/IPv6+UDP distinguishes from WirelessHART); gateway banner | KillerBee/ApiMote, SDR+GNU Radio, 6LoWPAN tools, OPC-UA/Modbus | Stronger 2-layer AES but shares selective-jamming/join-flood; provisioning errors; gateway pivot | Same as WirelessHART | Unified industrial-wireless module via gateway IP (P1) + RF (P2) |

### 2e. IT frontier

| Family | Cat | Protocols | Default ports | Fingerprint | Existing tools | Key risks | ARGUS gap | Integration |
|---|---|---|---|---|---|---|---|---|
| **Cloud IMDS (AWS/Azure/GCP)** | IT | HTTP link-local 169.254.169.254 (+per-cloud token/header) | 80 (link-local) | AWS PUT token/GET meta-data; Azure `Metadata:true`; GCP `Metadata-Flavor:Google` | curl/SSRF, **Pacu**, weirdAAL, ScoutSuite/Prowler, cloud_enum | IMDSv1 SSRF→STS creds (Capital One); Azure/GCP single-header weak; managed-identity privesc | **Stops at SSRF — no IMDS pivot** | **Stateful SSRF→IMDS→IAM** credential workflow (I) |
| **Cloud object storage (S3/Blob/GCS)** | IT | HTTPS REST | 443 | `<bucket>.s3.amazonaws.com` etc; anon GET → ListBucketResult vs AccessDenied | cloud_enum, S3Scanner, lazys3, GrayhatWarfare, awscli | ~36% orgs have public S3; world R/W ACL; writable→JS supply-chain poison | No cloud-storage recon | Name-permutation + anon R/W/list grading (S) |
| **Kubernetes (API/kubelet/etcd)** | IT | kube-apiserver REST, kubelet, etcd v3 gRPC | **6443**/443, **10250**/10255, **2379**/2380, 30000-32767 | `/version`,`/healthz`; kubelet `/pods`; etcd `/version` | **kube-hunter**, kubectl, kubeletctl, Peirates, etcdctl, kube-bench | Anonymous-auth; read-only kubelet 10255 leaks SA tokens; etcd no client-cert → all Secrets; →cluster-admin | No K8s API speakers | K8s/kubelet/etcd clients + anon-auth tests + SA-token pivot (I) |
| **Docker Engine / Registry** | IT | Docker Engine REST, Registry v2 | **2375** (no-auth), 2376 (TLS), 5000 | `/version`,`/info`,`/containers/json`; Registry `/v2/_catalog` | docker CLI, nmap, MSF docker modules, DockerRegistryGrabber | 2375 unauth → privileged container bind-mounts host `/` → root; registry leaks images/secrets | No Docker/OCI speakers | 2375/5000 fingerprint + container-escape PoC + registry dump (I→D) |
| **Active Directory / SMB** | IT | SMB2/3, MS-RPC/DCERPC, NetBIOS | **445**, 139, 135, 137-138/udp | Negotiate → dialect/OS/domain/signing; null session enum | nmap smb NSE, enum4linux-ng, smbmap, **NetExec/CrackMapExec**, **Impacket**, **Responder+ntlmrelayx** | Null-session enum; no SMB signing → **NTLM relay**; EternalBlue; spray; secretsdump | Banner-only — misses relay/lateral chains | Full SMB/DCERPC speaker + null-session + **NTLM capture/relay** (I→D) |
| **Kerberos (AD KDC)** | IT | Kerberos 5 (AS/TGS), kpasswd | **88/tcp+udp**, 464, 749 | 88+389+53 = DC; `krb5-enum-users` AS-REQ | **Impacket** GetNPUsers/GetUserSPNs, **Rubeus**, kerbrute, hashcat (13100/18200) | **Kerberoast** (TGS hash crack); **AS-REP roast** (no creds); Golden/Silver tickets | No Kerberos abuse | DC fingerprint + AS-REP/Kerberoast + offline crack pipeline (I) |
| **LDAP / Global Catalog** | IT | LDAP v3, LDAPS, MS GC | **389**, 636, **3268**, 3269 | rootDSE (base, scope=base) → naming contexts; anon bind | nmap ldap NSE, ldapsearch, windapsearch, **BloodHound/SharpHound**, NetExec | Anon/null bind leaks users/groups/OUs (passwords in description); LDAP relay→RBCD/DCSync | Open port noted, directory not harvested | rootDSE/anon-bind enum → **BloodHound attack graph** (I) |
| **GraphQL APIs** | IT | HTTP POST (JSON) | 443, 80, `/graphql` | `{__typename}`; introspection `{__schema{types{name}}}`; graphw00f | **InQL**, graphw00f, **Clairvoyance**, GraphQLmap, GraphCrawler | Introspection exposes admin mutations; batching/alias DoS; BOLA/BFLA; injection; mass-assignment | Classic scanner sees one opaque POST | Endpoint detect + introspection/Clairvoyance + per-op authz fuzz (I) |
| **gRPC / Protobuf** | IT | gRPC over HTTP/2 (TLS/h2c), protobuf, gRPC-Web | 443, **50051** | HTTP/2 `application/grpc`; ServerReflection → all methods | **grpcurl**, Postman, BloomRPC, protoc, Burp grpc-web | Reflection exposes admin/debug methods; metadata authz bypass; gRPC-Web CSRF; missing per-method authz | **No HTTP/2+protobuf client** | HTTP/2+protobuf client + reflection enum + RPC fuzz (I) |
| **REST APIs (OWASP API Top 10)** | IT | HTTP REST/JSON, OpenAPI/Swagger | 443, 80, `/api`,`/v1` | `/swagger.json`,`/openapi.json`; predictable IDs; JWT | Postman, Burp+Autorize, ffuf/feroxbuster, Kiterunner, nuclei, jwt_tool | **BOLA/IDOR (#1)**; BFLA; mass-assignment; weak JWT; no rate-limit; SSRF | No OpenAPI-driven authz-differential | Spec ingest + multi-identity authz-diff (BOLA/BFLA) + JWT (I) |
| **Message queues (AMQP/Kafka/MQTT/Redis)** | IT | AMQP, Kafka wire, MQTT, STOMP | 5672/15672, **9092**, 1883/8883, 2181 | `amqp-info`; Kafka ApiVersions; MQTT CONNACK | nmap `amqp-info`, kcat, MQTT-PWN, mosquitto_sub, MSF | guest:guest; Kafka ALLOW_PLAINTEXT_LISTENER; MQTT `#` subscribe; Kafka RCE (CVE-2025-27819) | No AMQP/Kafka speakers | Broker speakers + default-cred + topic R/W (I) |
| **Databases (MSSQL/MySQL/PG/Mongo/Oracle/Redis)** | IT | TDS, MySQL, PG FE/BE, Mongo wire, TNS, RESP | **1433**, 3306, 5432, 27017-19, 1521, **6379** | Per-protocol handshake; Mongo isMaster; Redis INFO/PING | nmap DB NSE, MSF DB modules, Impacket mssqlclient, ODAT, redis-cli, sqlmap | Default creds; MSSQL xp_cmdshell; Mongo no-auth; **unauth Redis→RCE**; hash dump | Fingerprint + no-auth/default-cred + exec chain | DB protocol clients + cred + exec-escalation (xp_cmdshell, Redis write) (I→D) |
| **VPN / edge appliances (Ivanti/Forti/Citrix/PAN/Cisco)** | IT | HTTPS SSL-VPN portals, IKE/IPsec, TLS | 443, **10443** (Forti), 500/4500 udp, 8443 | Portal paths/titles/headers (`/dana-na/`, `/remote/login`, `/vpn/`, `/global-protect/`); favicon hash | nmap http-title/ssl-cert, **nuclei** vendor templates, MSF, public PoCs, Shodan/FOFA | **#1 mass-exploited 2024-25**: Ivanti CVE-2025-0282/22457, Citrix Bleed (CVE-2023-4966), Forti/PAN 0-days; UNC5221 webshells | Currency + vendor-specific depth | Precise appliance/fw fingerprint + **continuously-updated edge-CVE feed** + safe version-check (S) |
| **Wi-Fi (WPA2/WPA3, captive portals)** | IT | 802.11, WPA2-PSK/WPA3-SAE, 802.1X/EAP, RADIUS | RF 2.4/5 GHz; 1812-13/udp; 80/443 | Beacon SSID/BSSID/RSN/AKM; EAPOL/PMKID capture | **aircrack-ng**, hcxdumptool/hcxtools, hashcat (22000/16800), Wifite, eaphammer, bettercap | PMKID/handshake offline crack; evil-twin; PEAP cred intercept; captive-portal phish; deauth | **Out-of-band — no monitor-mode RF** | Wireless capture+attack module + HW (P2) |

---

## 3. Deep dives

### 3.1 OT / ICS / SCADA — *reachability is control; do not blind-fuzz live OT*

The unifying fact: nearly every OT protocol — Modbus, S7comm, DNP3, EtherNet/IP, BACnet, IEC-104, FINS, the vendor long-tail — was built for an isolated, trusted bus and ships with **no authentication, no encryption, and no integrity**. Whoever can reach port 502/102/20000/44818/47808/2404/9600 can read, and (with a single write function code) often **command** the process. The threat model is **availability and physical safety first**, confidentiality last.

**How to test safely:**

1. **Passive-first.** Prefer SPAN/PCAP ingest (GRASSMARLIN doctrine) so the device topology and vendor/firmware fall out of observed traffic with *zero* packets sent. Active probing is only ever a read.
2. **Read-only function codes only by default.** Modbus FC 0x01/0x03/0x2B; S7 SZL read; DNP3 Class-0 poll; ENIP ListIdentity; BACnet Who-Is/ReadProperty; IEC-104 STARTDT + interrogation; FINS CPU-data-read. These are the "enumerate, never crash" Redpoint primitives.
3. **Hard-gate every write/control primitive** behind explicit engagement authorization (the D class): Modbus 0x05/06/0F/10; S7 STOP/START; DNP3 operate/CROB; ENIP forward-open/CPU-STOP; BACnet WriteProperty; IEC-104 C_SC/C_DC/C_RC; FINS program-area write. Even reads can crash fragile PLCs — so rate-limit and run the circuit breaker the `crestron_fuzzer` already implements.
4. **Layer-2 is invisible to ARGUS today.** GOOSE (0x88B8), SV (0x88BA), and PROFINET DCP (0x8892) have **no IP port** — they need raw-socket/SPAN capture on-segment. A spoofed GOOSE frame can physically trip a breaker (predictable stNum/sqNum), so GOOSE/SV injection is an *ultra-destructive* gate: passive-only by default.
5. **Map findings to CISA ICS-CERT advisories / OT:ICEFALL / vendor PSIRT (Siemens SSA, Rockwell)** — not just CVE/CVSS, which under-represents OT impact.

**Highest-value first integration: OPC-UA.** It is the modern, IP-native OT protocol most amenable to IT-style testing (opc.tcp HELLO/ACK → GetEndpoints → detect anonymous + SecurityPolicy None + cert-trust misconfig), with mature tooling (OpalOPC, Claroty Team82). **CODESYS** is the highest-leverage *fingerprint*: one hit on 1200/2455 (V2) or 11740 (V3) implicates an entire OEM PLC fleet (WAGO/Festo/Beckhoff/Schneider).

### 3.2 Building automation / AV — *the Crestron-class vertical ARGUS is already seeding*

This is the domain `agents/avot` was built for, and it generalizes cleanly. The pattern: **UDP/broadcast/multicast discovery on non-standard ports** (47808, 3671, 1628, 41794, 1911) rather than TCP-SYN/HTTP banner grabbing, plus **plaintext info-leak fingerprinting** (vendor/model/firmware/MAC over unauthenticated requests). BACnet/IP is the flagship (Who-Is → full device inventory; WriteProperty actuates HVAC/fire/access). Niagara Fox is the highest-ROI recon (a trivial 1911/4911 banner parse leaks version/host/IP, and chains to the Nozomi 2025 13-CVE root-RCE set). KNXnet/IP needs the multicast Search Request beacon.

**Safety classifier is mandatory here:** elevators, fire panels, egress/emergency lighting, and door locks are **life-safety points**. Even though ARGUS reaches them through the same BACnet/Modbus/Niagara parsers, they must be flagged **read-only / no-actuation** without explicit operator authorization. The DEF CON 31 OSDP work and Wiegand/Z-Wave/Zigbee families are **RF/RS-485/physical** and defer to the P2 hardware-bridge tier.

### 3.3 Consumer / enterprise IoT — *two tiers: IP-reachable now, RF later*

**Tier A (IP-reachable, do now):** MQTT (anonymous broker + `#` wildcard = all telemetry/commands), CoAP (`/.well-known/core` + amplification), UPnP/SSDP (IGD port-mapping pivot, CallStranger), mDNS/DNS-SD (a massive local-inventory recon win + Responder-style poisoning), ONVIF/RTSP cameras (WS-Discovery + Cameradar cred-brute + Hik/Dahua CVE KB), IPP/PJL printers (PRET filesystem/config access + CUPS RCE), NAS (DSM/QTS version + DeadBolt/eCh0raix), smart-home hubs (the IP→RF mesh pivot), and TR-069 CPE (RouterSploit + binwalk firmware analysis). Most need only a new probe + an IoT default-credential corpus.

**Tier B (RF — needs hardware, P2):** Zigbee (KillerBee, default TC key → NWK key at join), Z-Wave (Z-Shave S2→S0 downgrade), BLE (Just-Works GATT R/W, SweynTooth), Thread/Matter (mDNS half is IP-reachable now), LoRaWAN (LAF AppKey brute). These require an SDR/radio hardware-bridge ARGUS has no concept of — the single largest capability gap.

### 3.4 Vertical OT-IoT — *safety-of-life dominates; mostly hybrid IT+OT attack paths*

DICOM/HL7/FHIR/medical devices (PHI plaintext, AET-only access control, no-auth pump commands, **active probes crash safety-critical devices → strictly passive/read-only**, FDA/ICS-Medical advisory feed). Automotive CAN/UDS/J1939 (no-auth bus, weak seed-key, needs SocketCAN/HWBridge transport, **passive-first to avoid actuating a live vehicle**, DoIP 13400 is the IP-reachable foothold). DLMS/COSEM smart meters (4059, mass remote-disconnect load-shedding). Maritime NMEA/AIS/ECDIS (GPS injection grounds vessels; ECDIS is a scannable Windows host). Rail ETCS/CBTC (wayside PLCs are ICS-scannable; balise/EuroRadio need SDR). Industrial wireless WirelessHART/ISA100 (reach the **gateway over IP** — Modbus 502 / HART-IP 5094 / OPC-UA 4840 — as the practical entry point). The cross-cutting need: a **risk model that ranks availability/safety above confidentiality**, plus vertical CVE/default-cred feeds.

### 3.5 IT frontier — *credential-aware, stateful workflows ARGUS doesn't yet chain*

The frontier is less about new transports and more about **multi-step credential workflows**. An SSRF finding must **pivot** to IMDS (169.254.169.254, correct per-cloud header/token) → extract STS creds → enumerate IAM. An AD foothold must chain **Kerberoast/AS-REP roast → offline hashcat → lateral movement**; a null SMB session → BloodHound graph → Domain Admin path; SMB-signing-off → **NTLM relay (Responder/ntlmrelayx)**. GraphQL/gRPC need protocol-aware engines (introspection/reflection) that classic HTTP/1.1 scanners skip entirely. **VPN/edge appliances are the #1 mass-exploited initial-access vector of 2024-25** (Ivanti/Citrix-Bleed/Forti/PAN) and demand a *continuously-updated, version-specific* edge-CVE feed — currency is the gap, not detection mechanics. Wi-Fi is out-of-band (P2, needs monitor-mode RF).

---

## 4. Architecture recommendation for ARGUS

ARGUS already proves the right shape with `agents/avot`. The recommendation is to **promote that one-off into three first-class subsystems**, keeping the engine content-agnostic (so `test_no_hardcoded_attack_content` stays green).

### 4.1 The capability-module pattern (generalize `agents/avot`)

`agents/avot/recon.py` is the template. Every technology family becomes a self-contained module exposing the same two functions:

```python
# agents/<domain>/<tech>.py  — ALL tech-specific knowledge lives here, never in the engine
def detect(intel: dict) -> dict | None:        # port/banner/probe fingerprint → detection
def finding_for(detection: dict) -> dict:      # store_finding-shaped record (severity/title/…/mitre)
```

The engine already iterates this. `MasterAgent._avot_capability_scan()` (`agents/master_agent.py:4147`) calls `recon.detect(self._intel)`, dedups via `self._intel["_capability_detected"]`, injects an operator-guidance note (`_meta_advisory_context`), and stores the finding through the standard pipeline (`store_finding` with `FindingSeverity`, `tool_used`, `evidence`, `remediation`, MITRE). **Generalize this into `_capability_scan()`** that loops a **registry of registered detectors** instead of importing one module:

```python
CAPABILITY_MODULES = [          # the OT/IoT/IT registry (sub-project #5)
    ("agents.avot.recon",        "OT"),   # Crestron — exists
    ("agents.bas.bacnet",        "OT"),
    ("agents.bas.niagara_fox",   "OT"),
    ("agents.ics.opcua",         "OT"),
    ("agents.ics.modbus",        "OT"),
    ("agents.iot.mqtt",          "IoT"),
    ("agents.iot.onvif",         "IoT"),
    ("agents.it.kubernetes",     "IT"),
    ("agents.it.activedirectory","IT"),
    # …each module: detect() + finding_for() + safety_class + capability hint
]
```

Each module additionally declares a **`SAFETY_CLASS`** (`safe`/`intrusive`/`disruptive`) and a **capability hint** (the SAST/fuzzer/probe command the operator can run — exactly like avot's `_CAPABILITY_HINT`). This mirrors Metasploit's module-metadata model (structured options + rank + side-effect class) and ISF/Caring Caribou's reusable protocol-client objects.

### 4.2 The fingerprint registry (port/banner/probe → technology → capability)

Today, detection is hardcoded inside each module's `detect()`. For scale, **externalize the lookup into a versioned data file** — the single most important pattern to copy (Nmap `nmap-service-probes` + Rapid7 `Recog` + GRASSMARLIN NIC fingerprints):

```
PORT/PROBE → RESPONSE-PATTERN → TECHNOLOGY → CPE → SAFETY_CLASS → CAPABILITY-MODULE
502/tcp     MBAP+FC43 reply     Modbus       …   safe(read)      agents.ics.modbus
102/tcp     COTP, S7 PDU 0x32   S7comm       …   safe(read)      agents.ics.s7
102/tcp     COTP, MMS/ACSE      IEC61850-MMS …   safe(read)      agents.ics.iec61850
4840/tcp    opc.tcp ACK         OPC-UA       …   safe(read)      agents.ics.opcua
47808/udp   I-Am                BACnet       …   safe(read)      agents.bas.bacnet
1911/tcp    "fox a 0" hello     Niagara Fox  …   safe(read)      agents.bas.niagara_fox
```

The recon layer consults this registry **before any active probe** (identify-before-attack), routes every match into CVE/CPE correlation feeding the `knowledge_base`, and — for OT — lets the **passive PCAP/SPAN path run the same lookups with zero packets sent**. Ship OT/IoT match rules (and imported Redpoint/w3h-icsmaster NSE + ITI PORTS.md) as data packs decoupled from engine releases (the Defensics/Recog cadence pattern). An **OSINT enrichment connector** (Shodan/Censys) can pre-tag a CIDR's banners+CVEs *before* active scanning, feeding `cidr_orchestrator` triage so the operator prioritizes hosts and avoids re-probing already-characterized fragile OT.

### 4.3 Tool-catalog entries

`agents/operator_agent/tool_catalog.py` already references avot inside the `run_tool` doc (the SAST + dry-run CIP/CTP fuzzer). Extend the same way:

- Keep `run_tool` as the universal primitive, but **add the imported NSE/protocol scanners to its toolset** (the ICS NSE corpus, `mqtt-subscribe`, `coap-resources`, `bacnet-info`, `hartip-info`, `enip-info`, `s7-info`, Cameradar, PRET, kube-hunter, grpcurl, NetExec, Impacket, RouterSploit).
- **Add macro tools per domain** mirroring `recon`/`web_enum`: e.g. `ot_recon` (passive-first ICS enumeration, safe-class only), `iot_discover` (UDP/multicast: SSDP/mDNS/CoAP/WS-Discovery), `cloud_pivot` (SSRF→IMDS→IAM), `ad_enum` (null-session→Kerberoast→BloodHound).
- Each macro declares its safety class so the operator brain auto-dispatches only `safe` macros against OT targets.

### 4.4 Safe-by-default OT handling

Reuse what already exists. The `crestron_fuzzer` already implements the full safety scaffolding the broader program needs: **dry-run default, `--authorized` opt-in, `--scope-allow`/`--scope-deny` CIDR enforcement, multi-probe liveness with response signatures, OT safe-mode rate-limit + consecutive-failure circuit breaker, deterministic replay, and a JSONL audit log** (`agents/avot/README.md`, `crestron-avot-capability.md §9`). Generalize this into an engine-level **safety gate** that mirrors the engagement-integrity connectivity/token gates (sub-project #1):

- **Default action against an OT-classified target = `safe`/read-only.** `intrusive` and `disruptive` actions require explicit engagement authorization (the existing `--authorized` + allowlisted-scope model) and a human gate.
- **Passive-first preference** when a target is classified OT/fragile (GRASSMARLIN doctrine).
- **Life-safety classifier** flags elevators/fire/egress/locks as no-actuation.
- **Circuit breaker** halts on repeated crash signals and prompts device isolation/power-cycle — the same pattern as the connectivity blocker gate.

### 4.5 How findings flow to the report

Unchanged and already correct. `finding_for()` returns a `store_finding`-shaped record; the engine calls `store_finding(severity=FindingSeverity.…, title, description, host, tool_used, evidence, remediation, mitre)` (`db/schemas.py` `Finding`). This flows through the **engagement-integrity quality gate** (sub-project #1: origin-stamped, dedup'd, Issue-Validator-gated) into `report/generator.py`. OT findings additionally carry a **CISA-advisory / OT:ICEFALL / vendor-PSIRT mapping** field (rather than only CVE/CVSS) and a **safety-impact** note, so the report ranks availability/safety appropriately for industrial engagements.

### 4.6 Transport adapters (the non-IP tiers)

For Layer-2 (GOOSE/SV/PROFINET-DCP), CAN/serial (UDS/J1939), and RF (Zigbee/Z-Wave/BLE/LoRaWAN/Wi-Fi), add a **transport-abstraction layer** so non-IP buses expose the same `discover`/`enumerate`/`exploit` verbs through the module interface as IP modules (the Caring Caribou "modular API abstracts the bus" pattern + KillerBee/SDR hardware adapters normalized into `db/schemas.py` findings). This keeps the operator brain transport-agnostic and is the prerequisite for the P2 hardware tiers.

---

## 5. Reading the matrix against the existing engine

The matrix's "ARGUS gap" column maps directly onto the subsystems above: every "no X speaker / no X probe" gap is a **new capability module** (§4.1) + a **fingerprint-registry row** (§4.2); every "outside IP model / no RF" gap is a **transport adapter** (§4.6); every "stops at SSRF / banner-only / misses chains" gap is a **stateful operator workflow** (§3.5) wired as a macro tool (§4.3); and every "fragile / safety-of-life / actuates" risk is a **safety-class gate** (§4.4).

---

## 6. Prioritized roadmap (P0 / P1 / P2)

Scored on **prevalence × risk × tooling-maturity × IT-adjacency** (how much it reuses ARGUS's existing IP/socket/web engine).

### P0 — IP-reachable, high-prevalence, mature tools, near-zero new transport (do first)

| # | Family | Why first |
|---|---|---|
| 1 | **OPC-UA** | Modern, IP-native, most IT-like OT protocol; GetEndpoints + anonymous/None + cert test is pure socket work; OpalOPC/Team82 mature |
| 2 | **BACnet/IP** | Flagship building OT; one Who-Is yields full inventory; nmap/Redpoint/BAC0 mature; huge building-automation vertical |
| 3 | **Modbus / S7 / EtherNet/IP / IEC-104 / DNP3 / FINS** | The ICS core; read-only enumerators are trivial; ingest the Redpoint + w3h/icsmaster NSE corpus + plcscan wholesale |
| 4 | **Niagara Fox** | Trivial 1911/4911 banner parse, very high ROI; 50k+ buildings; Nozomi 2025 CVE chain |
| 5 | **AD / Kerberos / LDAP / SMB** | Dominant on-prem privesc surface; Impacket/NetExec/BloodHound/Responder mature; the IT-frontier chain ARGUS most under-covers |
| 6 | **VPN / edge appliances** | #1 mass-exploited initial access 2024-25; fingerprint + edge-CVE feed; mostly reuses web/TLS scanning |
| 7 | **ONVIF/RTSP cameras, IPP/PJL printers, MQTT, CoAP, UPnP/SSDP, mDNS** | All IP-reachable; mature tools (Cameradar/PRET/mqtt-subscribe/coap-resources); add probe + IoT cred corpus |
| 8 | **Cloud IMDS/S3, K8s/Docker, GraphQL/gRPC, DBs, message queues** | IT-frontier; stateful workflows + API clients over existing HTTP/socket layer |

### P1 — IP-reachable but new protocol stack or split RF/IP, high value

| # | Family | Why P1 |
|---|---|---|
| 9 | **CODESYS fingerprint** | One hit → whole OEM PLC fleet; high leverage but needs the V2/V3 port disambiguation |
| 10 | **KNXnet/IP, LonWorks, vendor PLC long-tail, HART-IP** | New UDP/multicast or protocol stacks; ICS NSE corpus covers much of it |
| 11 | **DICOM / HL7-MLLP / FHIR / medical-device classification** | High-impact health vertical; FHIR extends the web-vuln subagent; medical devices need strict passive/read-only + FDA feed |
| 12 | **DLMS/COSEM, DoIP (CAN over IP), maritime NMEA-over-IP, rail/industrial-wireless gateway IP side** | The IP-reachable foothold of otherwise-RF/serial verticals; gateway is the practical entry point |
| 13 | **AMX/Extron/Lutron/Savant AV, NAS, smart-home hubs, TR-069 CPE** | Building/AV + IoT appliances; mostly IP + default-cred + firmware extraction |
| 14 | **Matter mDNS discovery** | The IP-reachable half of Thread/Matter (commissionable-node discovery) |

### P2 — requires net-new hardware/transport (defer until the bridge exists)

| # | Family | Why deferred |
|---|---|---|
| 15 | **Layer-2 OT** (GOOSE/SV/PROFINET-DCP) | Raw-socket/SPAN on-segment; passive-only; ultra-destructive injection gate |
| 16 | **RF IoT** (Zigbee, Z-Wave, BLE, LoRaWAN, Thread mesh) | SDR/radio hardware-bridge (KillerBee/HackRF/Ubertooth) — the largest single gap |
| 17 | **CAN/serial** (UDS, J1939, NMEA-2000) | SocketCAN/HWBridge transport adapter; passive-first |
| 18 | **Physical access** (Wiegand, OSDP, prox/MIFARE) | RS-485/RFID hardware (Proxmark/Flipper/ESPKey); scan the IP panel meanwhile |
| 19 | **Wi-Fi, AIS/EuroRadio/balise SDR, implant MICS-band RF** | Monitor-mode RF / VHF SDR — out-of-band from IP scanning |

**Build order summary:** ship the **capability-module registry + fingerprint registry + safety-class gate** (the §4 plumbing) first, populate it with the **P0 IP-reachable families** (reusing the avot template), add the **passive-first OT SPAN path**, then the **P1 new-stack families**, and only invest in the **transport-abstraction + hardware bridge** for P2 once the IP-tier coverage is proven. This sequencing fits the existing program order (Integrity → Report → Crestron → AI-engine): the Crestron/avot work *is* the pilot of this exact pattern, so #5 generalizes a validated design rather than inventing one.

---

## 7. Verification notes (corrections applied)

The following research claims were corrected by adversarial fact-check and are reflected in the matrix (⚠ markers):

- **Modbus:** no Modbus/UDP standard exists; fingerprint **502/tcp** only (502/udp is an IANA reservation, not a live listener). MSF `modbusdetect` is a **presence/liveness check**, not a version/capability fingerprinter (use `modbusclient` READ_ID / nmap `modbus-discover`).
- **S7comm vs MMS:** both use 102/tcp, but only one binds per host; disambiguate by the **post-COTP payload byte** (S7 PDU `0x32` vs MMS/ACSE), not the port.
- **DNP3:** **no Metasploit DNP3 scanner module exists** (nmap `dnp3-info`/Redpoint is the enumerator); the "Aegis" fuzzer is private; `dnp3-info` and "Redpoint DNP3 script" are the same script.
- **EtherNet/IP:** CIP is **not** an OT:ICEFALL headline vendor — it shares the insecure-by-design *class*; 44818/udp is the browse/discovery channel.
- **OPC-UA:** SOAP transport deprecated (v1.03); 443 is generic HTTPS, not UA-assigned; the MSF modules are **3rd-party `COMSYS/msf-opcua`** (not built-in) and **no Nmap OPC-UA NSE script exists**.
- **PROFINET:** CBA/DCOM was **removed from IEC 61784-1 (2014)** — legacy only; PN-IRT is a communication class, not a separate protocol; "+ Profibus heritage" is serial fieldbus and needs its own entry.
- **Niagara Fox:** 3011/5011 are **not** default Fox ports (1911/4911 are); **no maintained MSF Fox module** — exploitation is PoC code; the "~67,000" exposure figure is unsourced (defensible: ~20k US Shodan / 50k+ buildings).
- **CODESYS:** **2455 is V2, not V3**; V3 runtime/gateway = **11740/tcp** (+1217, udp 1740-1743); **ICSSPLOIT has no CODESYS module**.
- **HART-IP:** add **nmap `hartip-info`** (the best off-the-shelf tool, omitted from the research); 5094 is the session-*initiation* port (traffic may move to a server-selected port).
- All other entries (ports, protocol names, fingerprint methods, named tools) were confirmed accurate — including DICOM, HL7-MLLP, BACnet, IEC-104, IEC-61850 Ethertypes (GOOSE 0x88B8 / SV 0x88BA), and S7's SZL/COTP fingerprint.

---

## 8. References

**OT / ICS / SCADA**
- Modbus: https://nmap.org/nsedoc/scripts/modbus-discover.html · https://www.rapid7.com/db/modules/auxiliary/scanner/scada/modbusdetect/ · https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/scada/modbusclient.rb · https://scadaprotocols.com/modbus-tcp-ip-port-502-iana/ · https://www.verylazytech.com/network-pentesting/modbus-port-502 · https://swisskyrepo.github.io/HardwareAllTheThings/protocols/modbus/
- S7comm: https://github.com/moki-ics/s7-metasploit-modules · https://github.com/digitalbond/Redpoint/blob/master/s7-enumerate.nse · https://nmap.org/nsedoc/scripts/s7-info.html · https://wiki.wireshark.org/S7comm · https://blog.nettedautomation.com/2017/10/conflicting-use-of-tcp-port-102-for-iec.html · https://claroty.com/team82/research/the-race-to-native-code-execution-in-plcs
- DNP3: https://www.cisa.gov/news-events/ics-advisories/icsa-13-291-01b · https://github.com/digitalbond/Redpoint/blob/master/dnp3-info.nse · https://dl.ifip.org/db/conf/ifip11-10/cip2009/EastBPS09.pdf · https://hackers-arise.com/scada-hacking-scada-protocols-dnp3/ · https://arxiv.org/pdf/2109.03945
- EtherNet/IP + CIP: https://www.rapid7.com/db/modules/auxiliary/admin/scada/multi_cip_command/ · https://github.com/nmap/nmap/blob/master/scripts/enip-info.nse · https://github.com/digitalbond/Redpoint/blob/master/enip-enumerate.nse · https://www.cisa.gov/news-events/ics-advisories/icsa-17-138-03 · https://www.odva.org/technology-standards/distinct-cip-services/cip-security/ · https://www.forescout.com/blog/ot-icefall-56-vulnerabilities-caused-by-insecure-by-design-practices-in-ot/
- OPC-UA: https://hacktricks.wiki/en/network-services-pentesting/4840-pentesting-opc-ua.html · https://github.com/claroty/opcua-exploit-framework · https://github.com/COMSYS/msf-opcua · https://opalopc.com/docs/tutorials/discover-opcua-servers-on-network/ · https://reference.opcfoundation.org/Core/Part6/v105/docs/7.4 · https://www.cisa.gov/news-events/ics-advisories/icsa-17-243-01-0 · https://f0rw4rd.github.io/posts/nmap-for-ot-scanning/
- IEC 61850: https://www.wireshark.org/docs/wsar_html/etypes_8h_source.html · https://scadaprotocols.com/iec-61850-mms-port-number-tcp-102/ · https://scadaprotocols.com/iec-61850-goose-vs-sampled-values/ · https://cdn.selinc.com/assets/Literature/Publications/Technical%20Papers/6921_IEC61850Network_MS_20190712_Web.pdf · https://github.com/mz-automation/libiec61850 · https://github.com/cutaway-security/goosestalker
- PROFINET: https://www.hms-networks.com/support/tech-support/kb-articles/6794937733394 · https://en.wikipedia.org/wiki/Discovery_and_Configuration_Protocol · https://scadaprotocols.com/profinet-conformance-classes-explained/ · https://github.com/secdev/scapy/blob/master/scapy/contrib/pnio.py · https://github.com/atimorin/scada-tools/blob/master/profinet_scanner.scapy.py
- BACnet: https://nmap.org/nsedoc/scripts/bacnet-info.html · https://github.com/digitalbond/Redpoint/blob/master/BACnet-discover-enumerate.nse · https://bac0.readthedocs.io/ · https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/scada/bacnet_l3.rb · https://www.fortinet.com/blog/business-and-technology/shodan-your-ics-network-the-bacnet-story · https://www.net.in.tum.de/fileadmin/bibtex/publications/papers/bacnet-amplification.pdf
- Niagara Fox: https://nmap.org/nsedoc/scripts/fox-info.html · https://github.com/digitalbond/Redpoint/blob/master/fox-info.nse · https://www.nozominetworks.com/blog/critical-vulnerabilities-found-in-tridium-niagara-framework · https://www.tridium.com/content/dam/tridium/en/documents/document-lists/niagara/tri-Niagara4-Hardening-Guide-en-2025.pdf · https://cyberscoop.com/fox-protocol-fbi-warning-port-1911-ics-security/ · https://www.cisa.gov/news-events/ics-advisories/icsa-12-228-01a
- IEC-104: https://nmap.org/nsedoc/scripts/iec-identify.html · https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/client/iec104/iec104.rb · https://github.com/mz-automation/lib60870 · https://github.com/riclolsen/qtester104 · https://scadaprotocols.com/iec-60870-5-104-type-ids-explained/ · https://dl.acm.org/doi/fullHtml/10.1145/3538969.3544475
- CODESYS: https://www.microsoft.com/en-us/security/blog/2023/08/10/multiple-high-severity-vulnerabilities-in-codesys-v3-sdk-could-lead-to-rce-or-dos/ · https://www.nozominetworks.com/blog/backdooring-codesys-applications-via-vulnerability-chaining · https://github.com/digitalbond/Redpoint/blob/master/codesys-v2-discover.nse · https://forge.codesys.com/ · https://industrialcyber.co/vulnerabilities/vedere-labs-updates-oticefall-findings
- OMRON FINS: https://cisa.gov/uscert/ics/advisories/icsa-19-346-02 · https://github.com/digitalbond/Redpoint · https://www.tenable.com/plugins/nnm/756882 · https://www.fa.omron.co.jp/product/security/assets/pdf/en/OMSR-2023-003_en.pdf
- HART-IP: https://nmap.org/nsedoc/scripts/hartip-info.html · https://www.cisa.gov/news-events/ics-advisories/icsa-20-287-04 · https://wiki.wireshark.org/HART-IP · https://www.cisa.gov/news-events/ics-advisories/icsa-15-029-01 · https://www.cisa.gov/news-events/ics-advisories/icsa-15-267-01 · https://www.fieldcommgroup.org/sites/default/files/imce_files/technology/documents/FCG%20AG10364%20%7B1.0%7D_HART-IP_Technical_Description.pdf
- Vendor PLC long-tail: https://github.com/digitalbond/Redpoint · https://github.com/w3h/icsmaster/tree/master/nse · https://github.com/ITI/ICS-Security-Tools/blob/master/protocols/PORTS.md · https://github.com/tijldeneut/icssploit

**Building automation / AV**
- Crestron: https://github.com/Phenomite/AMP-Research/blob/master/Port%2041794%20-%20Crestron%20CIP/README.md · https://www.cisa.gov/news-events/ics-advisories/icsa-18-221-01 · https://github.com/axcheron/crestron_getsudopwd · https://github.com/xfox64x/CVE-2019-3929 · https://help.crestron.com/cds/symbols/Definitions/Port_Number.htm
- AMX: https://www.cisa.gov/news-events/ics-advisories/icsa-16-049-02a · https://whatportis.com/ports/1319_amx-icsp
- Extron / Lutron / Savant: https://www.extron.com/product/ipcppro250xi · https://vulners.com/openvas/OPENVAS:1361412562310113206 · https://assets.lutron.com/a/documents/hwqs%20rs-232%20ethernet%20integration.pdf · https://wiki.2n.com/hip/inte/latest/en/4-home-and-building-automation/savant
- KNX: https://nmap.org/nsedoc/scripts/knx-gateway-info.html · https://github.com/takeshixx/knxmap · https://github.com/knxd/knxd · https://github.com/Orange-Cyberdefense/awesome-industrial-protocols/blob/main/protocols/knxnetip.md
- LonWorks: https://wiki.wireshark.org/Protocols/CEA-709.1 · https://ctlsys.com/support/ip-852/ · https://en.wikipedia.org/wiki/LonTalk
- DALI: https://www.dali-alliance.org/dali/ip.html · https://www.lunatone.com/en/product/dali-2-iot-gateway/ · https://www.hms-networks.com/p/inmbsdal0640500-dali-2-to-modbus-tcp-server-gateway
- OSDP / Wiegand: https://bishopfox.com/blog/breaking-into-secure-facilities-with-osdp · https://github.com/BishopFox/mellon · https://blackhat.com/docs/us-15/materials/us-15-Evenchick-Breaking-Access-Controls-With-BLEKey-wp.pdf
- Z-Wave / Zigbee (building): https://www.pentestpartners.com/security-blog/z-shave-exploiting-z-wave-downgrade-attacks/ · https://github.com/riverloopsec/killerbee · https://github.com/Shadow7726/Z-Wave-PT
- Elevators: https://nmap.org/nsedoc/scripts/bacnet-info.html · https://www.tridium.com/content/dam/tridium/en/documents/document-lists/niagara/tri-Niagara4-Hardening-Guide-en-2025.pdf

**Consumer / enterprise IoT**
- MQTT: https://nmap.org/nsedoc/scripts/mqtt-subscribe.html · https://hacktricks.wiki/en/network-services-pentesting/1883-pentesting-mqtt-mosquitto.html · https://github.com/kh4sh3i/MQTT-Pentesting
- CoAP: https://nmap.org/nsedoc/scripts/coap-resources.html · https://www.netscout.com/blog/asert/coap-attacks-wild · https://datatracker.ietf.org/doc/html/draft-mattsson-core-coap-attacks-01
- AMQP/Kafka: https://hacktricks.wiki/en/network-services-pentesting/5671-5672-pentesting-amqp.html · https://github.com/kh4sh3i/RabbitMQ-Pentesting · https://blog.securelayer7.net/cve-2025-27817-apache-kafka-connect-arbitrary-file-read/
- UPnP/SSDP: https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices · https://www.rapid7.com/blog/post/2020/12/22/upnp-with-a-holiday-cheer/
- mDNS: https://hacktricks.wiki/en/network-services-pentesting/5353-udp-multicast-dns-mdns.html · https://hackmag.com/security/multicast-dns-pentest
- ONVIF/RTSP: https://aardwolfsecurity.com/ip-camera-penetration-testing/ · https://hacktricks.wiki/en/network-services-pentesting/3702-udp-pentesting-ws-discovery.html · https://www.nozominetworks.com/blog/vulnerability-in-dahua-s-onvif-implementation-threatens-ip-camera-security · https://ipvm.com/reports/nmap-ip-cameras
- Printers: https://github.com/RUB-NDS/PRET · https://book.hacktricks.xyz/network-services-pentesting/9100-pjl · https://www.tenable.com/blog/rooting-a-printer-from-security-bulletin-to-remote-code-execution
- NAS: https://www.helpnetsecurity.com/2022/09/12/cve-2022-27593/ · https://valicyber.com/resources/a-brief-history-of-nas-ransomware/ · https://www.qnap.com/en/security-advisory/qsa-22-19
- Smart-home hubs: https://approov.io/blog/the-security-risks-of-mobile-apps-and-apis-in-the-smart-home · https://cybersecuritynews.com/tp-link-iot-smart-hub-vulnerability/
- CPE/TR-069: https://www.pentestpad.com/port-exploit/port-7547-cwmp-tr-069-cpe-wan-management-protocol · https://comsecuris.com/blog/posts/were_900k_deutsche_telekom_routers_compromised_by_mirai/
- BLE/Zigbee/Z-Wave/Thread/LoRaWAN: https://hacktricks.wiki/en/todo/radio-hacking/pentesting-ble-bluetooth-low-energy.html · https://github.com/riverloopsec/killerbee · https://i.blackhat.com/EU-24/Presentations/EU-24-Genge-BreakingMatterVulnerabiltiesInTheMatterProtocol-wp.pdf · https://github.com/IOActive/laf · https://www.tarlogic.com/blog/lorawan-vulnerabilities-versions/

**Vertical OT-IoT**
- DICOM: https://nmap.org/nsedoc/scripts/dicom-ping.html · https://www.ioactive.com/penetration-testing-of-the-dicom-protocol-real-world-attacks/ · https://www.rapid7.com/blog/post/2023/10/11/the-risks-of-exposing-dicom-data-to-the-internet/
- HL7/FHIR: https://www.txone.com/blog/hl7-protocol-vulnerabilities-mitigation/ · https://www.letsaskclaire.com/healthcare/ehr-integration-security
- Medical devices: https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-030-01 · https://www.fda.gov/medical-devices/safety-communications/cybersecurity-vulnerabilities-certain-patient-monitors-contec-and-epsimed-fda-safety-communication · https://www.armis.com/blog/patient-monitor-vulnerabilities-threaten-healthcare-security-cisa-warns/
- CAN/UDS/J1939: https://github.com/CaringCaribou/caringcaribou · https://www.kali.org/docs/nethunter/nethunter-carsenal/ · https://www.csselectronics.com/pages/uds-protocol-tutorial-unified-diagnostic-services · https://copperhilltech.com/blog/security-vulnerabilities-in-can-canopen-and-j1939-networks-risks-and-mitigation-strategies/
- DLMS/COSEM: https://cytal.co.uk/protocols/cosem/ · https://phoeni2x.eu/2025/07/01/the-hidden-cyber-threats-in-smart-meters-inside-dlms-cosem-attacks/
- Maritime: https://www.pentestpartners.com/security-blog/maritime-ot-networks-a-primer/ · https://www.pentestpartners.com/security-blog/hacking-tracking-stealing-and-sinking-ships/ · https://www.nmea.org/cybersecurity.html
- Rail: https://www.txone.com/blog/communication-based-train-control-architecture-and-its-attack-aspects/ · https://gca.isa.org/blog/understanding-railway-cybersecurity
- Physical access: https://www.getkisi.com/blog/hid-keycard-readers-hacked-using-wiegand-protocol-vulnerability · https://whitepapers.axis.com/en-us/osdp-protocol-in-access-control
- Industrial wireless: https://blog.isa.org/analysis-wireless-industrial-automation-standards-isa-100-11a-wirelesshart · https://www.yokogawa.com/library/resources/media-publications/security-for-wireless-instrumentation/ · https://www.sciencedirect.com/science/article/pii/S0167404823002936

**IT frontier**
- IMDS: https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/ · https://securitylabs.datadoghq.com/articles/misconfiguration-spotlight-imds/ · https://guardz.com/blog/exploiting-azure-managed-identity-tokens-from-imds/ · https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- Object storage: https://www.intigriti.com/researchers/blog/hacking-tools/hacking-misconfigured-aws-s3-buckets-a-complete-guide · https://github.com/initstring/cloud_enum
- Kubernetes: https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/pentesting-kubernetes-services/index.html · https://deepstrike.io/blog/kubernetes-penetration-testing-methodology-and-guide · https://github.com/SunWeb3Sec/Kubernetes-security
- Docker: https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker · https://book.hacktricks.xyz/network-services-pentesting/5000-pentesting-docker-registry
- AD/SMB/Kerberos/LDAP: https://nmap.org/nsedoc/scripts/smb-security-mode.html · https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast · https://www.hackingarticles.in/kerberoasting-attack-in-active-directory/ · https://nmap.org/nsedoc/scripts/ldap-search.html · https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap
- GraphQL/gRPC/REST: https://portswigger.net/web-security/graphql · https://github.com/Escape-Technologies/awesome-graphql-security · https://hackviser.com/tactics/pentesting/services/grpc · https://grpc.io/docs/guides/reflection/ · https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- Message queues / DBs: https://book.hacktricks.xyz/network-services-pentesting/5671-5672-pentesting-amqp · https://www.0xczr.com/tools/database_pentesting_cheatsheet/ · https://hackviser.com/tactics/pentesting/services/MongoDB · https://trevorsaudi.com/posts/2021-03-23_rce-on-unauthenticated-redis-server/
- VPN/edge: https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day · https://unit42.paloaltonetworks.com/threat-brief-ivanti-cve-2025-0282-cve-2025-0283/ · https://www.helpnetsecurity.com/2025/04/03/ivanti-vpn-customers-targeted-via-unrecognized-rce-vulnerability-cve-2025-22457/
- Wi-Fi: https://deepstrike.io/blog/wireless-penetration-testing · https://www.hackingarticles.in/wireless-penetration-testing-pmkid-attack/ · https://www.aircrack-ng.org/doku.php?id=cracking_wpa

**Tooling / architecture patterns**
- Nmap NSE + service-probes: https://nmap.org/nsedoc/scripts/ · https://nmap.org/book/nmap-service-probes.html · https://nmap.org/book/vscan-fileformat.html
- Redpoint / ICS NSE: https://github.com/digitalbond/Redpoint · https://github.com/jiansiting/NMAP-NSE-SCADA
- Metasploit SCADA: https://docs.metasploit.com/docs/modules.html · https://www.rapid7.com/db/modules/auxiliary/scanner/scada/modbusclient/
- ISF / ICSSPLOIT / RouterSploit: https://github.com/tijldeneut/icssploit · https://github.com/hslatman/awesome-industrial-control-system-security
- Firmware (binwalk/FACT/FAT): https://www.hackingtutorials.org/iot-hacking/iot-penetration-testing-from-hardware-to-firmware/ · https://ivanorsolic.github.io/post/hardwarehacking2/
- Fuzzing (boofuzz/Defensics): https://dreamlab.net/en/blog/post/fuzzing-ics-protocols/
- Shodan/Censys: https://www.stationx.net/how-to-use-shodan/ · https://johal.in/censys-shodan-python-iot-reconnaissance-2025/
- Recog / fingerprint DB: https://nmap.org/book/man-version-detection.html
- KillerBee / Z3sec / SDR: https://www.sans.org/tools/killerbee · https://github.com/IoTsec/Z3sec · https://www.rtl-sdr.com/reverse-engineering-signals-universal-radio-hacker-software/ · https://github.com/cn0xroot/RFSec-ToolKit
- Caring Caribou: https://github.com/CaringCaribou/caringcaribou · https://github.com/iDoka/awesome-canbus
- GRASSMARLIN (passive): https://github.com/nsacyber/GRASSMARLIN · https://www.dragos.com/blog/passive-monitoring-active-collection-for-a-complete-ot-asset-inventory

**Internal ARGUS references**
- `agents/avot/recon.py` — capability-module template (`detect()` / `finding_for()`)
- `agents/avot/README.md`, `docs/superpowers/specs/crestron-avot-capability.md`, `crestron-avot-fuzzing.md` — safety scaffolding + roadmap
- `agents/master_agent.py:4147` — `_avot_capability_scan()` engine wiring (generalize to `_capability_scan()`)
- `agents/operator_agent/tool_catalog.py` — toolbelt + macro tools
- `db/schemas.py` — `Finding` / `FindingSeverity` (finding flow)
- `docs/superpowers/specs/2026-06-19-engagement-integrity-design.md` — authorization/gate model + findings quality-gate to reuse
