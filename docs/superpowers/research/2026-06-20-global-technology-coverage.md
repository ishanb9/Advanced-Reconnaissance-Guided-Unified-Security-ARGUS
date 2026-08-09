# Global Technology Coverage — Skill Catalog

> Deep-research output (2026-06-20). Generated from the authored skill catalog (`knowledge/skills/`), so it reflects exactly what ships. Coverage is **data**: each row is a skill file ARGUS matches against recon + ingests into RAG; add one to extend coverage.

## Coverage summary

| Category | Skills | Domains | Transports |
|---|---|---|---|
| Security devices | 14 | IT | ip |
| Network devices | 12 | IT | ip |
| Operating systems | 14 | IT | ip |
| Web applications | 15 | IT | ip |
| SCADA / HMI systems | 14 | OT | ip |
| Home automation | 13 | IOT | ip |
| Yacht & ship (marine) | 15 | OT | can,ip,rf |
| Aircraft (aviation) | 14 | OT | arinc,ip,rf |
| Core OT/IoT/IT protocols (P0-P2) | 54 | IOT,IT,OT | can,ip,l2,rf,serial |
| **TOTAL** | **165** | OT/IoT/IT | ip/rf/can/l2/serial/arinc |

Safety: OT/SCADA/marine/aviation skills are `safe`-by-default (read-only lead); `life_safety` points never auto-actuate; the human sets the scan-intrusiveness ceiling. Non-`ip` transports are recognised + guided but need a hardware bridge to execute.

## Security devices (14)

| id | Technology | Domain | Transport | Safety | Severity | Life-safety |
|---|---|---|---|---|---|---|
| `aruba_clearpass_nac` | Aruba ClearPass Policy Manager (NAC) | IT | ip | safe | high |  |
| `checkpoint_gaia` | Check Point GAIA / Security Gateway | IT | ip | safe | high |  |
| `cisco_asa_ftd` | Cisco ASA / Firepower Threat Defense (FTD) | IT | ip | safe | critical |  |
| `cisco_ise_nac` | Cisco Identity Services Engine (ISE) NAC | IT | ip | safe | high |  |
| `f5_asm_waf` | F5 BIG-IP ASM / Advanced WAF | IT | ip | safe | critical |  |
| `fortigate` | Fortinet FortiGate / FortiOS | IT | ip | safe | critical |  |
| `hsm_kms` | Hardware Security Module (HSM) / KMS | IT | ip | safe | critical |  |
| `imperva_waf` | Imperva WAF / SecureSphere | IT | ip | safe | high |  |
| `panos_ngfw` | Palo Alto PAN-OS Next-Gen Firewall | IT | ip | safe | critical |  |
| `pfsense_opnsense` | pfSense / OPNsense Open-Source Firewall | IT | ip | safe | high |  |
| `proofpoint_seg` | Proofpoint Secure Email Gateway | IT | ip | safe | high |  |
| `snort_suricata_ids` | Snort / Suricata IDS-IPS Sensor | IT | ip | safe | medium |  |
| `splunk_siem` | Splunk Enterprise SIEM | IT | ip | safe | high |  |
| `zscaler_proxy` | Zscaler Internet Access / Cloud Proxy | IT | ip | safe | high |  |

## Network devices (12)

| id | Technology | Domain | Transport | Safety | Severity | Life-safety |
|---|---|---|---|---|---|---|
| `arista_eos` | Arista EOS | IT | ip | intrusive | high |  |
| `cisco_ios` | Cisco IOS / IOS-XE | IT | ip | intrusive | critical |  |
| `cisco_nxos` | Cisco NX-OS (Nexus) | IT | ip | intrusive | critical |  |
| `citrix_adc` | Citrix ADC / NetScaler | IT | ip | intrusive | critical |  |
| `f5_bigip` | F5 BIG-IP | IT | ip | intrusive | critical |  |
| `hpe_aruba` | HPE Aruba AOS / ArubaOS | IT | ip | intrusive | critical |  |
| `juniper_junos` | Juniper Junos OS | IT | ip | intrusive | critical |  |
| `mikrotik_routeros` | MikroTik RouterOS | IT | ip | intrusive | critical |  |
| `sdwan_edge` | SD-WAN Edge Appliances (Cisco Viptela/VMware VeloCloud/Fortinet) | IT | ip | intrusive | critical |  |
| `snmp_managed_switch` | SNMP Managed Switches | IT | ip | intrusive | high |  |
| `ubiquiti_unifi` | Ubiquiti UniFi / EdgeOS | IT | ip | intrusive | high |  |
| `wireless_lan_controller` | Wireless LAN Controllers (Cisco WLC / AireOS) | IT | ip | intrusive | high |  |

## Operating systems (14)

| id | Technology | Domain | Transport | Safety | Severity | Life-safety |
|---|---|---|---|---|---|---|
| `os-android-adb` | Android ADB (Android Debug Bridge) | IT | ip | intrusive | critical |  |
| `os-esxi-vsphere` | VMware ESXi / vSphere Hypervisor | IT | ip | intrusive | critical |  |
| `os-freebsd` | FreeBSD / OpenBSD | IT | ip | safe | medium |  |
| `os-ibm-aix` | IBM AIX | IT | ip | safe | high |  |
| `os-ios-mdm` | iOS / iPadOS Attack Surface (MDM, Lockdown, Jailbreak) | IT | ip | safe | high |  |
| `os-linux-privesc` | Linux Privilege Escalation (sudo/SUID/kernel) | IT | ip | intrusive | critical |  |
| `os-linux-ssh` | Linux SSH (Secure Shell) | IT | ip | intrusive | high |  |
| `os-macos-ard` | macOS Apple Remote Desktop / Screen Sharing | IT | ip | intrusive | high |  |
| `os-solaris` | Oracle Solaris | IT | ip | safe | high |  |
| `os-windows-adcs` | Windows Active Directory Certificate Services (AD CS) | IT | ip | intrusive | critical |  |
| `os-windows-iis` | Windows IIS (Internet Information Services) | IT | ip | safe | high |  |
| `os-windows-rdp` | Windows RDP (Remote Desktop Protocol) | IT | ip | intrusive | critical |  |
| `os-windows-server-roles` | Windows Server Roles (SCCM / WSUS / Print Spooler / NPS) | IT | ip | intrusive | high |  |
| `os-windows-winrm` | Windows WinRM / PowerShell Remoting | IT | ip | intrusive | high |  |

## Web applications (15)

| id | Technology | Domain | Transport | Safety | Severity | Life-safety |
|---|---|---|---|---|---|---|
| `apache_tomcat` | Apache Tomcat | IT | ip | intrusive | critical |  |
| `citrix_storefront` | Citrix StoreFront / NetScaler Gateway | IT | ip | intrusive | critical |  |
| `confluence` | Atlassian Confluence | IT | ip | intrusive | critical |  |
| `drupal` | Drupal | IT | ip | intrusive | critical |  |
| `gitlab` | GitLab | IT | ip | intrusive | critical |  |
| `grafana` | Grafana | IT | ip | intrusive | high |  |
| `jboss_wildfly` | JBoss / WildFly Application Server | IT | ip | intrusive | critical |  |
| `jenkins` | Jenkins CI/CD | IT | ip | intrusive | critical |  |
| `jira` | Atlassian Jira | IT | ip | intrusive | high |  |
| `kibana` | Kibana / Elastic Stack | IT | ip | intrusive | high |  |
| `phpmyadmin` | phpMyAdmin | IT | ip | intrusive | critical |  |
| `sharepoint` | Microsoft SharePoint | IT | ip | intrusive | critical |  |
| `spring_boot_actuator` | Spring Boot Actuator | IT | ip | intrusive | critical |  |
| `weblogic` | Oracle WebLogic Server | IT | ip | intrusive | critical |  |
| `wordpress` | WordPress | IT | ip | intrusive | critical |  |

## SCADA / HMI systems (14)

| id | Technology | Domain | Transport | Safety | Severity | Life-safety |
|---|---|---|---|---|---|---|
| `aveva-system-platform` | AVEVA System Platform (ArchestrA) | OT | ip | safe | high | yes |
| `factorytalk-view` | Rockwell Automation FactoryTalk View | OT | ip | safe | high | yes |
| `ge-cimplicity` | GE CIMPLICITY HMI/SCADA | OT | ip | safe | high | yes |
| `ge-ifix` | GE iFIX SCADA/HMI | OT | ip | safe | high | yes |
| `iconics-genesis64` | ICONICS GENESIS64 SCADA/HMI | OT | ip | safe | high | yes |
| `ignition-scada` | Inductive Automation Ignition | OT | ip | safe | high |  |
| `kepware-kepserverex` | PTC Kepware KEPServerEX OPC Server | OT | ip | safe | high | yes |
| `opc-da-classic` | OPC-DA / OPC Classic (DCOM) | OT | ip | safe | high | yes |
| `osisoft-pi-system` | OSIsoft / AVEVA PI System (Historian) | OT | ip | safe | high |  |
| `schneider-clearscada` | Schneider Electric ClearSCADA / EcoStruxure Geo SCADA | OT | ip | safe | high | yes |
| `siemens-wincc` | Siemens WinCC SCADA/HMI | OT | ip | safe | critical | yes |
| `vtscada` | VTScada (Trihedral) SCADA | OT | ip | safe | medium | yes |
| `wonderware-historian` | AVEVA Wonderware Historian | OT | ip | safe | high |  |
| `wonderware-intouch` | AVEVA Wonderware InTouch HMI | OT | ip | safe | high | yes |

## Home automation (13)

| id | Technology | Domain | Transport | Safety | Severity | Life-safety |
|---|---|---|---|---|---|---|
| `amazon_alexa_echo` | Amazon Alexa / Echo | IOT | ip | intrusive | high |  |
| `apple_homekit_hap` | Apple HomeKit / HAP | IOT | ip | safe | medium |  |
| `control4` | Control4 | IOT | ip | intrusive | high |  |
| `google_home_nest` | Google Home / Nest | IOT | ip | intrusive | high |  |
| `home_assistant` | Home Assistant | IOT | ip | intrusive | high |  |
| `hubitat_elevation` | Hubitat Elevation | IOT | ip | intrusive | high |  |
| `insteon` | Insteon Hub / Protocol | IOT | ip | intrusive | critical |  |
| `openhab` | openHAB | IOT | ip | intrusive | high |  |
| `philips_hue` | Philips Hue Bridge | IOT | ip | intrusive | medium |  |
| `ring_arlo_cameras` | Ring / Arlo IP Cameras | IOT | ip | intrusive | high |  |
| `samsung_smartthings` | Samsung SmartThings | IOT | ip | intrusive | high |  |
| `tuya_cloud` | Tuya Smart Cloud | IOT | ip | intrusive | critical |  |
| `vera_micasaverde` | Vera / MiCasaVerde | IOT | ip | intrusive | high |  |

## Yacht & ship (marine) (15)

| id | Technology | Domain | Transport | Safety | Severity | Life-safety |
|---|---|---|---|---|---|---|
| `ais_transponder` | AIS Transponder (Class A/B VHF + IP gateway) | OT | rf | safe | critical | yes |
| `ballast_water_mgmt` | Ballast Water Management System (BWMS) | OT | ip | safe | medium | yes |
| `cargo_management` | Cargo Management System (CMS / LCMS) | OT | ip | safe | high | yes |
| `dynamic_positioning` | Dynamic Positioning (DP) System | OT | ip | safe | critical | yes |
| `ecdis` | ECDIS (Electronic Chart Display and Information System) | OT | ip | safe | critical | yes |
| `engine_monitoring` | Marine Engine / Propulsion Monitoring (Modbus/CAN) | OT | can | safe | high | yes |
| `gmdss` | GMDSS (Global Maritime Distress and Safety System) | OT | rf | safe | high | yes |
| `integrated_bridge` | Integrated Bridge System (IBS) | OT | ip | safe | critical | yes |
| `marine_satcom` | Marine VSAT / Inmarsat / Iridium Satcom | OT | ip | safe | high |  |
| `nmea2000` | NMEA 2000 / CAN backbone | OT | can | safe | critical | yes |
| `port_terminal_tos` | Port / Terminal Operating System (TOS) | OT | ip | safe | high |  |
| `radar_arpa` | Marine Radar / ARPA | OT | ip | safe | high | yes |
| `ship_alarm_monitoring` | Ship Alarm and Monitoring System (AMS/IAS) | OT | ip | safe | high | yes |
| `vdr` | VDR / S-VDR (Voyage Data Recorder) | OT | ip | safe | high | yes |
| `vessel_network_infra` | Vessel Network Infrastructure (Ship LAN / OT-IT convergence) | OT | ip | safe | high |  |

## Aircraft (aviation) (14)

| id | Technology | Domain | Transport | Safety | Severity | Life-safety |
|---|---|---|---|---|---|---|
| `acars` | ACARS (Aircraft Communications Addressing and Reporting System) | OT | rf | safe | high | yes |
| `adsb_1090es` | ADS-B 1090ES (Automatic Dependent Surveillance-Broadcast) | OT | rf | safe | high | yes |
| `aero_satcom` | Aero SATCOM (Inmarsat SwiftBroadband / SBB) | OT | rf | safe | critical | yes |
| `afdx_arinc664` | AFDX / ARINC 664 (Avionics Full-Duplex Switched Ethernet) | OT | arinc | safe | critical | yes |
| `airport_dcs` | Airport DCS / Baggage Handling System (BHS / DCS) | OT | ip | safe | high |  |
| `arinc429` | ARINC 429 (Avionics Digital Information Transfer System) | OT | arinc | safe | high | yes |
| `atc_automation` | ATC Automation (STARS / ERAM / TopSky — Air Traffic Control Systems) | OT | ip | safe | critical | yes |
| `cpdlc` | CPDLC (Controller-Pilot Data Link Communications) | OT | rf | safe | critical | yes |
| `efb` | EFB (Electronic Flight Bag) | OT | ip | safe | high | yes |
| `fadec` | FADEC (Full Authority Digital Engine Control) | OT | arinc | safe | critical | yes |
| `ife` | IFE (In-Flight Entertainment System) | OT | ip | safe | high | yes |
| `modes_transponder` | Mode-S Transponder (Secondary Surveillance Radar) | OT | rf | safe | high | yes |
| `tcas` | TCAS (Traffic Collision Avoidance System / ACAS II) | OT | rf | safe | critical | yes |
| `vdl2` | VDL Mode 2 (VHF Digital Link Mode 2) | OT | rf | safe | high | yes |

## Core OT/IoT/IT protocols (P0-P2) (54)

| id | Technology | Domain | Transport | Safety | Severity | Life-safety |
|---|---|---|---|---|---|---|
| `amx_netlinx` | AMX NetLinx (ICSP) | IOT | ip | safe | critical |  |
| `ble` | Bluetooth Low Energy (BLE) | IOT | rf | intrusive | high |  |
| `coap` | CoAP | IOT | ip | safe | medium |  |
| `dicom` | DICOM (PACS/modalities) | IOT | ip | safe | critical | yes |
| `hl7_mllp` | HL7 v2.x over MLLP | IOT | ip | safe | critical | yes |
| `ipp_pjl` | Network printers (IPP/PJL/JetDirect) | IOT | ip | safe | high |  |
| `lorawan` | LoRaWAN | IOT | rf | intrusive | high |  |
| `lutron_lip` | Lutron lighting (LIP) | IOT | ip | safe | medium |  |
| `matter_mdns` | Matter (mDNS commissioning) | IOT | ip | safe | medium |  |
| `mdns` | mDNS / DNS-SD | IOT | ip | safe | medium |  |
| `medical_devices` | Networked medical devices | IOT | ip | safe | critical | yes |
| `mqtt` | MQTT | IOT | ip | safe | high |  |
| `nas_appliances` | NAS (Synology/QNAP/WD) | IOT | ip | safe | high |  |
| `onvif_rtsp` | ONVIF / RTSP cameras | IOT | ip | safe | high |  |
| `smarthome_hubs` | Smart-home hubs (Hue/SmartThings/Tuya/Home Assistant) | IOT | ip | safe | high |  |
| `tr069_cpe` | Routers / CPE (TR-069/CWMP) | IOT | ip | safe | critical |  |
| `upnp_ssdp` | UPnP / SSDP | IOT | ip | safe | high |  |
| `wifi` | Wi-Fi (WPA2/WPA3) | IOT | rf | intrusive | high |  |
| `zigbee` | Zigbee (802.15.4) | IOT | rf | intrusive | high |  |
| `zwave` | Z-Wave (G.9959) | IOT | rf | intrusive | high |  |
| `cloud_imds` | Cloud IMDS (AWS/Azure/GCP) | IT | ip | intrusive | critical |  |
| `databases` | Databases (MSSQL/MySQL/PG/Mongo/Redis) | IT | ip | safe | critical |  |
| `docker` | Docker Engine / Registry | IT | ip | safe | critical |  |
| `fhir` | HL7 FHIR / SMART-on-FHIR | IT | ip | safe | high |  |
| `graphql` | GraphQL APIs | IT | ip | safe | high |  |
| `grpc` | gRPC / Protobuf | IT | ip | safe | high |  |
| `kerberos` | Kerberos (AD KDC) | IT | ip | safe | critical |  |
| `kubernetes` | Kubernetes (API/kubelet/etcd) | IT | ip | safe | critical |  |
| `ldap` | LDAP / Global Catalog | IT | ip | safe | high |  |
| `message_queues` | Message queues (AMQP/Kafka/Redis) | IT | ip | safe | high |  |
| `smb_ad` | Active Directory / SMB | IT | ip | safe | critical |  |
| `vpn_edge` | VPN / edge appliances | IT | ip | safe | critical |  |
| `bacnet` | BACnet/IP | OT | ip | safe | critical | yes |
| `can_uds` | CAN bus + UDS | OT | can | intrusive | critical | yes |
| `codesys` | CODESYS Runtime | OT | ip | safe | critical |  |
| `dlms_cosem` | DLMS/COSEM (smart meters) | OT | ip | safe | critical |  |
| `dnp3` | DNP3 | OT | ip | safe | high |  |
| `doip` | DoIP (automotive over IP) | OT | ip | safe | high |  |
| `ethernetip` | EtherNet/IP + CIP | OT | ip | safe | critical |  |
| `goose_sv` | IEC 61850 GOOSE / SV | OT | l2 | intrusive | critical | yes |
| `hart_ip` | HART-IP | OT | ip | safe | high |  |
| `iec104` | IEC 60870-5-104 | OT | ip | safe | critical |  |
| `j1939` | SAE J1939 (heavy vehicle) | OT | can | intrusive | critical | yes |
| `knxnet_ip` | KNXnet/IP | OT | ip | safe | high |  |
| `lonworks` | LonWorks / LonTalk (IP-852) | OT | ip | safe | high |  |
| `modbus` | Modbus / Modbus-TCP | OT | ip | safe | high |  |
| `niagara_fox` | Niagara Fox / Tridium | OT | ip | safe | critical |  |
| `nmea_maritime` | Maritime NMEA-over-IP | OT | ip | safe | critical | yes |
| `omron_fins` | OMRON FINS | OT | ip | safe | high |  |
| `opcua` | OPC-UA | OT | ip | safe | high |  |
| `osdp` | OSDP access control | OT | serial | intrusive | critical | yes |
| `profinet_dcp` | PROFINET DCP | OT | l2 | intrusive | high |  |
| `s7comm` | Siemens S7comm | OT | ip | safe | critical |  |
| `wiegand` | Legacy Wiegand | OT | serial | intrusive | high | yes |

## Keeping it current

`scripts/update_skills.py` runs weekly (cron / Task Scheduler): a CISA-KEV CVE refresh on existing skills + LLM trend-discovery that authors new schema-valid, FP-guarded skill files. Every write is validated; `--dry-run` previews; runs are logged to `knowledge/skills/.update_log.jsonl`.
