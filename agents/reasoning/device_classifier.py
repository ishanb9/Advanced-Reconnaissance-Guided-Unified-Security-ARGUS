"""agents/reasoning/device_classifier.py — Device-type taxonomy + confidence.

The platform's primer / web / lateral chains were originally tuned for
generic Linux + Windows AD targets.  When the operator points the
platform at a network range containing IoT cameras, network printers,
embedded controllers, web apps, and full-OS hosts mixed together, each
target needs a DIFFERENT attack chain.  This module produces a single
``DeviceClassification`` per host that the playbook router consumes to
pick the right chain.

Inputs (all optional — uses what's available):
    open_ports:        list of int port numbers
    services:          dict {port -> {service, version, product, banner}}
    os_guess:          nmap OS detection string
    web_tech:          list of fingerprinted tech names (e.g. ["nginx", "wordpress"])
    banners:           dict {port -> raw banner text}
    target_kind:       'ip' | 'hostname' | 'url' | 'app' | 'cidr'
    raw_target:        original target string (used as a hint when scheme
                       was supplied, e.g. URL → likely web app)

Output:
    DeviceClassification(
        kind:        TaxonomyKind,
        os_family:   'linux' | 'windows' | 'macos' | 'embedded' | 'unknown',
        confidence:  0..1,
        labels:      list of matched signal labels (for explainability),
        playbooks:   ordered list of playbook IDs to run on this device,
        priority:    0..10 (higher = more interesting target),
        notes:       human-readable summary,
    )

The classifier is deterministic, fast, and never network-fetches — it
operates purely on already-collected recon data.  It is safe to call
many times per host as new evidence arrives; the latest call wins.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set


__all__ = [
    "TaxonomyKind", "DeviceClassification",
    "classify_device", "playbooks_for_kind",
]


class TaxonomyKind(str, Enum):
    """Coarse-grained device taxonomy.  Each maps to a playbook in the router."""

    # ── Full-OS hosts ─────────────────────────────────────────
    LINUX_SERVER       = "linux_server"          # general-purpose Linux box
    WINDOWS_SERVER     = "windows_server"        # Windows Server (DC excluded)
    WINDOWS_DC         = "windows_dc"            # Active Directory Domain Controller
    WINDOWS_WORKSTATION= "windows_workstation"   # Windows desktop/laptop
    MACOS              = "macos"

    # ── Web / Application targets ─────────────────────────────
    WEB_APP            = "web_app"               # generic webapp on http(s)
    WEB_API            = "web_api"               # REST/GraphQL API surface
    CMS                = "cms"                   # WordPress / Drupal / Joomla / etc.
    WEB_ADMIN_PANEL    = "web_admin_panel"       # Tomcat manager / Jenkins / phpMyAdmin
    INTRANET_PORTAL    = "intranet_portal"       # SharePoint / Confluence / Jira

    # ── Database servers ──────────────────────────────────────
    DATABASE           = "database"              # MySQL/Postgres/MSSQL/Mongo/Redis/Elastic

    # ── IoT / Embedded ────────────────────────────────────────
    IOT_CAMERA         = "iot_camera"            # IP camera / NVR
    IOT_PRINTER        = "iot_printer"           # network printer (JetDirect, IPP)
    IOT_ROUTER         = "iot_router"            # consumer/SoHo router/firewall
    IOT_VOIP           = "iot_voip"              # SIP / IP-PBX
    IOT_MEDIA          = "iot_media"             # smart TV, Chromecast, media server
    IOT_INDUSTRIAL     = "iot_industrial"        # PLC, SCADA, Modbus, BACnet
    IOT_SMART_HOME     = "iot_smart_home"        # Hue, Sonos, Nest, generic smart-home
    EMBEDDED_GENERIC   = "embedded_generic"      # unknown embedded device
    NETWORK_DEVICE     = "network_device"        # switches, APs, network appliances

    # ── Containers / Cloud / Virtualisation ───────────────────
    CONTAINER_HOST     = "container_host"        # Docker / Podman exposed
    KUBERNETES         = "kubernetes"            # k8s API server / kubelet
    HYPERVISOR         = "hypervisor"            # VMware / Hyper-V

    # ── Auxiliary services ────────────────────────────────────
    MAIL_SERVER        = "mail_server"           # SMTP / IMAP / Exchange
    FTP_SERVER         = "ftp_server"
    DNS_SERVER         = "dns_server"
    LDAP_SERVER        = "ldap_server"
    UNKNOWN            = "unknown"


@dataclass
class DeviceClassification:
    kind:        TaxonomyKind
    os_family:   str = "unknown"
    confidence:  float = 0.5
    labels:      List[str] = field(default_factory=list)
    playbooks:   List[str] = field(default_factory=list)
    priority:    int = 5
    notes:       str = ""

    def to_dict(self) -> dict:
        return {
            "kind":       self.kind.value,
            "os_family":  self.os_family,
            "confidence": self.confidence,
            "labels":     list(self.labels),
            "playbooks":  list(self.playbooks),
            "priority":   self.priority,
            "notes":      self.notes,
        }


# ────────────────────────────────────────────────────────────────────
# Playbook map — which automation chains to run per device type.
# Each entry is an ordered list of primer-chain IDs from decision_engine
# plus phase names from master_agent.  The reasoning loop already
# dispatches phases via _consider_pivots, so this map mostly drives the
# *priority* of which chains fire first for a given target.
# ────────────────────────────────────────────────────────────────────

_PLAYBOOKS: Dict[TaxonomyKind, List[str]] = {
    TaxonomyKind.LINUX_SERVER: [
        "credentialed-SSH", "default-creds", "post-foothold-linux", "lateral",
    ],
    TaxonomyKind.WINDOWS_SERVER: [
        "credentialed-AD", "no-creds-AD", "default-creds",
        "post-foothold-windows", "lateral",
    ],
    TaxonomyKind.WINDOWS_DC: [
        "credentialed-AD", "no-creds-AD", "ad-cs", "kerberoast", "asreproast",
        "secretsdump", "lateral",
    ],
    TaxonomyKind.WINDOWS_WORKSTATION: [
        "credentialed-AD", "default-creds", "post-foothold-windows",
    ],
    TaxonomyKind.MACOS: [
        "credentialed-SSH", "default-creds", "post-foothold-macos",
    ],

    TaxonomyKind.WEB_APP: [
        "web-exploit", "default-creds", "credentialed-Web",
    ],
    TaxonomyKind.WEB_API: [
        "web-exploit", "credentialed-Web",
    ],
    TaxonomyKind.CMS: [
        "web-exploit-cms", "default-creds", "credentialed-Web",
    ],
    TaxonomyKind.WEB_ADMIN_PANEL: [
        "default-creds", "credentialed-Web", "web-exploit",
    ],
    TaxonomyKind.INTRANET_PORTAL: [
        "default-creds", "credentialed-Web", "web-exploit",
    ],

    TaxonomyKind.DATABASE: [
        "credentialed-DB", "default-creds-db",
    ],

    TaxonomyKind.IOT_CAMERA: [
        "default-creds-iot-camera", "iot-firmware-cve", "rtsp-noauth",
    ],
    TaxonomyKind.IOT_PRINTER: [
        "default-creds-iot-printer", "snmp-public", "ipp-info-leak",
    ],
    TaxonomyKind.IOT_ROUTER: [
        "default-creds-router", "router-cve", "snmp-public",
    ],
    TaxonomyKind.IOT_VOIP: [
        "sip-enumeration", "default-creds-voip",
    ],
    TaxonomyKind.IOT_MEDIA: [
        "upnp-info", "default-creds-media",
    ],
    TaxonomyKind.IOT_INDUSTRIAL: [
        "modbus-read", "bacnet-enum", "industrial-recon",
    ],
    TaxonomyKind.IOT_SMART_HOME: [
        "default-creds-smarthome", "upnp-info",
    ],
    TaxonomyKind.EMBEDDED_GENERIC: [
        "default-creds", "telnet-default", "snmp-public",
    ],
    TaxonomyKind.NETWORK_DEVICE: [
        "snmp-public", "default-creds-network", "config-leak",
    ],

    TaxonomyKind.CONTAINER_HOST: [
        "docker-api-exposed", "registry-info", "container-escape",
    ],
    TaxonomyKind.KUBERNETES: [
        "k8s-api-anon", "kubelet-info", "kube-hunter",
    ],
    TaxonomyKind.HYPERVISOR: [
        "vcenter-cve", "default-creds-vmware",
    ],

    TaxonomyKind.MAIL_SERVER: [
        "smtp-relay", "imap-default-creds",
    ],
    TaxonomyKind.FTP_SERVER: [
        "ftp-anonymous", "default-creds-ftp",
    ],
    TaxonomyKind.DNS_SERVER: [
        "dns-zone-transfer", "dns-cache-snoop",
    ],
    TaxonomyKind.LDAP_SERVER: [
        "ldap-anonymous-bind", "credentialed-Web",
    ],
    TaxonomyKind.UNKNOWN: [
        "default-creds",
    ],
}


def playbooks_for_kind(kind: TaxonomyKind) -> List[str]:
    """Return the ordered playbook list for a taxonomy kind."""
    return list(_PLAYBOOKS.get(kind, _PLAYBOOKS[TaxonomyKind.UNKNOWN]))


# ────────────────────────────────────────────────────────────────────
# Classifier
# ────────────────────────────────────────────────────────────────────

# Port → service-class hints.  Used as evidence even when banners are
# empty.  A single port match doesn't lock the verdict — we score across
# multiple signals and pick the strongest.
_PORT_HINTS: Dict[int, List[str]] = {
    21:    ["ftp"],
    22:    ["ssh"],
    23:    ["telnet", "embedded"],
    25:    ["smtp", "mail"],
    53:    ["dns"],
    80:    ["http"],
    88:    ["kerberos", "ad"],
    110:   ["pop3", "mail"],
    111:   ["rpcbind"],
    119:   ["nntp"],
    123:   ["ntp"],
    135:   ["msrpc", "windows"],
    137:   ["netbios", "windows"],
    138:   ["netbios", "windows"],
    139:   ["smb", "windows"],
    143:   ["imap", "mail"],
    161:   ["snmp", "embedded"],
    162:   ["snmptrap"],
    179:   ["bgp", "network"],
    389:   ["ldap", "ad"],
    443:   ["https"],
    445:   ["smb", "windows"],
    465:   ["smtps", "mail"],
    500:   ["ipsec", "vpn"],
    502:   ["modbus", "industrial"],
    515:   ["lpd", "printer"],
    520:   ["rip", "network"],
    554:   ["rtsp", "iot_camera"],
    587:   ["smtp_submission", "mail"],
    593:   ["msrpc_http", "windows"],
    623:   ["ipmi", "embedded"],
    631:   ["ipp", "printer"],
    636:   ["ldaps", "ad"],
    873:   ["rsync"],
    902:   ["vmware", "hypervisor"],
    993:   ["imaps", "mail"],
    995:   ["pop3s", "mail"],
    1080:  ["socks_proxy"],
    1099:  ["rmi", "java"],
    1194:  ["openvpn"],
    1433:  ["mssql", "database"],
    1521:  ["oracle", "database"],
    1900:  ["upnp", "iot"],
    2049:  ["nfs"],
    2181:  ["zookeeper"],
    2375:  ["docker", "container"],
    2376:  ["docker_tls", "container"],
    2379:  ["etcd", "k8s"],
    2483:  ["oracle", "database"],
    3000:  ["dev_web"],
    3128:  ["squid_proxy"],
    3268:  ["gc_ldap", "ad"],
    3269:  ["gc_ldaps", "ad"],
    3306:  ["mysql", "database"],
    3389:  ["rdp", "windows"],
    3690:  ["svn"],
    3702:  ["ws_discovery", "iot"],
    4242:  ["dev"],
    4369:  ["epmd", "erlang"],
    4500:  ["ipsec", "vpn"],
    4848:  ["glassfish", "java"],
    5000:  ["dev_web"],
    5001:  ["dev_web"],
    5060:  ["sip", "voip"],
    5061:  ["sips", "voip"],
    5222:  ["xmpp"],
    5353:  ["mdns", "iot"],
    5432:  ["postgres", "database"],
    5601:  ["kibana", "elastic"],
    5666:  ["nrpe", "monitoring"],
    5672:  ["amqp", "message_queue"],
    5800:  ["vnc_http"],
    5900:  ["vnc"],
    5984:  ["couchdb", "database"],
    5985:  ["winrm", "windows"],
    5986:  ["winrm_https", "windows"],
    6379:  ["redis", "database"],
    6443:  ["k8s_api", "k8s"],
    6667:  ["irc"],
    7000:  ["cassandra", "database"],
    7001:  ["weblogic", "java"],
    8000:  ["dev_web"],
    8080:  ["http_alt"],
    8081:  ["http_alt"],
    8088:  ["yarn", "hadoop"],
    8089:  ["splunk"],
    8443:  ["https_alt"],
    8500:  ["consul"],
    8888:  ["dev_web"],
    9000:  ["dev_web", "sonarqube"],
    9090:  ["prometheus"],
    9092:  ["kafka"],
    9100:  ["jetdirect", "printer"],
    9200:  ["elasticsearch", "database"],
    9300:  ["elasticsearch_internal"],
    9389:  ["adws", "ad"],
    10000: ["webmin", "admin_panel"],
    11211: ["memcached"],
    15672: ["rabbitmq_mgmt"],
    27017: ["mongodb", "database"],
    27018: ["mongodb_shard"],
    47808: ["bacnet", "industrial"],
    49664: ["msrpc_dynamic", "windows"],
    50050: ["cobaltstrike"],
}


# ── Banner / product fingerprint regexes ────────────────────────────
_BANNER_RULES = [
    # (regex, kind, label, confidence_boost)
    (re.compile(r"(?i)microsoft.*windows", ),       TaxonomyKind.WINDOWS_SERVER, "windows", 0.85),
    (re.compile(r"(?i)domain controller|active directory|kerberos|ldap.*microsoft"), TaxonomyKind.WINDOWS_DC, "ad", 0.9),
    (re.compile(r"(?i)windows.{0,40}workstation|windows 10|windows 11"), TaxonomyKind.WINDOWS_WORKSTATION, "win-ws", 0.8),
    (re.compile(r"(?i)samba"),                       TaxonomyKind.LINUX_SERVER, "samba", 0.7),
    (re.compile(r"(?i)openssh.*ubuntu|openssh.*debian|openssh.*centos|openssh.*linux"), TaxonomyKind.LINUX_SERVER, "openssh-linux", 0.85),
    (re.compile(r"(?i)mac\s*os|darwin"),             TaxonomyKind.MACOS, "macos", 0.85),

    # CMS / web platforms
    (re.compile(r"(?i)wordpress|wp-(?:admin|content|login|json)"), TaxonomyKind.CMS, "wordpress", 0.85),
    (re.compile(r"(?i)drupal"),                      TaxonomyKind.CMS, "drupal", 0.85),
    (re.compile(r"(?i)joomla"),                      TaxonomyKind.CMS, "joomla", 0.85),
    (re.compile(r"(?i)magento|mage[-_]"),            TaxonomyKind.CMS, "magento", 0.85),
    (re.compile(r"(?i)tomcat manager|/manager/(?:html|text)"), TaxonomyKind.WEB_ADMIN_PANEL, "tomcat-mgr", 0.9),
    (re.compile(r"(?i)jenkins"),                     TaxonomyKind.WEB_ADMIN_PANEL, "jenkins", 0.85),
    (re.compile(r"(?i)phpmyadmin"),                  TaxonomyKind.WEB_ADMIN_PANEL, "phpmyadmin", 0.9),
    (re.compile(r"(?i)gitlab|gitea|gogs"),           TaxonomyKind.WEB_ADMIN_PANEL, "git-portal", 0.8),
    (re.compile(r"(?i)confluence"),                  TaxonomyKind.INTRANET_PORTAL, "confluence", 0.85),
    (re.compile(r"(?i)jira"),                        TaxonomyKind.INTRANET_PORTAL, "jira", 0.85),
    (re.compile(r"(?i)sharepoint"),                  TaxonomyKind.INTRANET_PORTAL, "sharepoint", 0.85),

    # Databases
    (re.compile(r"(?i)mysql"),                       TaxonomyKind.DATABASE, "mysql", 0.9),
    (re.compile(r"(?i)mariadb"),                     TaxonomyKind.DATABASE, "mariadb", 0.9),
    (re.compile(r"(?i)postgres"),                    TaxonomyKind.DATABASE, "postgres", 0.9),
    (re.compile(r"(?i)mongodb"),                     TaxonomyKind.DATABASE, "mongodb", 0.9),
    (re.compile(r"(?i)microsoft sql server|\bmssql"), TaxonomyKind.DATABASE, "mssql", 0.9),
    (re.compile(r"(?i)oracle"),                      TaxonomyKind.DATABASE, "oracle", 0.85),
    (re.compile(r"(?i)redis"),                       TaxonomyKind.DATABASE, "redis", 0.9),
    (re.compile(r"(?i)elasticsearch"),               TaxonomyKind.DATABASE, "elasticsearch", 0.9),
    (re.compile(r"(?i)couchdb|cassandra"),           TaxonomyKind.DATABASE, "nosql", 0.85),

    # IoT / Embedded
    (re.compile(r"(?i)hikvision|dahua|axis.*camera|surveillance|nvr|dvr"), TaxonomyKind.IOT_CAMERA, "ip-camera", 0.9),
    (re.compile(r"(?i)hp.*laserjet|hp.*officejet|jetdirect|brother.*printer|canon.*ipp|epson.*epl"), TaxonomyKind.IOT_PRINTER, "printer", 0.9),
    (re.compile(r"(?i)mikrotik|tp-link|d-link|netgear|asuswrt|openwrt|tomato.*firmware|cisco.*ios"), TaxonomyKind.IOT_ROUTER, "router", 0.85),
    (re.compile(r"(?i)freeswitch|asterisk|3cx|fanvil|grandstream|polycom|yealink"), TaxonomyKind.IOT_VOIP, "voip", 0.9),
    (re.compile(r"(?i)samsung tv|chromecast|sonos|roku|plex"), TaxonomyKind.IOT_MEDIA, "media", 0.85),
    (re.compile(r"(?i)modbus|bacnet|s7comm|siemens.*plc|allen.bradley|schneider electric"), TaxonomyKind.IOT_INDUSTRIAL, "ics", 0.95),
    (re.compile(r"(?i)nest|hue.*bridge|smartthings|wemo|alexa"), TaxonomyKind.IOT_SMART_HOME, "smart-home", 0.85),

    # Containers / k8s / hypervisors
    (re.compile(r"(?i)docker"),                      TaxonomyKind.CONTAINER_HOST, "docker", 0.85),
    (re.compile(r"(?i)kubernetes|kubelet|k8s"),      TaxonomyKind.KUBERNETES, "k8s", 0.9),
    (re.compile(r"(?i)vmware|esxi|vsphere|vcenter"), TaxonomyKind.HYPERVISOR, "vmware", 0.9),

    # Mail
    (re.compile(r"(?i)exchange|microsoft.*owa"),     TaxonomyKind.MAIL_SERVER, "exchange", 0.9),
    (re.compile(r"(?i)postfix|sendmail|exim|courier"), TaxonomyKind.MAIL_SERVER, "smtp-linux", 0.8),
]


def _gather_text(services: Dict, banners: Dict) -> str:
    """Concatenate all banner / product / service info into one string."""
    blob: List[str] = []
    for port, svc in (services or {}).items():
        if isinstance(svc, dict):
            for k in ("service", "version", "product", "banner", "extrainfo", "ostype"):
                v = svc.get(k)
                if v: blob.append(str(v))
        elif svc:
            blob.append(str(svc))
    for port, banner in (banners or {}).items():
        if banner:
            blob.append(str(banner))
    return " ".join(blob)


def classify_device(
    *,
    open_ports:  Optional[List[int]] = None,
    services:    Optional[Dict]      = None,
    os_guess:    Optional[str]       = None,
    web_tech:    Optional[List[str]] = None,
    banners:     Optional[Dict]      = None,
    target_kind: Optional[str]       = None,
    raw_target:  Optional[str]       = None,
) -> DeviceClassification:
    """Score-based device classifier.  See module docstring for full
    behaviour.  Always returns a DeviceClassification — falls back to
    UNKNOWN with low confidence when nothing matches.
    """
    open_ports = list({int(p) for p in (open_ports or []) if str(p).isdigit() or isinstance(p, int)})
    services   = services or {}
    banners    = banners  or {}
    web_tech   = [str(t).lower() for t in (web_tech or [])]
    os_guess_l = (os_guess or "").lower()
    raw_target = (raw_target or "").lower()
    target_kind = (target_kind or "").lower()

    # Score table — kind → cumulative confidence
    scores: Dict[TaxonomyKind, float] = {}
    labels: Set[str] = set()
    text_blob = _gather_text(services, banners) + " " + os_guess_l + " " + " ".join(web_tech)

    def _bump(k: TaxonomyKind, amount: float, label: str = "") -> None:
        scores[k] = scores.get(k, 0.0) + amount
        if label: labels.add(label)

    # 1. URL/app target → strong web-app prior
    if target_kind in ("url", "app"):
        _bump(TaxonomyKind.WEB_APP, 0.7, "target=url")
        if raw_target.endswith(("/api", "/api/", "/graphql", "/v1", "/v2")):
            _bump(TaxonomyKind.WEB_API, 0.5, "url=api-path")

    # 2. Banner / product regex pass — strongest signal
    for pat, kind, label, boost in _BANNER_RULES:
        if pat.search(text_blob):
            _bump(kind, boost, label)

    # 3. Port-based heuristics
    has_smb     = any(p in open_ports for p in (139, 445))
    has_winrm   = any(p in open_ports for p in (5985, 5986))
    has_rdp     = 3389 in open_ports
    has_kerb    = 88   in open_ports
    has_ldap    = any(p in open_ports for p in (389, 636, 3268, 3269))
    has_adws    = 9389 in open_ports
    has_ssh     = 22   in open_ports
    has_http    = any(p in open_ports for p in (80, 443, 8080, 8443, 8000, 5000, 3000))
    has_https   = any(p in open_ports for p in (443, 8443))
    has_ipp     = 631  in open_ports or 9100 in open_ports
    has_rtsp    = 554  in open_ports
    has_modbus  = 502  in open_ports
    has_bacnet  = 47808 in open_ports
    has_sip     = any(p in open_ports for p in (5060, 5061))
    has_db_port = any(p in open_ports for p in (1433, 1521, 3306, 5432, 6379, 9200, 27017, 5984))
    has_docker  = any(p in open_ports for p in (2375, 2376))
    has_k8s     = any(p in open_ports for p in (6443, 10250, 2379))
    has_vmware  = 902 in open_ports

    # AD detection — strongest combo wins
    if has_kerb and has_ldap and has_smb:
        _bump(TaxonomyKind.WINDOWS_DC, 0.95, "ad-trio")
    elif has_smb and (has_winrm or has_rdp):
        _bump(TaxonomyKind.WINDOWS_SERVER, 0.7, "win-srv-ports")

    if has_smb and not has_kerb:
        _bump(TaxonomyKind.WINDOWS_WORKSTATION, 0.4, "smb-only")

    if has_ssh and not has_smb and not has_winrm:
        _bump(TaxonomyKind.LINUX_SERVER, 0.65, "ssh-no-smb")

    if has_db_port and not has_smb and not has_ssh:
        _bump(TaxonomyKind.DATABASE, 0.7, "bare-db-port")

    if has_ipp:
        _bump(TaxonomyKind.IOT_PRINTER, 0.85, "ipp/jetdirect")
    if has_rtsp:
        _bump(TaxonomyKind.IOT_CAMERA, 0.85, "rtsp")
    if has_modbus or has_bacnet:
        _bump(TaxonomyKind.IOT_INDUSTRIAL, 0.95, "industrial-protocol")
    if has_sip:
        _bump(TaxonomyKind.IOT_VOIP, 0.85, "sip")
    if has_docker:
        _bump(TaxonomyKind.CONTAINER_HOST, 0.9, "docker-api")
    if has_k8s:
        _bump(TaxonomyKind.KUBERNETES, 0.9, "k8s-api")
    if has_vmware:
        _bump(TaxonomyKind.HYPERVISOR, 0.85, "esxi")

    # Web-only host
    if has_http and not (has_smb or has_ssh or has_db_port):
        _bump(TaxonomyKind.WEB_APP, 0.6, "http-only")

    # Service tags from web fingerprinter
    for tech in web_tech:
        if tech in ("wordpress", "drupal", "joomla", "magento"):
            _bump(TaxonomyKind.CMS, 0.5, f"web-tech:{tech}")
        if tech in ("tomcat", "jenkins", "phpmyadmin"):
            _bump(TaxonomyKind.WEB_ADMIN_PANEL, 0.5, f"web-tech:{tech}")
        if tech in ("confluence", "jira", "sharepoint"):
            _bump(TaxonomyKind.INTRANET_PORTAL, 0.5, f"web-tech:{tech}")
        if tech in ("nginx", "apache", "iis", "caddy"):
            _bump(TaxonomyKind.WEB_APP, 0.2, f"web-tech:{tech}")

    # OS guess pass
    if "windows" in os_guess_l:
        _bump(TaxonomyKind.WINDOWS_SERVER, 0.5, "os=windows")
    if any(t in os_guess_l for t in ("linux", "ubuntu", "debian", "centos", "rhel", "fedora")):
        _bump(TaxonomyKind.LINUX_SERVER, 0.5, "os=linux")
    if "mac" in os_guess_l or "darwin" in os_guess_l:
        _bump(TaxonomyKind.MACOS, 0.5, "os=macos")
    if any(t in os_guess_l for t in ("embedded", "vxworks", "qnx", "busybox")):
        _bump(TaxonomyKind.EMBEDDED_GENERIC, 0.6, "os=embedded")

    # SNMP-only embedded fallback
    if 161 in open_ports and not (has_ssh or has_smb or has_http):
        _bump(TaxonomyKind.NETWORK_DEVICE, 0.5, "snmp-only")

    # Pick the highest-scoring kind
    if not scores:
        return DeviceClassification(
            kind = TaxonomyKind.UNKNOWN,
            os_family = "unknown",
            confidence = 0.2,
            labels = [],
            playbooks = playbooks_for_kind(TaxonomyKind.UNKNOWN),
            priority = 3,
            notes = "No signals matched — UNKNOWN.  Run more recon.",
        )

    best_kind = max(scores.keys(), key=lambda k: scores[k])
    best_score = scores[best_kind]
    confidence = max(0.0, min(1.0, best_score))

    os_family = "unknown"
    if best_kind in (TaxonomyKind.LINUX_SERVER,):
        os_family = "linux"
    elif best_kind in (TaxonomyKind.WINDOWS_SERVER, TaxonomyKind.WINDOWS_DC, TaxonomyKind.WINDOWS_WORKSTATION):
        os_family = "windows"
    elif best_kind == TaxonomyKind.MACOS:
        os_family = "macos"
    elif best_kind in (
        TaxonomyKind.IOT_CAMERA, TaxonomyKind.IOT_PRINTER, TaxonomyKind.IOT_ROUTER,
        TaxonomyKind.IOT_VOIP, TaxonomyKind.IOT_MEDIA, TaxonomyKind.IOT_INDUSTRIAL,
        TaxonomyKind.IOT_SMART_HOME, TaxonomyKind.EMBEDDED_GENERIC,
        TaxonomyKind.NETWORK_DEVICE,
    ):
        os_family = "embedded"

    # Priority — DCs and industrial systems are high-impact
    priority = 5
    if best_kind == TaxonomyKind.WINDOWS_DC:        priority = 10
    elif best_kind == TaxonomyKind.IOT_INDUSTRIAL:  priority = 9
    elif best_kind == TaxonomyKind.HYPERVISOR:      priority = 9
    elif best_kind == TaxonomyKind.KUBERNETES:      priority = 8
    elif best_kind in (TaxonomyKind.WEB_ADMIN_PANEL, TaxonomyKind.DATABASE): priority = 7
    elif best_kind in (TaxonomyKind.WINDOWS_SERVER, TaxonomyKind.LINUX_SERVER): priority = 6

    return DeviceClassification(
        kind = best_kind,
        os_family = os_family,
        confidence = confidence,
        labels = sorted(labels),
        playbooks = playbooks_for_kind(best_kind),
        priority = priority,
        notes = (
            f"{best_kind.value.replace('_', ' ').title()} — score={best_score:.2f}, "
            f"signals: {', '.join(sorted(labels)[:6]) or 'port-only'}"
        ),
    )
