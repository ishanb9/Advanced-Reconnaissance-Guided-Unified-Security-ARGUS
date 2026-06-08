"""Target-agnostic surface model.

A typed graph of what has been discovered. Each node carries CAPABILITIES from a
small general vocabulary, inferred from intel via generic STRUCTURAL heuristics
(parameter names, service flags) — never product-specific signatures. Capabilities
are what the hypothesis backlog maps against the weakness taxonomy, so the engine
generalises to any target type without naming any product or vuln.
"""
from __future__ import annotations

from typing import Any, Dict, List

# Generic param/endpoint name signals -> capability. Structural, not box-specific.
_PARAM_SIGNALS = {
    "fetches_remote": ("url", "uri", "link", "target", "dest", "callback", "webhook", "proxy", "fetch", "load"),
    "file_access":    ("path", "file", "filename", "dir", "download", "read", "doc", "include", "page"),
    "takes_input":    ("q", "query", "search", "id", "name", "input", "data", "param", "value", "filter"),
    "deserializes":   ("data", "payload", "obj", "state", "session", "blob", "cookie"),
    "templated":      ("template", "tpl", "format", "render", "view", "theme"),
    "redirects":      ("redirect", "next", "return", "returnurl", "continue", "goto", "dest"),
    "uploads":        ("upload", "file", "attachment", "import", "avatar"),
}
_AUTH_SERVICES = ("ssh", "ftp", "rdp", "smb", "mysql", "mssql", "postgres", "ldap",
                  "telnet", "vnc", "winrm", "redis", "mongo", "oracle")
_WEB_PORTS = (80, 443, 8080, 8443, 3000, 8000, 5000, 8888, 9000, 4200)


class SurfaceNode:
    def __init__(self, key: str, kind: str, ref: str = "", capabilities=None, meta=None):
        self.key = key
        self.kind = kind
        self.ref = ref
        self.capabilities = set(capabilities or [])
        self.meta = meta or {}

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "kind": self.kind, "ref": self.ref,
                "capabilities": sorted(self.capabilities), "meta": self.meta}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SurfaceNode":
        return cls(d["key"], d.get("kind", ""), d.get("ref", ""),
                   d.get("capabilities"), d.get("meta"))


class SurfaceModel:
    def __init__(self):
        self.nodes: Dict[str, SurfaceNode] = {}

    def add(self, node: SurfaceNode) -> None:
        ex = self.nodes.get(node.key)
        if ex:
            ex.capabilities |= node.capabilities
            ex.meta.update(node.meta)
        else:
            self.nodes[node.key] = node

    def all_capabilities(self) -> set:
        out: set = set()
        for n in self.nodes.values():
            out |= n.capabilities
        return out

    def infer_from_intel(self, intel: Dict[str, Any]) -> None:
        svc = intel.get("services") or {}
        for port in (intel.get("open_ports") or []):
            pn = port.get("port") if isinstance(port, dict) else port
            s = svc.get(pn) or svc.get(str(pn)) or (port if isinstance(port, dict) else {})
            caps: set = set()
            name = ""
            if isinstance(s, dict):
                name = " ".join(str(s.get(k, "")) for k in ("name", "product")).lower()
                if s.get("version") or s.get("product"):
                    caps.add("version_known")
            if any(a in name for a in _AUTH_SERVICES):
                caps.add("authenticates")
            try:
                is_web = ("http" in name) or (int(pn) in _WEB_PORTS)
            except Exception:
                is_web = "http" in name
            if is_web:
                caps.update({"renders_output", "takes_input"})
            self.add(SurfaceNode(f"port:{pn}", "service", str(pn), caps, {"service": name}))
        for path in (intel.get("web_paths") or []):
            p = path if isinstance(path, str) else (path.get("path") if isinstance(path, dict) else str(path))
            low = p.lower()
            caps = {"takes_input"} if ("?" in low or "=" in low) else set()
            for cap, signals in _PARAM_SIGNALS.items():
                if any(sig in low for sig in signals):
                    caps.add(cap)
            if "xml" in low or low.rstrip("/").endswith((".xml", ".svg")):
                caps.add("parses_format")
            self.add(SurfaceNode(f"path:{p}", "endpoint", p, caps))
        if intel.get("technologies"):
            self.add(SurfaceNode("tech:stack", "technology", "", {"version_known"},
                                 {"technologies": list(intel.get("technologies"))}))
        if intel.get("shell_access") or intel.get("rce_confirmed"):
            self.add(SurfaceNode("host:foothold", "host", "",
                                 {"executes", "file_access", "stores_secrets"}))

    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": [n.to_dict() for n in self.nodes.values()]}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SurfaceModel":
        sm = cls()
        for nd in (d or {}).get("nodes", []):
            sm.add(SurfaceNode.from_dict(nd))
        return sm
