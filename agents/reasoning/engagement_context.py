"""
agents/reasoning/engagement_context.py

Structured representation of what the operator wants from this engagement.
Derived by an LLM reading operator notes + scope — not by regex.

Engagement types
----------------
pentest          Standard network / application penetration test
ctf              Capture-the-Flag — answer specific questions / find flags
forensics        Digital forensics — extract artifacts, build timelines
network_analysis Packet / traffic analysis — identify anomalies, protocols, IOCs
malware_analysis Static / dynamic malware analysis
compliance       Configuration audit / compliance check (CIS, PCI-DSS, etc.)
bug_bounty       Web / API bug-bounty hunt
red_team         Full adversary simulation with C2 / persistence
custom           Anything else — let the objectives list drive it
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class EngagementContext:
    engagement_type:       str        = "pentest"
    title:                 str        = ""
    context_summary:       str        = ""
    objectives:            List[dict] = field(default_factory=list)
    constraints:           List[str]  = field(default_factory=list)
    tools_preferred:       List[str]  = field(default_factory=list)
    tools_excluded:        List[str]  = field(default_factory=list)
    approach_summary:      str        = ""
    clarifying_questions:  List[str]  = field(default_factory=list)

    # ── Derived flags ─────────────────────────────────────────────────────────

    @property
    def needs_clarification(self) -> bool:
        return bool(self.clarifying_questions)

    @property
    def has_objectives(self) -> bool:
        return bool(self.objectives)

    @property
    def should_run_network_scan(self) -> bool:
        """True for engagement types that start with nmap / port scanning."""
        return self.engagement_type in {
            "pentest", "ctf", "red_team", "bug_bounty", "custom"
        }

    @property
    def should_run_exploitation(self) -> bool:
        """True when exploitation is in scope."""
        return self.engagement_type in {"pentest", "ctf", "red_team"}

    @property
    def is_passive_analysis(self) -> bool:
        """True for read-only / analysis-only engagements."""
        return self.engagement_type in {
            "forensics", "network_analysis", "malware_analysis", "compliance"
        }

    @property
    def is_ctf(self) -> bool:
        return self.engagement_type == "ctf"

    @property
    def is_forensics(self) -> bool:
        return self.engagement_type == "forensics"

    @property
    def is_network_analysis(self) -> bool:
        return self.engagement_type == "network_analysis"

    def is_tool_excluded(self, tool: str) -> bool:
        """Return True if this tool should not be run in this engagement."""
        tl = tool.lower().split()[0]
        return tl in {t.lower().split()[0] for t in self.tools_excluded}

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "engagement_type":      self.engagement_type,
            "title":                self.title,
            "context_summary":      self.context_summary,
            "objectives":           list(self.objectives),
            "constraints":          list(self.constraints),
            "tools_preferred":      list(self.tools_preferred),
            "tools_excluded":       list(self.tools_excluded),
            "approach_summary":     self.approach_summary,
            "clarifying_questions": list(self.clarifying_questions),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EngagementContext":
        return cls(
            engagement_type       = str(d.get("engagement_type", "pentest")),
            title                 = str(d.get("title", "")),
            context_summary       = str(d.get("context_summary", "")),
            objectives            = list(d.get("objectives") or []),
            constraints           = list(d.get("constraints") or []),
            tools_preferred       = list(d.get("tools_preferred") or []),
            tools_excluded        = list(d.get("tools_excluded") or []),
            approach_summary      = str(d.get("approach_summary", "")),
            clarifying_questions  = list(d.get("clarifying_questions") or []),
        )

    @classmethod
    def default_pentest(cls) -> "EngagementContext":
        return cls(
            engagement_type  = "pentest",
            title            = "Penetration Test",
            context_summary  = "Standard penetration test — no operator notes provided.",
            approach_summary = "Run full recon → vuln ID → web testing → exploit → post-exploit.",
        )


# ── Bootstrap tool lists by engagement type (module-level to avoid mutable default) ──
BOOTSTRAP_TOOLS: dict = {
    "pentest": [
        "nmap -sV -sC --open -T4 {target}",
        "nmap -p- --min-rate 5000 {target}",
    ],
    "ctf": [
        "nmap -sV -sC -p- --open {target}",
        "nmap --script vuln {target}",
    ],
    "forensics": [
        "file {target}",
        "strings {target}",
        "xxd {target} | head -100",
        "binwalk {target}",
        "foremost -i {target}",
    ],
    "network_analysis": [
        "tshark -r {target} -q -z io,phs",
        "tshark -r {target} -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn | head -50",
        "tshark -r {target} -Y 'http or dns or ftp or smtp' -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Info | head -200",
    ],
    "malware_analysis": [
        "file {target}",
        "strings -a {target} | head -500",
        "xxd {target} | head -200",
        "binwalk -e {target}",
    ],
    "compliance": [
        "nmap -sV --script ssl-enum-ciphers,http-security-headers {target}",
        "nmap --script smb-security-mode,smb2-security-mode {target}",
    ],
    "bug_bounty": [
        "nmap -sV -sC -p 80,443,8080,8443 {target}",
        "whatweb {target}",
        "nuclei -u {target} -severity critical,high",
    ],
    "red_team": [
        "nmap -sV -sC --open -T2 {target}",
        "nmap -p- --min-rate 2000 {target}",
    ],
}
