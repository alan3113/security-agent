from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import quote


class Reachability(StrEnum):
    REACHABLE = "reachable"
    POSSIBLE = "possible"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    direct: bool = False
    development: bool = False
    source: str = ""

    @property
    def purl(self) -> str:
        purl_type = {
            "npm": "npm",
            "PyPI": "pypi",
            "Go": "golang",
            "crates.io": "cargo",
            "Maven": "maven",
        }.get(self.ecosystem, self.ecosystem.lower())
        name = self.name
        if self.ecosystem == "Maven" and ":" in name:
            group, artifact = name.split(":", 1)
            name = f"{quote(group, safe='.')}/{quote(artifact, safe='.') }"
        else:
            name = quote(name, safe="/")
        return f"pkg:{purl_type}/{name}@{quote(self.version, safe='.+-_:')}"

    def osv_query(self) -> dict[str, Any]:
        return {
            "package": {"name": self.name, "ecosystem": self.ecosystem},
            "version": self.version,
        }


@dataclass(slots=True)
class Advisory:
    id: str
    summary: str
    details: str = ""
    aliases: list[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    cvss: float | None = None
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published: str | None = None
    modified: str | None = None

    @property
    def cves(self) -> list[str]:
        return [value for value in [self.id, *self.aliases] if value.startswith("CVE-")]


@dataclass(slots=True)
class Triage:
    reachability: Reachability = Reachability.UNKNOWN
    impact: str = ""
    fix: str = ""
    fixed_version: str | None = None
    evidence: list[str] = field(default_factory=list)
    llm_used: bool = False


@dataclass(slots=True)
class Finding:
    dependency: Dependency
    advisory: Advisory
    kev: bool = False
    epss: float | None = None
    triage: Triage = field(default_factory=Triage)
    priority: float = 0
    disposition: str = "log"

    @property
    def key(self) -> str:
        return f"{self.advisory.id}|{self.dependency.purl}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

