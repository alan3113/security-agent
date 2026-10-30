from __future__ import annotations

import json
import re
import subprocess
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

from security_agent.models import Dependency


class InventoryError(RuntimeError):
    pass


class InventoryScanner:
    """Create a normalized inventory from lockfiles or a Syft CycloneDX SBOM."""

    LOCKFILES = ("package-lock.json", "requirements.txt", "poetry.lock", "go.sum", "Cargo.lock", "pom.xml")

    def scan(self, repository: Path, *, use_syft: bool = False) -> list[Dependency]:
        repository = repository.resolve()
        if use_syft:
            dependencies = self._scan_syft(repository)
        else:
            dependencies = []
            for name in self.LOCKFILES:
                for lockfile in repository.rglob(name):
                    if any(part in {"node_modules", ".venv", "venv", ".git"} for part in lockfile.parts):
                        continue
                    dependencies.extend(self._parse(lockfile))
        unique: dict[tuple[str, str, str], Dependency] = {}
        for dependency in dependencies:
            key = (dependency.ecosystem, dependency.name.lower(), dependency.version)
            previous = unique.get(key)
            if previous is None or (dependency.direct and not previous.direct):
                unique[key] = dependency
        return sorted(unique.values(), key=lambda item: (item.ecosystem, item.name.lower(), item.version))

    def _parse(self, path: Path) -> list[Dependency]:
        parsers = {
            "package-lock.json": self._package_lock,
            "requirements.txt": self._requirements,
            "poetry.lock": self._poetry,
            "go.sum": self._go_sum,
            "Cargo.lock": self._cargo_lock,
            "pom.xml": self._pom,
        }
        try:
            return parsers[path.name](path)
        except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError, ET.ParseError) as exc:
            raise InventoryError(f"Could not parse {path}: {exc}") from exc

    @staticmethod
    def _package_lock(path: Path) -> list[Dependency]:
        data = json.loads(path.read_text())
        packages = data.get("packages", {})
        root_package = packages.get("", {})
        root_dependencies = {
            **data.get("dependencies", {}),
            **data.get("devDependencies", {}),
            **data.get("optionalDependencies", {}),
            **root_package.get("dependencies", {}),
            **root_package.get("devDependencies", {}),
            **root_package.get("optionalDependencies", {}),
        }
        result: list[Dependency] = []
        if packages:
            for location, metadata in packages.items():
                if not location or not metadata.get("version"):
                    continue
                name = metadata.get("name") or location.rsplit("node_modules/", 1)[-1]
                result.append(Dependency(
                    name=name,
                    version=str(metadata["version"]),
                    ecosystem="npm",
                    direct=name in root_dependencies and location.count("node_modules/") == 1,
                    development=bool(metadata.get("dev", False)),
                    source=str(path),
                ))
            return result

        def walk(dependencies: dict, direct: bool = True) -> None:
            for name, metadata in dependencies.items():
                if metadata.get("version"):
                    result.append(Dependency(name, str(metadata["version"]), "npm", direct,
                                             bool(metadata.get("dev", False)), str(path)))
                walk(metadata.get("dependencies", {}), False)

        walk(data.get("dependencies", {}))
        return result

    @staticmethod
    def _requirements(path: Path) -> list[Dependency]:
        result = []
        pattern = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?==([^\s;]+)")
        for line in path.read_text().splitlines():
            match = pattern.match(line)
            if match:
                result.append(Dependency(match.group(1), match.group(2), "PyPI", True, False, str(path)))
        return result

    @staticmethod
    def _poetry(path: Path) -> list[Dependency]:
        data = tomllib.loads(path.read_text())
        result = []
        for package in data.get("package", []):
            groups = package.get("groups", [])
            development = package.get("category") == "dev" or (groups and "main" not in groups)
            result.append(Dependency(package["name"], str(package["version"]), "PyPI", False,
                                     development, str(path)))
        return result

    @staticmethod
    def _go_sum(path: Path) -> list[Dependency]:
        result = []
        seen = set()
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            name, version = parts[0], parts[1].removesuffix("/go.mod")
            key = (name, version)
            if key not in seen:
                seen.add(key)
                result.append(Dependency(name, version, "Go", False, False, str(path)))
        return result

    @staticmethod
    def _cargo_lock(path: Path) -> list[Dependency]:
        data = tomllib.loads(path.read_text())
        return [Dependency(package["name"], str(package["version"]), "crates.io", False, False, str(path))
                for package in data.get("package", [])]

    @staticmethod
    def _pom(path: Path) -> list[Dependency]:
        root = ET.parse(path).getroot()
        namespace = root.tag.split("}")[0] + "}" if "}" in root.tag else ""
        properties = {node.tag.split("}")[-1]: (node.text or "")
                      for node in root.findall(f"{namespace}properties/*")}
        result = []
        for node in root.findall(f".//{namespace}dependencies/{namespace}dependency"):
            value = lambda tag: node.findtext(f"{namespace}{tag}") or ""
            version = value("version")
            match = re.fullmatch(r"\$\{(.+)}", version)
            if match:
                version = properties.get(match.group(1), "")
            if not version:
                continue
            scope = value("scope")
            result.append(Dependency(f"{value('groupId')}:{value('artifactId')}", version, "Maven", True,
                                     scope == "test", str(path)))
        return result

    @staticmethod
    def _scan_syft(repository: Path) -> list[Dependency]:
        try:
            completed = subprocess.run(
                ["syft", f"dir:{repository}", "-o", "cyclonedx-json"],
                check=True, capture_output=True, text=True, timeout=300,
            )
        except FileNotFoundError as exc:
            raise InventoryError("Syft was requested but is not installed") from exc
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise InventoryError(f"Syft failed: {exc}") from exc
        data = json.loads(completed.stdout)
        result = []
        ecosystem_by_type = {"npm": "npm", "pypi": "PyPI", "golang": "Go", "cargo": "crates.io", "maven": "Maven"}
        for component in data.get("components", []):
            purl = component.get("purl", "")
            match = re.match(r"pkg:([^/]+)/(.+?)@([^?]+)", purl)
            if not match or match.group(1) not in ecosystem_by_type:
                continue
            result.append(Dependency(component.get("name", match.group(2)), component.get("version", match.group(3)),
                                     ecosystem_by_type[match.group(1)], False,
                                     component.get("scope") == "excluded", "syft"))
        return result
