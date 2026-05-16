from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any

import httpx

from app.config import settings
from app.scanner.diff_parser import parse_unified_diff


@dataclass(slots=True)
class DependencySpec:
    name: str
    version: str
    ecosystem: str
    file: str
    line: int
    raw: str


@dataclass(slots=True)
class CVEFinding:
    cwe: str
    title: str
    severity: str
    file: str
    line: int
    code: str
    reason: str
    fix: str
    fixed_example: str
    vuln_id: str
    package: str
    version: str
    aliases: list[str]


PY_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+\-]+)")
NPM_LINE_RE = re.compile(r'^\s*"([@A-Za-z0-9_./-]+)"\s*:\s*"[\^~]?([0-9][^"]*)"')
MAVEN_RE = re.compile(r"<artifactId>([^<]+)</artifactId>.*?<version>([^<]+)</version>", re.DOTALL)


def parse_dependencies_from_diff(diff_text: str) -> list[DependencySpec]:
    dependencies: list[DependencySpec] = []
    for diff_file in parse_unified_diff(diff_text):
        path = diff_file.path.lower()
        for line in diff_file.scan_lines or diff_file.additions:
            raw = line.content.strip()
            if not raw or raw.startswith(("#", "//")):
                continue
            if path.endswith(("requirements.txt", "requirements-dev.txt", "constraints.txt", "pyproject.toml")):
                match = PY_REQ_RE.search(raw)
                if match:
                    dependencies.append(DependencySpec(match.group(1), match.group(2), "PyPI", diff_file.path, line.number, line.content))
            elif path.endswith(("package.json", "package-lock.json")):
                match = NPM_LINE_RE.search(raw)
                if match:
                    dependencies.append(DependencySpec(match.group(1), match.group(2), "npm", diff_file.path, line.number, line.content))
            elif path.endswith(("pom.xml",)):
                match = MAVEN_RE.search(raw)
                if match:
                    dependencies.append(DependencySpec(match.group(1), match.group(2), "Maven", diff_file.path, line.number, line.content))
    return dependencies[: settings.CVE_MAX_DEPENDENCIES]


def query_osv_batch(dependencies: list[DependencySpec]) -> list[dict[str, Any]]:
    if not dependencies or not settings.CVE_ENABLE:
        return []
    payload = {
        "queries": [
            {
                "version": dep.version,
                "package": {"name": dep.name, "ecosystem": dep.ecosystem},
            }
            for dep in dependencies
        ]
    }
    url = f"{settings.CVE_OSV_API_URL.rstrip('/')}/v1/querybatch"
    response = httpx.post(url, json=payload, timeout=settings.CVE_TIMEOUT)
    response.raise_for_status()
    results = response.json().get("results", [])
    enriched: list[dict[str, Any]] = []
    for dep, result in zip(dependencies, results, strict=False):
        for vuln in result.get("vulns", [])[:5]:
            enriched.append({"dependency": dep, "vuln": vuln})
    return enriched


def _severity_from_vuln(vuln: dict[str, Any]) -> str:
    database_specific = vuln.get("database_specific") or {}
    severity = str(database_specific.get("severity") or "").upper()
    if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return severity
    aliases = " ".join(vuln.get("aliases") or [])
    if "CVE-" in aliases:
        return "HIGH"
    return "MEDIUM"


def cve_findings_from_diff(diff_text: str) -> list[CVEFinding]:
    dependencies = parse_dependencies_from_diff(diff_text)
    findings: list[CVEFinding] = []
    for item in query_osv_batch(dependencies):
        dep: DependencySpec = item["dependency"]
        vuln: dict[str, Any] = item["vuln"]
        vuln_id = str(vuln.get("id") or "OSV")
        aliases = [str(alias) for alias in vuln.get("aliases") or []]
        summary = str(vuln.get("summary") or vuln.get("details") or "Known vulnerable dependency").splitlines()[0][:260]
        findings.append(
            CVEFinding(
                cwe="CVE",
                title=f"Vulnerable dependency: {dep.name}",
                severity=_severity_from_vuln(vuln),
                file=dep.file,
                line=dep.line,
                code=dep.raw,
                reason=f"Пакет {dep.name}=={dep.version} найден в базе OSV/CVE: {vuln_id}. {summary}",
                fix="Обновите зависимость до версии, в которой уязвимость исправлена, и проверьте changelog/advisory.",
                fixed_example=f"{dep.name}>=<fixed-version>",
                vuln_id=vuln_id,
                package=dep.name,
                version=dep.version,
                aliases=aliases,
            )
        )
    return findings


def query_cve_database(package: str, version: str, ecosystem: str = "PyPI") -> dict[str, Any]:
    dependency = DependencySpec(package, version, ecosystem, "manual-query", 1, f"{package}=={version}")
    try:
        results = query_osv_batch([dependency])
    except Exception as exc:
        return {"ok": False, "error": str(exc), "package": package, "version": version, "ecosystem": ecosystem}
    return {
        "ok": True,
        "package": package,
        "version": version,
        "ecosystem": ecosystem,
        "vulnerabilities": [
            {
                "id": item["vuln"].get("id"),
                "aliases": item["vuln"].get("aliases", []),
                "summary": item["vuln"].get("summary"),
                "details": (item["vuln"].get("details") or "")[:500],
            }
            for item in results
        ],
    }


def dependency_query_from_message(message: str) -> tuple[str, str, str] | None:
    patterns = [
        r"\b([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9_.!+\-]*)",
        r"\b([A-Za-z0-9_.-]+)@([0-9][A-Za-z0-9_.!+\-]*)",
        r"package\s+([A-Za-z0-9_.-]+)\s+version\s+([0-9][A-Za-z0-9_.!+\-]*)",
    ]
    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            ecosystem = "npm" if "npm" in message.lower() else "PyPI"
            return match.group(1), match.group(2), ecosystem
    return None
