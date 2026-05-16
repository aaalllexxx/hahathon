from __future__ import annotations

import json
import re
from typing import Any

from app.config import settings
from app.llm.client import get_openai_client
from app.llm.prompts import SYSTEM_PROMPT, build_diff_review_prompt, build_user_prompt


def _parse_json_response(content: str) -> dict[str, Any]:
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", content, flags=re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def review_finding(diff_text: str, finding: object) -> dict[str, Any]:
    client = get_openai_client()
    response = client.chat.completions.create(
        model=settings.OPENAI_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(diff_text=diff_text, finding=finding)},
        ],
        temperature=settings.OPENAI_TEMPERATURE,
        max_tokens=settings.OPENAI_MAX_TOKENS,
    )
    content = response.choices[0].message.content or "{}"
    parsed = _parse_json_response(content)
    verdict = str(parsed.get("verdict", "WARN")).upper()
    if verdict not in {"BLOCK", "WARN", "PASS"}:
        parsed["verdict"] = "WARN"
    else:
        parsed["verdict"] = verdict
    return parsed


def review_findings(diff_text: str, findings: list[object]) -> list[dict[str, Any]]:
    return [review_finding(diff_text, finding) for finding in findings]


def _extract_imports(diff_text: str) -> list[str]:
    """Extract Python/JS import names from diff to check against CVE databases."""
    imports = set()
    for m in re.finditer(r"^\+\s*(?:import|from)\s+([A-Za-z0-9_]+)", diff_text, re.MULTILINE):
        imports.add(m.group(1))
    for m in re.finditer(r'^\+\s*(?:const|let|var)\s+\w+\s*=\s*require\(["\']([^"\']+)', diff_text, re.MULTILINE):
        imports.add(m.group(1))
    return list(imports)


# Map stdlib modules to their CPython package name for OSV queries
_STDLIB_TO_CPYTHON = {
    "zipfile", "tarfile", "xml", "pickle", "urllib", "http",
    "ssl", "hashlib", "tempfile", "subprocess", "os", "shutil",
    "ftplib", "imaplib", "smtplib", "telnetlib", "cgi",
}


def _query_osv(query_payload: dict, timeout: int = 10) -> list[dict]:
    """Generic OSV API query."""
    import httpx
    try:
        resp = httpx.post(
            f"{settings.CVE_OSV_API_URL.rstrip('/')}/v1/query",
            json=query_payload,
            timeout=timeout,
        )
        if resp.status_code == 200:
            return resp.json().get("vulns", [])
    except Exception:
        pass
    return []


def _search_cve_for_libraries(diff_text: str) -> list[dict[str, Any]]:
    """Query OSV API for CVEs related to libraries found in the diff."""
    imports = _extract_imports(diff_text)
    if not imports:
        return []

    cve_findings = []
    for lib in imports[:10]:
        vulns = []
        # Query PyPI ecosystem
        vulns.extend(_query_osv({"package": {"name": lib, "ecosystem": "PyPI"}}))
        # If it's a stdlib module, also query CPython
        if lib in _STDLIB_TO_CPYTHON:
            vulns.extend(_query_osv({"package": {"name": "cpython", "ecosystem": "GIT"}}))
            # Also try direct text search for the module name
            vulns.extend(_query_osv({"package": {"name": f"stdlib-{lib}", "ecosystem": "PyPI"}}))

        for vuln in vulns[:5]:
            vuln_id = vuln.get("id", "")
            aliases = vuln.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
            summary = (vuln.get("summary") or vuln.get("details") or "")[:200]
            # Skip if summary doesn't mention the library at all (for CPython bulk results)
            if lib in _STDLIB_TO_CPYTHON and lib not in summary.lower():
                continue
            cve_findings.append({
                "verdict": "BLOCK",
                "confidence": 0.85,
                "cwe": "CVE",
                "title": f"{cve_id}: {lib} — {summary[:80]}",
                "severity": "HIGH",
                "file": "",
                "line": 1,
                "code": f"import {lib}",
                "reason": f"Библиотека {lib} имеет известную уязвимость {cve_id}. {summary}",
                "safe_fix": f"Обновите {lib} до исправленной версии или используйте безопасную альтернативу.",
                "fixed_code": "",
            })
    return cve_findings


def _search_cve_by_ids(cve_ids: list[str]) -> list[dict[str, Any]]:
    """Look up specific CVE IDs in OSV to get details."""
    findings = []
    for cve_id in cve_ids[:10]:
        import httpx
        try:
            resp = httpx.get(
                f"{settings.CVE_OSV_API_URL.rstrip('/')}/v1/vulns/{cve_id}",
                timeout=10,
            )
            if resp.status_code != 200:
                continue
            vuln = resp.json()
            summary = (vuln.get("summary") or vuln.get("details") or "")[:300]
            aliases = vuln.get("aliases", [])
            real_cve = next((a for a in aliases if a.startswith("CVE-")), cve_id)
            findings.append({
                "id": real_cve,
                "summary": summary,
                "severity": _severity_from_osv(vuln),
                "aliases": aliases,
            })
        except Exception:
            continue
    return findings


def _severity_from_osv(vuln: dict) -> str:
    """Extract severity from OSV vuln entry."""
    for sev in vuln.get("severity", []):
        score = sev.get("score", "")
        if "CRITICAL" in score.upper():
            return "CRITICAL"
        if "HIGH" in score.upper():
            return "HIGH"
    db = vuln.get("database_specific", {})
    s = str(db.get("severity", "")).upper()
    if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return s
    return "HIGH"


def review_diff(diff_text: str, scanner_findings: list[object]) -> dict[str, Any]:
    client = get_openai_client()
    response = client.chat.completions.create(
        model=settings.OPENAI_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_diff_review_prompt(diff_text=diff_text, scanner_findings=scanner_findings)},
        ],
        temperature=settings.OPENAI_TEMPERATURE,
        max_tokens=settings.OPENAI_MAX_TOKENS,
    )
    content = response.choices[0].message.content or '{"findings":[]}'
    parsed = _parse_json_response(content)
    if not isinstance(parsed.get("findings"), list):
        parsed["findings"] = []

    # Auto-query OSV for CVEs on imported libraries
    if settings.CVE_ENABLE:
        try:
            cve_hits = _search_cve_for_libraries(diff_text)
            parsed["findings"].extend(cve_hits)
        except Exception:
            pass

    # Enrich LLM findings that mention CVE IDs with OSV data
    if settings.CVE_ENABLE:
        for finding in parsed["findings"]:
            title = str(finding.get("title", ""))
            cve_ids = re.findall(r"CVE-\d{4}-\d+", title)
            if cve_ids:
                try:
                    enriched = _search_cve_by_ids(cve_ids)
                    if enriched:
                        osv = enriched[0]
                        if osv.get("summary"):
                            finding["reason"] = f'{finding.get("reason", "")} [OSV: {osv["summary"]}]'
                        if osv.get("severity"):
                            finding["severity"] = osv["severity"]
                except Exception:
                    pass

    return parsed
