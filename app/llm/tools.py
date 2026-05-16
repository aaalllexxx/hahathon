from __future__ import annotations

from collections import Counter
from pathlib import PurePosixPath
import re
from typing import Any

from sqlalchemy import desc
from sqlalchemy.orm import Session, joinedload

from app.git.gitlab_client import GitLabClient, GitLabAPIError
from app.models import AuditLog, Finding, Repository, SecurityCheck
from app.scanner.cve_checker import dependency_query_from_message, query_cve_database
from app.scanner.engine import scan_diff


CWE_HELP = {
    "CWE-89": "SQL Injection: пользовательский ввод меняет структуру SQL-запроса. Фикс: параметризованные запросы.",
    "CWE-798": "Hardcoded Credentials: секрет хранится в коде. Фикс: env/secret manager и ротация секрета.",
    "CWE-79": "XSS: недоверенный ввод попадает в HTML. Фикс: escaping, textContent, безопасные шаблоны.",
    "CWE-78": "OS Command Injection: ввод попадает в shell/команду ОС. Фикс: argv-list без shell=True и allowlist.",
    "CWE-22": "Path Traversal: ввод управляет путём к файлу. Фикс: normalize/resolve + base dir allowlist.",
    "CWE-918": "SSRF: сервер ходит по URL из ввода. Фикс: allowlist hosts, запрет private/link-local сетей.",
    "CWE-502": "Insecure Deserialization: небезопасная десериализация. Фикс: safe parser/schema validation.",
}


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "cwe": finding.cwe,
        "title": finding.title,
        "severity": finding.severity,
        "file": finding.file,
        "line": finding.line,
        "code": finding.code,
        "reason": finding.reason,
        "fix": finding.fix,
        "fixed_example": finding.fixed_example,
        "llm_verdict": finding.llm_verdict,
        "llm_confidence": finding.llm_confidence,
    }


def get_stats(db: Session) -> dict[str, Any]:
    findings = db.query(Finding).all()
    checks = db.query(SecurityCheck).all()
    return {
        "checks": len(checks),
        "blocked": sum(1 for check in checks if check.status == "blocked"),
        "findings": len(findings),
        "by_severity": dict(Counter(finding.severity for finding in findings)),
        "top_cwe": dict(Counter(finding.cwe for finding in findings).most_common(8)),
    }


def list_recent_checks(db: Session, limit: int = 6) -> list[dict[str, Any]]:
    checks = (
        db.query(SecurityCheck)
        .options(joinedload(SecurityCheck.repository), joinedload(SecurityCheck.findings))
        .order_by(desc(SecurityCheck.created_at))
        .limit(limit)
        .all()
    )
    return [
        {
            "id": check.id,
            "pr_number": check.pr_number,
            "repository": check.repository.name,
            "author": check.author,
            "branch": check.branch,
            "status": check.status,
            "severity": check.severity,
            "findings": len(check.findings),
            "created_at": check.created_at.isoformat(),
        }
        for check in checks
    ]


def get_check_context(db: Session, check_id: int | None) -> dict[str, Any]:
    if check_id is None:
        latest = db.query(SecurityCheck).order_by(desc(SecurityCheck.created_at)).first()
        check_id = latest.id if latest else None
    if check_id is None:
        return {"found": False, "message": "Проверок пока нет."}

    check = (
        db.query(SecurityCheck)
        .options(joinedload(SecurityCheck.repository), joinedload(SecurityCheck.findings), joinedload(SecurityCheck.messages))
        .filter(SecurityCheck.id == check_id)
        .first()
    )
    if check is None:
        return {"found": False, "message": f"Проверка #{check_id} не найдена."}
    return {
        "found": True,
        "id": check.id,
        "pr_number": check.pr_number,
        "repository": check.repository.name,
        "branch": check.branch,
        "status": check.status,
        "severity": check.severity,
        "author": check.author,
        "commit_sha": check.commit_sha,
        "findings": [_finding_to_dict(finding) for finding in check.findings[:8]],
        "last_messages": [{"role": msg.role, "text": msg.text} for msg in check.messages[-6:]],
    }


def list_repositories(db: Session) -> list[dict[str, Any]]:
    repositories = (
        db.query(Repository)
        .options(joinedload(Repository.checks))
        .order_by(desc(Repository.created_at))
        .limit(12)
        .all()
    )
    return [
        {
            "id": repo.id,
            "name": repo.name,
            "gitlab_project_id": repo.gitlab_project_id,
            "url": repo.url,
            "checks": len(repo.checks),
        }
        for repo in repositories
    ]


def list_audit_logs(db: Session, limit: int = 12) -> list[dict[str, Any]]:
    logs = db.query(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit).all()
    return [
        {
            "level": log.level,
            "event": log.event,
            "source": log.source,
            "actor": log.actor,
            "message": log.message,
            "created_at": log.created_at.isoformat(),
        }
        for log in logs
    ]


def _latest_check(db: Session, check_id: int | None) -> SecurityCheck | None:
    if check_id is not None:
        return db.query(SecurityCheck).filter(SecurityCheck.id == check_id).first()
    return db.query(SecurityCheck).order_by(desc(SecurityCheck.created_at)).first()


def read_gitlab_file(db: Session, message: str, check_id: int | None = None) -> dict[str, Any]:
    check = _latest_check(db, check_id)
    if check is None:
        return {"ok": False, "error": "Нет проверок, из которых можно определить GitLab project id."}
    repository = db.query(Repository).filter(Repository.id == check.repository_id).first()
    if repository is None or repository.gitlab_project_id is None:
        return {"ok": False, "error": "У репозитория не указан GitLab project id."}
    path_match = re.search(r"(?:file|файл|path|путь)\s*[:=]?\s*([A-Za-z0-9_./\\-]+\.[A-Za-z0-9]+)", message, re.IGNORECASE)
    if not path_match and check.findings:
        path = check.findings[0].file
    elif path_match:
        path = path_match.group(1).replace("\\", "/")
    else:
        return {"ok": False, "error": "Не найден путь файла. Напишите, например: файл app/auth.py."}
    ref = check.branch or "main"
    try:
        content = GitLabClient().get_repository_file(repository.gitlab_project_id, path, ref=ref)
    except GitLabAPIError as exc:
        return {"ok": False, "error": str(exc), "file": path, "ref": ref}
    line_match = re.search(r"(?:строк[аи]?|line)\s*[:=]?\s*(\d+)(?:\s*[-:]\s*(\d+))?", message, re.IGNORECASE)
    lines = content.splitlines()
    start = 1
    end = min(len(lines), 160)
    if line_match:
        start = max(int(line_match.group(1)) - 20, 1)
        end = min(int(line_match.group(2) or line_match.group(1)) + 20, len(lines))
    selected = "\n".join(f"{idx + 1}: {line}" for idx, line in enumerate(lines[start - 1:end], start - 1))
    return {"ok": True, "file": path, "ref": ref, "start": start, "end": end, "content": selected[:12000]}


def search_gitlab_regex(db: Session, message: str, check_id: int | None = None) -> dict[str, Any]:
    check = _latest_check(db, check_id)
    if check is None:
        return {"ok": False, "error": "Нет проверок для выбора репозитория."}
    repository = db.query(Repository).filter(Repository.id == check.repository_id).first()
    if repository is None or repository.gitlab_project_id is None:
        return {"ok": False, "error": "У репозитория не указан GitLab project id."}
    pattern_match = re.search(r"(?:regex|регулярк[ае]|поиск)\s*[:=]?\s*`?([^`\n]+)`?", message, re.IGNORECASE)
    if not pattern_match:
        return {"ok": False, "error": "Не найдена регулярка. Напишите: regex: os\\.system|subprocess"}
    pattern = pattern_match.group(1).strip()
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return {"ok": False, "error": f"Некорректная регулярка: {exc}", "pattern": pattern}
    client = GitLabClient()
    ref = check.branch or "main"
    try:
        tree = client.list_repository_tree(repository.gitlab_project_id, ref=ref, recursive=True)
    except GitLabAPIError as exc:
        return {"ok": False, "error": str(exc)}
    allowed_suffixes = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".php", ".rb", ".cs", ".sql", ".yml", ".yaml", ".json", ".toml"}
    matches: list[dict[str, Any]] = []
    scanned = 0
    for item in tree:
        if item.get("type") != "blob":
            continue
        path = str(item.get("path") or "")
        if PurePosixPath(path).suffix.lower() not in allowed_suffixes:
            continue
        scanned += 1
        if scanned > 40:
            break
        try:
            content = client.get_repository_file(repository.gitlab_project_id, path, ref=ref)
        except GitLabAPIError:
            continue
        for idx, line in enumerate(content.splitlines(), 1):
            if compiled.search(line):
                matches.append({"file": path, "line": idx, "code": line.strip()[:300]})
                if len(matches) >= 20:
                    return {"ok": True, "pattern": pattern, "scanned_files": scanned, "matches": matches}
    return {"ok": True, "pattern": pattern, "scanned_files": scanned, "matches": matches}


def query_cve_tool(message: str) -> dict[str, Any]:
    parsed = dependency_query_from_message(message)
    if not parsed:
        return {"ok": False, "error": "Укажите зависимость в формате package==version или package@version."}
    package, version, ecosystem = parsed
    return query_cve_database(package, version, ecosystem)


def explain_cwe(message: str) -> dict[str, Any]:
    found = [code for code in CWE_HELP if code.lower() in message.lower()]
    if not found:
        found = list(CWE_HELP)
    return {"items": {code: CWE_HELP[code] for code in found[:6]}}


def scan_code_snippet(message: str) -> dict[str, Any]:
    lines = message.splitlines()
    code_lines = [line for line in lines if any(marker in line for marker in ("=", "(", ")", "{", "}", ";", "SELECT", "request.", "req."))]
    if not code_lines:
        return {"scanned": False, "message": "В вопросе нет явного фрагмента кода."}
    diff = "diff --git a/chat-snippet.py b/chat-snippet.py\n--- a/chat-snippet.py\n+++ b/chat-snippet.py\n@@ -0,0 +1,%d @@\n%s\n" % (
        len(code_lines),
        "\n".join(f"+{line}" for line in code_lines[:80]),
    )
    result = scan_diff(diff, use_llm=True)
    findings = sorted(result.findings, key=lambda finding: finding.cwe == "AI-REVIEW")
    return {
        "scanned": True,
        "status": result.status,
        "severity": result.severity,
        "findings": [finding.to_dict() for finding in findings[:6]],
    }


def gitlab_setup_guide() -> dict[str, Any]:
    return {
        "steps": [
            "В GitLab проекте открыть Settings -> Webhooks.",
            "URL: http://codeguardian:8000/webhooks/gitlab.",
            "Secret token должен совпадать с GITLAB_WEBHOOK_SECRET.",
            "Включить Push events и Merge request events.",
            "В Admin Area -> Settings -> Network разрешить local network outbound requests.",
            "Нажать Test -> Push events и проверить POST /webhooks/gitlab в логах CodeGuardian.",
        ]
    }


def integrity_status(db: Session) -> dict[str, Any]:
    return {
        "mode": "MVP",
        "status": "audit-only",
        "repositories": db.query(Repository).count(),
        "description": "Контроль целостности представлен audit trail и commit_sha в SecurityCheck. Baseline hashes можно добавить следующим этапом.",
    }


def monitoring_status(db: Session) -> dict[str, Any]:
    latest_log = db.query(AuditLog).order_by(desc(AuditLog.created_at)).first()
    return {
        "api": "ok",
        "database": "ok",
        "latest_event": latest_log.event if latest_log else None,
        "latest_event_at": latest_log.created_at.isoformat() if latest_log else None,
    }


def extract_check_id_from_message(message: str) -> int | None:
    """Extract check/чек ID from user message like 'чек #8', 'check 8', 'проверка #8'."""
    m = re.search(r"(?:чек[еа]?|check|проверк[аеи]|#)\s*#?\s*(\d+)", message, re.IGNORECASE)
    return int(m.group(1)) if m else None


def select_tools(message: str) -> list[str]:
    lowered = message.lower()
    tools = ["get_stats"]
    # Always include check context if user mentions a check ID
    has_check_ref = bool(re.search(r"(?:чек|check|проверк|#)\s*#?\s*\d+", lowered))
    if has_check_ref or any(word in lowered for word in ("провер", "pr", "merge", "блок", "finding", "уязв", "что было", "покажи чек", "детали")):
        tools.append("get_check_context")
        tools.append("list_recent_checks")
    if any(word in lowered for word in ("лог", "pipeline", "цепоч", "webhook", "ошиб")):
        tools.append("list_audit_logs")
    if any(word in lowered for word in ("репоз", "project id", "проект", "ветк")):
        tools.append("list_repositories")
    if "cwe" in lowered:
        tools.append("explain_cwe")
    if any(word in lowered for word in ("код", "query", "select", "request.", "req.", "subprocess", "innerhtml", "token")):
        tools.append("scan_code_snippet")
    if dependency_query_from_message(message) or any(word in lowered for word in ("cve", "osv", "уязвимост", "зависим", "dependency", "package", "pip", "npm")):
        tools.append("query_cve_database")
    if any(word in lowered for word in ("прочитай", "покажи файл", "файл ", "file ", "path ", "целиком", "частично")):
        tools.append("read_gitlab_file")
    if any(word in lowered for word in ("regex", "регуляр", "поиск", "найди в файлах", "grep")):
        tools.append("search_gitlab_regex")
    if any(word in lowered for word in ("gitlab", "вебхук", "webhook", "настро")):
        tools.append("gitlab_setup_guide")
    if any(word in lowered for word in ("целост", "integrity")):
        tools.append("integrity_status")
    if any(word in lowered for word in ("монитор", "health", "статус")):
        tools.append("monitoring_status")
    return list(dict.fromkeys(tools))


def _log_tool_call(db: Session, name: str, message: str) -> None:
    db.add(
        AuditLog(
            level="INFO",
            event="ai.tool.called",
            actor="AI Assistant",
            source=f"tool:{name}",
            message=f"Tool {name} вызван для запроса: {message[:180]}",
        )
    )


def run_tools(db: Session, message: str, check_id: int | None = None) -> dict[str, Any]:
    # Auto-detect check_id from message if not provided
    if check_id is None:
        check_id = extract_check_id_from_message(message)
    selected = select_tools(message)
    outputs: dict[str, Any] = {}
    for name in selected:
        _log_tool_call(db, name, message)
        if name == "get_stats":
            outputs[name] = get_stats(db)
        elif name == "get_check_context":
            outputs[name] = get_check_context(db, check_id)
        elif name == "list_recent_checks":
            outputs[name] = list_recent_checks(db)
        elif name == "list_audit_logs":
            outputs[name] = list_audit_logs(db)
        elif name == "list_repositories":
            outputs[name] = list_repositories(db)
        elif name == "explain_cwe":
            outputs[name] = explain_cwe(message)
        elif name == "scan_code_snippet":
            outputs[name] = scan_code_snippet(message)
        elif name == "query_cve_database":
            outputs[name] = query_cve_tool(message)
        elif name == "read_gitlab_file":
            outputs[name] = read_gitlab_file(db, message, check_id)
        elif name == "search_gitlab_regex":
            outputs[name] = search_gitlab_regex(db, message, check_id)
        elif name == "gitlab_setup_guide":
            outputs[name] = gitlab_setup_guide()
        elif name == "integrity_status":
            outputs[name] = integrity_status(db)
        elif name == "monitoring_status":
            outputs[name] = monitoring_status(db)
    return {"tools_used": selected, "outputs": outputs}
