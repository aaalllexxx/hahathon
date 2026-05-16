from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import desc, func
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.database import get_db
from app.models import AppSetting, AuditLog, BotMessage, Finding, Repository, SecurityCheck
from app.llm.chat import ask_assistant
from app.schemas import AuditLogOut, ChatIn, ChatOut, CheckCommentIn, SecurityCheckOut

router = APIRouter(tags=["dashboard"])
TEMPLATE_PATH = Path("app/dashboard/templates/dashboard.html")


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    html = TEMPLATE_PATH.read_text(encoding="utf-8").replace("{{ title }}", settings.DASHBOARD_TITLE)
    return HTMLResponse(html)


def _week_labels() -> list[str]:
    return ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]


def _status_to_ui(status: str) -> str:
    return "active" if status in {"passed", "warning", "blocked"} else "error"


def _provider_from_url(url: str | None) -> str:
    if not url:
        return "GitLab"
    lowered = url.lower()
    if "github" in lowered:
        return "GitHub"
    if "gitlab" in lowered:
        return "GitLab"
    return "Git"


SETTING_KEYS = {
    "OPENAI_BASE_URL": str,
    "OPENAI_API_KEY": str,
    "OPENAI_MODEL": str,
    "OPENAI_TIMEOUT": float,
    "OPENAI_TEMPERATURE": float,
    "OPENAI_MAX_TOKENS": int,
    "SECURITY_BLOCK_ON_CRITICAL": bool,
    "SECURITY_BLOCK_ON_HIGH": bool,
    "SECURITY_BLOCK_ON_WARNING": bool,
    "SECURITY_USE_LLM": bool,
    "SECURITY_REQUIRE_LLM_REVIEW": bool,
    "SECURITY_FAIL_CLOSED_ON_LLM_ERROR": bool,
    "SECURITY_MAX_DIFF_CHARS": int,
    "SECURITY_BLOCK_MERGE_REQUESTS": bool,
    "SECURITY_BLOCK_CLOSE_MR": bool,
    "SECURITY_BLOCK_INLINE_COMMENTS": bool,
    "SECURITY_BLOCK_PUSHES": bool,
    "SECURITY_BLOCK_PRE_RECEIVE": bool,
    "SECURITY_PRECHECK_PUBLIC": bool,
    "CVE_ENABLE": bool,
    "CVE_OSV_API_URL": str,
    "CVE_TIMEOUT": float,
    "CVE_MAX_DEPENDENCIES": int,
}


def _coerce_setting(value: object, kind: object) -> object:
    if kind is bool:
        if isinstance(value, bool):
            return value
        return str(value).lower() in {"1", "true", "yes", "on"}
    if kind is int:
        return int(value)
    if kind is float:
        return float(value)
    return str(value)


def _public_settings() -> dict[str, object]:
    values = {key: getattr(settings, key) for key in SETTING_KEYS}
    if values.get("OPENAI_API_KEY"):
        values["OPENAI_API_KEY"] = "********"
    return values


def _masked_stored_settings(db: Session) -> dict[str, str]:
    stored: dict[str, str] = {}
    for item in db.query(AppSetting).all():
        stored[item.key] = "********" if item.key == "OPENAI_API_KEY" and item.value else item.value
    return stored


def apply_stored_settings(db: Session) -> None:
    for item in db.query(AppSetting).all():
        kind = SETTING_KEYS.get(item.key)
        if kind is None:
            continue
        setattr(settings, item.key, _coerce_setting(item.value, kind))


@router.get("/api/checks", response_model=list[SecurityCheckOut])
def list_checks(
    db: Session = Depends(get_db),
    severity: str | None = None,
    status_filter: str | None = None,
    repository_id: int | None = None,
    q: str | None = None,
) -> list[SecurityCheck]:
    query = (
        db.query(SecurityCheck)
        .options(joinedload(SecurityCheck.repository), joinedload(SecurityCheck.findings), joinedload(SecurityCheck.messages))
        .order_by(desc(SecurityCheck.created_at))
    )
    if severity and severity.lower() != "all":
        query = query.filter(SecurityCheck.severity == severity.upper())
    if status_filter and status_filter.lower() != "all":
        query = query.filter(SecurityCheck.status == status_filter.lower())
    if repository_id:
        query = query.filter(SecurityCheck.repository_id == repository_id)
    if q:
        pattern = f"%{q.strip()}%"
        query = query.join(SecurityCheck.repository).filter(
            (Repository.name.ilike(pattern))
            | (SecurityCheck.author.ilike(pattern))
            | (SecurityCheck.branch.ilike(pattern))
        )
    return query.limit(50).all()


@router.get("/api/checks/{check_id}", response_model=SecurityCheckOut)
def get_check(check_id: int, db: Session = Depends(get_db)) -> SecurityCheck:
    check = (
        db.query(SecurityCheck)
        .options(joinedload(SecurityCheck.repository), joinedload(SecurityCheck.findings), joinedload(SecurityCheck.messages))
        .filter(SecurityCheck.id == check_id)
        .first()
    )
    if check is None:
        raise HTTPException(status_code=404, detail="Check not found")
    return check


@router.get("/api/stats")
def get_stats(period: str = "week", db: Session = Depends(get_db)) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    period_days = {"week": 7, "month": 30, "year": 365}.get(period, 7)
    week_ago = now - timedelta(days=period_days)
    checks_count = db.query(SecurityCheck).count()
    findings = db.query(Finding).all()
    blocked_count = db.query(SecurityCheck).filter(SecurityCheck.status == "blocked").count()
    critical_count = sum(1 for finding in findings if finding.severity == "CRITICAL")
    top = Counter(finding.title for finding in findings)
    active_checks = db.query(SecurityCheck).filter(SecurityCheck.created_at >= week_ago).count()
    needs_attention = db.query(SecurityCheck).filter(SecurityCheck.status.in_(["blocked", "warning"])).count()
    repositories_count = db.query(Repository).count()
    protected_branches = db.query(Repository).count()
    running_scans = db.query(SecurityCheck).filter(SecurityCheck.status == "running").count()

    num_points = min(period_days, 30) if period_days <= 30 else 12
    bucket_size = max(period_days // num_points, 1)
    dates = [(now - timedelta(days=(num_points - 1 - idx) * bucket_size)).date() for idx in range(num_points)]
    finding_by_date: dict[object, int] = defaultdict(int)
    check_by_date: dict[object, int] = defaultdict(int)
    recent_checks = db.query(SecurityCheck).options(joinedload(SecurityCheck.findings)).filter(SecurityCheck.created_at >= now - timedelta(days=period_days)).all()
    for check in recent_checks:
        date_key = check.created_at.date()
        # bucket into nearest date point
        best = min(dates, key=lambda d: abs((d - date_key).days))
        check_by_date[best] += 1
        finding_by_date[best] += len(check.findings)

    if period_days <= 7:
        labels = [d.strftime("%a") for d in dates]
    elif period_days <= 30:
        labels = [d.strftime("%d.%m") for d in dates]
    else:
        labels = [d.strftime("%b") for d in dates]

    top_vulnerabilities = [
        {"name": name, "count": count}
        for name, count in top.most_common(5)
    ]
    return {
        "kpi": {
            "checks": checks_count,
            "vulnerabilities": len(findings),
            "critical": critical_count,
            "blocked": blocked_count,
        },
        "checks_kpi": {
            "active": active_checks,
            "blocked": blocked_count,
            "attention": needs_attention,
            "avg_time": "—",
        },
        "repositories_kpi": {
            "connected": repositories_count,
            "webhooks": repositories_count,
            "running": running_scans,
            "protected": protected_branches,
        },
        "logs_kpi": {
            "session_logs": db.query(AuditLog).count(),
            "steps": 0 if checks_count == 0 else 9,
            "findings": len(findings),
            "analysis_time": "—",
        },
        "trend": {
            "labels": labels,
            "values": [finding_by_date[date] for date in dates],
        },
        "check_activity": {
            "labels": labels,
            "values": [check_by_date[date] for date in dates],
        },
        "top_vulnerabilities": top_vulnerabilities,
    }


@router.post("/api/checks/{check_id}/override", response_model=SecurityCheckOut)
def override_check(check_id: int, body: dict[str, object] = Body(default={}), db: Session = Depends(get_db)) -> SecurityCheck:
    check = (
        db.query(SecurityCheck)
        .options(joinedload(SecurityCheck.repository), joinedload(SecurityCheck.findings), joinedload(SecurityCheck.messages))
        .filter(SecurityCheck.id == check_id)
        .first()
    )
    if check is None:
        raise HTTPException(status_code=404, detail="Check not found")
    reason = str(body.get("reason") or "").strip() or "manual override"
    actor = str(body.get("actor") or "dashboard-user")
    prev = check.enforcement or "?"
    check.status = "warning" if check.findings else "passed"
    check.enforcement = "override"
    db.add(BotMessage(check_id=check.id, role="bot", text=f"⚠ Блок снят вручную ({actor}). Причина: {reason}"))
    db.add(
        AuditLog(
            level="WARNING",
            event="security_check.override",
            actor=actor,
            source="dashboard",
            message=f"Override blocked check #{check.id} (was {prev}): {reason}",
        )
    )
    db.commit()
    db.refresh(check)
    return check


@router.post("/api/checks/{check_id}/rerun", response_model=SecurityCheckOut)
def rerun_check(check_id: int, db: Session = Depends(get_db)) -> SecurityCheck:
    check = (
        db.query(SecurityCheck)
        .options(joinedload(SecurityCheck.repository), joinedload(SecurityCheck.findings), joinedload(SecurityCheck.messages))
        .filter(SecurityCheck.id == check_id)
        .first()
    )
    if check is None:
        raise HTTPException(status_code=404, detail="Check not found")
    db.add(
        BotMessage(
            check_id=check.id,
            role="bot",
            text="Перепроверка поставлена в очередь. Для локального MVP повторный запуск фиксируется в журнале, а новые webhook-события создают отдельные проверки.",
        )
    )
    db.add(
        AuditLog(
            level="INFO",
            event="security_check.rerun",
            actor="dashboard-user",
            source="dashboard",
            message=f"Manual rerun requested for check #{check.id}",
        )
    )
    db.commit()
    db.refresh(check)
    return check


@router.post("/api/checks/{check_id}/comment", response_model=SecurityCheckOut)
def add_comment(check_id: int, body: CheckCommentIn, db: Session = Depends(get_db)) -> SecurityCheck:
    check = (
        db.query(SecurityCheck)
        .options(joinedload(SecurityCheck.repository), joinedload(SecurityCheck.findings), joinedload(SecurityCheck.messages))
        .filter(SecurityCheck.id == check_id)
        .first()
    )
    if check is None:
        raise HTTPException(status_code=404, detail="Check not found")

    db.add(BotMessage(check_id=check.id, role="user", text=body.text))
    answer = ask_assistant(db, body.text, check_id=check.id)
    db.add(
        BotMessage(
            check_id=check.id,
            role="bot",
            text=answer["answer"],
        )
    )
    db.add(
        AuditLog(
            level="INFO",
            event="bot.comment.created",
            actor="dashboard-user",
            source="dashboard",
            message=f"Comment added to check #{check.id}",
        )
    )
    db.commit()
    db.refresh(check)
    return check


@router.post("/api/chat", response_model=ChatOut)
def chat(body: ChatIn, db: Session = Depends(get_db)) -> dict[str, object]:
    answer = ask_assistant(db, body.message, check_id=body.check_id)
    db.add(
        AuditLog(
            level="INFO" if not answer["degraded"] else "WARNING",
            event="ai.chat.completed",
            actor="dashboard-user",
            source="AI Assistant",
            message=f"AI chat answered with tools: {', '.join(answer['tools_used'])}",
        )
    )
    db.commit()
    return answer


@router.post("/api/chat/stream")
def chat_stream(body: ChatIn, db: Session = Depends(get_db)):
    """SSE streaming endpoint for AI chat."""
    from starlette.responses import StreamingResponse
    from app.llm.chat import stream_assistant

    tool_context, gen = stream_assistant(db, body.message, check_id=body.check_id)

    def event_stream():
        try:
            for chunk in gen:
                # SSE format — plain text chunks, no JSON wrapper
                safe = chunk.replace('\n', '\ndata: ')
                yield f"data: {safe}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as exc:
            yield f"data: [ERR]{exc}\n\n"
        finally:
            db.add(
                AuditLog(
                    level="INFO",
                    event="ai.chat.stream.completed",
                    actor="dashboard-user",
                    source="AI Assistant",
                    message=f"Streamed chat with tools: {', '.join(tool_context['tools_used'])}",
                )
            )
            db.commit()

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.get("/api/logs", response_model=list[AuditLogOut])
def list_logs(
    db: Session = Depends(get_db),
    level: str | None = None,
    q: str | None = None,
) -> list[AuditLog]:
    query = db.query(AuditLog).order_by(desc(AuditLog.created_at))
    if level and level.lower() != "all":
        query = query.filter(AuditLog.level == level.upper())
    if q:
        pattern = f"%{q.strip()}%"
        query = query.filter(
            (AuditLog.event.ilike(pattern))
            | (AuditLog.source.ilike(pattern))
            | (AuditLog.message.ilike(pattern))
            | (AuditLog.actor.ilike(pattern))
        )
    return query.limit(200).all()


@router.get("/api/repositories")
def list_repositories(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    repositories = (
        db.query(Repository)
        .options(joinedload(Repository.checks).joinedload(SecurityCheck.findings))
        .order_by(desc(Repository.created_at))
        .all()
    )
    result: list[dict[str, object]] = []
    for repository in repositories:
        checks = sorted(repository.checks, key=lambda check: check.created_at, reverse=True)
        last_check = checks[0] if checks else None
        findings = [finding for check in checks for finding in check.findings]
        counts = Counter(finding.severity for finding in findings)
        activity_counter = Counter(check.created_at.weekday() for check in checks)
        result.append(
            {
                "id": repository.id,
                "name": repository.name,
                "provider": _provider_from_url(repository.url),
                "branch": last_check.branch if last_check and last_check.branch else "main",
                "url": repository.url,
                "status": _status_to_ui(last_check.status) if last_check else "active",
                "webhook": "online" if checks else "not_configured",
                "merge_protection": bool(checks),
                "last_check": last_check.created_at.isoformat() if last_check else None,
                "checks_count": len(checks),
                "findings_count": len(findings),
                "blocked_count": sum(1 for check in checks if check.status == "blocked"),
                "severity_summary": {
                    "high": counts["CRITICAL"] + counts["HIGH"],
                    "medium": counts["MEDIUM"],
                    "low": counts["LOW"],
                    "info": max(len(checks) - len(findings), 0),
                },
                "activity": {
                    "labels": _week_labels(),
                    "values": [activity_counter[idx] for idx in range(7)],
                },
                "recent_checks": [
                    {
                        "id": check.id,
                        "pr_number": check.pr_number,
                        "title": f"PR #{check.pr_number or check.id}",
                        "branch": check.branch,
                        "created_at": check.created_at.isoformat(),
                        "severity": check.severity,
                        "status": check.status,
                    }
                    for check in checks[:5]
                ],
            }
        )
    return result


@router.post("/api/repositories")
def create_repository(
    payload: dict[str, object] = Body(...),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    name = str(payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=422, detail="Repository name is required")
    repository = Repository(
        name=name,
        gitlab_project_id=int(payload["gitlab_project_id"]) if payload.get("gitlab_project_id") else None,
        url=str(payload.get("url") or ""),
    )
    db.add(repository)
    db.add(
        AuditLog(
            level="INFO",
            event="repository.connected",
            actor="dashboard-user",
            source="dashboard",
            message=f"Repository {name} connected to CodeGuardian AI",
        )
    )
    db.commit()
    db.refresh(repository)
    return {"id": repository.id, "name": repository.name, "url": repository.url}


@router.delete("/api/repositories/{repo_id}")
def delete_repository(repo_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    repo = db.query(Repository).filter(Repository.id == repo_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    name = repo.name
    # Delete related checks, findings, messages
    for check in repo.checks:
        db.query(Finding).filter(Finding.check_id == check.id).delete()
        from app.models import BotMessage
        db.query(BotMessage).filter(BotMessage.check_id == check.id).delete()
        db.delete(check)
    db.delete(repo)
    db.add(
        AuditLog(
            level="WARNING",
            event="repository.deleted",
            actor="dashboard-user",
            source="dashboard",
            message=f"Repository {name} deleted from CodeGuardian AI",
        )
    )
    db.commit()
    return {"ok": True, "deleted": name}


@router.get("/api/settings")
def get_app_settings(db: Session = Depends(get_db)) -> dict[str, object]:
    return {"values": _public_settings(), "stored": _masked_stored_settings(db)}


@router.post("/api/settings")
def update_app_settings(payload: dict[str, object] = Body(...), db: Session = Depends(get_db)) -> dict[str, object]:
    changed: list[str] = []
    for key, value in payload.items():
        if key not in SETTING_KEYS:
            continue
        if key == "OPENAI_API_KEY" and str(value).strip() in {"", "********"}:
            continue
        coerced = _coerce_setting(value, SETTING_KEYS[key])
        setattr(settings, key, coerced)
        setting = db.query(AppSetting).filter(AppSetting.key == key).first()
        if setting is None:
            setting = AppSetting(key=key, value=str(coerced))
            db.add(setting)
        else:
            setting.value = str(coerced)
        changed.append(key)
    db.add(
        AuditLog(
            level="INFO",
            event="settings.updated",
            actor="dashboard-user",
            source="settings",
            message=f"Updated settings: {', '.join(changed) if changed else 'none'}",
        )
    )
    db.commit()
    return {"ok": True, "changed": changed, "values": _public_settings()}


@router.get("/api/ui")
def get_ui_config(db: Session = Depends(get_db)) -> dict[str, object]:
    blocked = db.query(SecurityCheck).filter(SecurityCheck.status == "blocked").count()
    warnings = db.query(SecurityCheck).filter(SecurityCheck.status == "warning").count()
    blocked_by_origin = {
        (row[0] or "webhook"): row[1]
        for row in db.query(SecurityCheck.origin, func.count(SecurityCheck.id))
        .filter(SecurityCheck.status == "blocked")
        .group_by(SecurityCheck.origin)
        .all()
    }
    return {
        "app": {
            "title": settings.DASHBOARD_TITLE,
            "environment": settings.APP_ENV,
            "version": "2.0",
        },
        "user": {
            "name": "Алексей",
            "initials": "A",
            "role": "DevSecOps",
        },
        "i18n": {
            "all_repositories": "Все репозитории",
            "no_data": "Нет данных",
            "shown_of": "Показано {shown} из {total}",
            "loading": "Загрузка…",
            "no_changes": "Нет изменений",
            "search_placeholder": "Поиск…",
            "command_palette_hint": "Ctrl+K — поиск по системе",
            "copy": "Копировать",
            "copied": "Скопировано",
            "rerun": "Перепроверить",
            "override": "Снять блок",
            "blocked_at": "Заблокировано на",
            "open_in_gitlab": "Открыть в GitLab",
            "view_diff": "Diff",
            "no_findings": "Без находок",
            "connect_repository": "Подключить репозиторий",
            "save": "Сохранить",
            "refresh": "Обновить",
            "more": "Ещё",
        },
        "theme": {
            "default": "dark",
            "palette": {
                "blue": "#2f81f7",
                "cyan": "#3fbce7",
                "green": "#3fb950",
                "amber": "#f59e42",
                "red": "#f85149",
                "purple": "#a371f7",
            },
            "severity_palette": {
                "CRITICAL": {"label": "Critical", "color": "#f85149", "bg": "rgba(248,81,73,.15)"},
                "HIGH": {"label": "High", "color": "#f59e42", "bg": "rgba(245,158,66,.15)"},
                "MEDIUM": {"label": "Medium", "color": "#f1c40f", "bg": "rgba(241,196,15,.15)"},
                "LOW": {"label": "Low", "color": "#3fb950", "bg": "rgba(63,185,80,.15)"},
            },
            "status_palette": {
                "blocked": {"label": "Заблокирован", "color": "#f85149", "icon": "fa-solid fa-lock"},
                "warning": {"label": "Предупреждение", "color": "#f59e42", "icon": "fa-solid fa-triangle-exclamation"},
                "passed": {"label": "Пройден", "color": "#3fb950", "icon": "fa-solid fa-circle-check"},
                "failed": {"label": "Ошибка", "color": "#f85149", "icon": "fa-solid fa-circle-xmark"},
                "running": {"label": "На проверке", "color": "#3fbce7", "icon": "fa-solid fa-spinner"},
            },
            "level_palette": {
                "INFO": {"label": "Info", "status": "OK", "color": "#3fbce7"},
                "WARNING": {"label": "Warning", "status": "FLAGGED", "color": "#f59e42"},
                "ERROR": {"label": "Error", "status": "BLOCKED", "color": "#f85149"},
                "ALERT": {"label": "Alert", "status": "CONFIRMED", "color": "#a371f7"},
                "SUCCESS": {"label": "Success", "status": "POSTED", "color": "#3fb950"},
            },
            "origin_palette": {
                "pre-push": {"label": "Pre-push", "icon": "fa-solid fa-laptop-code", "color": "#3fbce7"},
                "pre-receive": {"label": "Pre-receive", "icon": "fa-solid fa-server", "color": "#a371f7"},
                "mr-webhook": {"label": "MR webhook", "icon": "fa-solid fa-code-pull-request", "color": "#2f81f7"},
                "push-webhook": {"label": "Push webhook", "icon": "fa-solid fa-cloud-arrow-up", "color": "#2f81f7"},
                "ci": {"label": "CI", "icon": "fa-solid fa-gears", "color": "#f59e42"},
                "manual": {"label": "Ручная", "icon": "fa-regular fa-hand", "color": "#8b949e"},
                "webhook": {"label": "Webhook", "icon": "fa-solid fa-bolt", "color": "#2f81f7"},
            },
            "provider_icons": {
                "GitHub": "fa-brands fa-github",
                "GitLab": "fa-brands fa-gitlab",
                "Git": "fa-solid fa-code-branch",
            },
        },
        "navigation": [
            {"view": "dashboard", "label": "Дашборд", "icon": "fa-solid fa-house"},
            {"view": "checks", "label": "Проверки PR", "icon": "fa-solid fa-code-pull-request"},
            {"view": "gate", "label": "Блокировки", "icon": "fa-solid fa-shield-halved", "badge_key": "blocked"},
            {"view": "repositories", "label": "Репозитории", "icon": "fa-regular fa-folder"},
            {"view": "logs", "label": "Логи", "icon": "fa-regular fa-rectangle-list"},
            {"view": "settings", "label": "Настройки", "icon": "fa-solid fa-gear"},
        ],
        "kpi_specs": {
            "dashboard": [
                {"key": "checks", "label": "Проверок PR", "hint": "Всего проверок", "icon": "fa-solid fa-shield", "tone": "blue", "path": "kpi.checks"},
                {"key": "vulnerabilities", "label": "Уязвимостей", "hint": "По всем репозиториям", "icon": "fa-solid fa-magnifying-glass-chart", "tone": "amber", "path": "kpi.vulnerabilities"},
                {"key": "critical", "label": "Критичных", "hint": "CRITICAL findings", "icon": "fa-solid fa-triangle-exclamation", "tone": "red", "path": "kpi.critical"},
                {"key": "blocked", "label": "Заблокировано PR", "hint": "Policy Engine", "icon": "fa-solid fa-lock", "tone": "purple", "path": "kpi.blocked"},
            ],
            "checks": [
                {"key": "active", "label": "Активных", "hint": "За 7 дней", "icon": "fa-solid fa-shield-check", "tone": "blue", "path": "checks_kpi.active"},
                {"key": "blocked", "label": "Заблокировано", "hint": "Policy Engine", "icon": "fa-solid fa-lock", "tone": "red", "path": "checks_kpi.blocked"},
                {"key": "attention", "label": "Требуют внимания", "hint": "Blocked + Warning", "icon": "fa-solid fa-triangle-exclamation", "tone": "amber", "path": "checks_kpi.attention"},
                {"key": "avg_time", "label": "Среднее время", "hint": "Scanner + LLM", "icon": "fa-regular fa-clock", "tone": "purple", "path": "checks_kpi.avg_time"},
            ],
            "repositories": [
                {"key": "connected", "label": "Подключено", "hint": "Активные интеграции", "icon": "fa-solid fa-layer-group", "tone": "blue", "path": "repositories_kpi.connected"},
                {"key": "webhooks", "label": "Webhook", "hint": "GitLab/GitHub callbacks", "icon": "fa-solid fa-code-branch", "tone": "purple", "path": "repositories_kpi.webhooks"},
                {"key": "running", "label": "Сканируется", "hint": "Очередь анализа", "icon": "fa-solid fa-wave-square", "tone": "amber", "path": "repositories_kpi.running"},
                {"key": "protected", "label": "Защищённых веток", "hint": "Merge protection", "icon": "fa-solid fa-lock", "tone": "green", "path": "repositories_kpi.protected"},
            ],
            "logs": [
                {"key": "session_logs", "label": "Логов", "hint": "Audit Logger", "icon": "fa-regular fa-clipboard", "tone": "blue", "path": "logs_kpi.session_logs"},
                {"key": "steps", "label": "Шагов анализа", "hint": "Pipeline detection", "icon": "fa-solid fa-diagram-project", "tone": "amber", "path": "logs_kpi.steps"},
                {"key": "findings", "label": "Уязвимостей", "hint": "Critical + warnings", "icon": "fa-solid fa-shield-virus", "tone": "red", "path": "logs_kpi.findings"},
                {"key": "analysis_time", "label": "Время", "hint": "Общее время", "icon": "fa-regular fa-clock", "tone": "green", "path": "logs_kpi.analysis_time"},
            ],
            "gate": [
                {"key": "pre_push", "label": "Pre-push", "hint": "Warn-only по умолчанию", "icon": "fa-solid fa-laptop-code", "tone": "blue", "value": blocked_by_origin.get("pre-push", 0)},
                {"key": "pre_receive", "label": "Pre-receive", "hint": "Отключён для веток", "icon": "fa-solid fa-server", "tone": "purple", "value": blocked_by_origin.get("pre-receive", 0)},
                {"key": "mr", "label": "MR webhook", "hint": "Закрыто авто", "icon": "fa-solid fa-code-pull-request", "tone": "amber", "value": blocked_by_origin.get("mr-webhook", 0)},
                {"key": "ci", "label": "CI", "hint": "Завалено пайплайнов", "icon": "fa-solid fa-gears", "tone": "red", "value": blocked_by_origin.get("ci", 0)},
            ],
        },
        "segmented_periods": [
            {"value": "week", "label": "Неделя"},
            {"value": "month", "label": "Месяц"},
        ],
        "settings_schema": [
            {"section": "LLM / DeepSeek", "icon": "fa-solid fa-brain", "fields": [
                {"name": "OPENAI_BASE_URL", "label": "Base URL", "type": "text", "placeholder": "https://api.deepseek.com/v1"},
                {"name": "OPENAI_API_KEY", "label": "API key", "type": "password", "placeholder": "********"},
                {"name": "OPENAI_MODEL", "label": "Model", "type": "text", "placeholder": "deepseek-v4"},
                {"name": "OPENAI_TIMEOUT", "label": "Timeout, s", "type": "number", "min": 1, "step": 1},
                {"name": "OPENAI_MAX_TOKENS", "label": "Max tokens", "type": "number", "min": 128, "step": 64},
                {"name": "OPENAI_TEMPERATURE", "label": "Temperature", "type": "number", "min": 0, "max": 1, "step": 0.05},
            ]},
            {"section": "Security policy", "icon": "fa-solid fa-shield-halved", "fields": [
                {"name": "SECURITY_USE_LLM", "label": "Использовать LLM", "type": "checkbox"},
                {"name": "SECURITY_REQUIRE_LLM_REVIEW", "label": "Все diff обязательно проверяет LLM", "type": "checkbox"},
                {"name": "SECURITY_FAIL_CLOSED_ON_LLM_ERROR", "label": "Fail closed при ошибке LLM", "type": "checkbox"},
                {"name": "SECURITY_BLOCK_ON_CRITICAL", "label": "Блокировать Critical", "type": "checkbox"},
                {"name": "SECURITY_BLOCK_ON_HIGH", "label": "Блокировать High", "type": "checkbox"},
                {"name": "SECURITY_BLOCK_ON_WARNING", "label": "Блокировать любые warning", "type": "checkbox"},
                {"name": "SECURITY_MAX_DIFF_CHARS", "label": "Max diff chars", "type": "number", "min": 1000, "step": 1000},
            ]},
            {"section": "GitLab enforcement", "icon": "fa-brands fa-gitlab", "fields": [
                {"name": "SECURITY_BLOCK_MERGE_REQUESTS", "label": "Блокировать Merge Request", "type": "checkbox"},
                {"name": "SECURITY_BLOCK_CLOSE_MR", "label": "Закрывать MR при блокировке", "type": "checkbox"},
                {"name": "SECURITY_BLOCK_INLINE_COMMENTS", "label": "Писать inline-комментарии у строк", "type": "checkbox"},
                {"name": "SECURITY_BLOCK_PUSHES", "label": "Блокировать push в ветки", "type": "checkbox"},
                {"name": "SECURITY_BLOCK_PRE_RECEIVE", "label": "Включить server-side pre-receive block", "type": "checkbox"},
                {"name": "SECURITY_PRECHECK_PUBLIC", "label": "Разрешить precheck без токена", "type": "checkbox"},
            ]},
            {"section": "CVE / OSV", "icon": "fa-solid fa-bug", "fields": [
                {"name": "CVE_ENABLE", "label": "Включить CVE lookup", "type": "checkbox"},
                {"name": "CVE_OSV_API_URL", "label": "OSV API URL", "type": "text", "placeholder": "https://api.osv.dev"},
                {"name": "CVE_TIMEOUT", "label": "Timeout, s", "type": "number", "min": 1, "step": 1},
                {"name": "CVE_MAX_DEPENDENCIES", "label": "Max deps", "type": "number", "min": 1, "step": 1},
            ]},
        ],
        "quick_actions": [
            {"key": "export_logs", "label": "Экспорт логов", "icon": "fa-solid fa-download"},
            {"key": "open_incident", "label": "Открыть инцидент", "icon": "fa-regular fa-file-lines"},
            {"key": "open_git_comment", "label": "Показать комментарий", "icon": "fa-brands fa-gitlab"},
        ],
        "policy": {
            "pre_push_blocking": settings.SECURITY_BLOCK_PUSHES,
            "merge_request_blocking": settings.SECURITY_BLOCK_MERGE_REQUESTS,
            "pre_receive_blocking": settings.SECURITY_BLOCK_PRE_RECEIVE,
            "webhook_close_mr": settings.SECURITY_BLOCK_CLOSE_MR,
            "webhook_inline_comments": settings.SECURITY_BLOCK_INLINE_COMMENTS,
            "llm_required": settings.SECURITY_REQUIRE_LLM_REVIEW,
            "fail_closed": settings.SECURITY_FAIL_CLOSED_ON_LLM_ERROR,
            "block_on_critical": settings.SECURITY_BLOCK_ON_CRITICAL,
            "block_on_high": settings.SECURITY_BLOCK_ON_HIGH,
            "block_on_warning": getattr(settings, "SECURITY_BLOCK_ON_WARNING", False),
        },
        "filters": {
            "severity": [
                {"value": "all", "label": "Все"},
                {"value": "critical", "label": "Critical"},
                {"value": "high", "label": "High"},
                {"value": "medium", "label": "Medium"},
                {"value": "low", "label": "Low"},
            ],
            "status": [
                {"value": "all", "label": "Все"},
                {"value": "blocked", "label": "Заблокирован"},
                {"value": "warning", "label": "Предупреждение"},
                {"value": "passed", "label": "Пройден"},
            ],
            "log_levels": [
                {"value": "all", "label": "Все уровни"},
                {"value": "info", "label": "Info"},
                {"value": "warning", "label": "Warning"},
                {"value": "error", "label": "Error"},
            ],
            "log_statuses": [
                {"value": "all", "label": "Все статусы"},
                {"value": "ok", "label": "OK"},
                {"value": "blocked", "label": "BLOCKED"},
                {"value": "confirmed", "label": "CONFIRMED"},
            ],
            "repo_providers": [
                {"value": "all", "label": "Все провайдеры"},
                {"value": "github", "label": "GitHub"},
                {"value": "gitlab", "label": "GitLab"},
                {"value": "git", "label": "Git"},
            ],
            "repo_statuses": [
                {"value": "all", "label": "Все статусы"},
                {"value": "active", "label": "Активен"},
                {"value": "error", "label": "Ошибка"},
            ],
        },
        "ai_tools": [
            "get_check_context",
            "scan_code_snippet",
            "query_cve_database",
            "read_gitlab_file",
            "search_gitlab_regex",
            "list_audit_logs",
            "integrity_status",
            "monitoring_status",
        ],
        "detection_chain": [
            {"key": "webhook", "label": "Webhook API"},
            {"key": "diff", "label": "Diff Extractor"},
            {"key": "filter", "label": "Filter Engine"},
            {"key": "static", "label": "Static Scan"},
            {"key": "llm", "label": "LLM Validate"},
            {"key": "fix", "label": "Fix Suggestion"},
            {"key": "policy", "label": "Policy Block"},
            {"key": "comment", "label": "GitLab Comment"},
        ],
        "notifications": {
            "attention": blocked + warnings,
            "blocked": blocked,
            "warnings": warnings,
        },
    }


@router.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}
