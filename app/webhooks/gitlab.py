from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.git.gitlab_client import GitLabAPIError, GitLabClient
from app.models import AuditLog, BotMessage, Finding, Repository, SecurityCheck
from app.scanner.annotations import annotate_vulnerable_line
from app.scanner.diff_parser import parse_unified_diff
from app.scanner.engine import scan_diff
from app.webhooks.enforcement import (
    build_block_message,
    enforce_commit_status,
    enforce_merge_request_block,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _inline_body_for_commit(finding) -> str:
    return (
        f"🚫 **CodeGuardian AI · {finding.severity}** — {finding.cwe}\n\n"
        f"**{finding.title}**\n\n"
        f"_Почему опасно:_ {finding.reason or '—'}\n\n"
        f"_Как исправить:_ {finding.fix or '—'}\n\n"
        + (f"```\n{(finding.fixed_example or '')[:1200]}\n```" if finding.fixed_example else "")
    )


def _branch_from_ref(ref: str | None) -> str | None:
    if not ref:
        return None
    return ref.removeprefix("refs/heads/")


def _get_or_create_repository(db: Session, *, name: str, project_id: int | None, url: str | None) -> Repository:
    repository = None
    if project_id is not None:
        repository = db.query(Repository).filter(Repository.gitlab_project_id == project_id).first()
    if repository is None:
        repository = db.query(Repository).filter(Repository.name == name).first()
    if repository is not None:
        repository.name = name
        repository.url = url or repository.url
        return repository
    repository = Repository(name=name, gitlab_project_id=project_id, url=url)
    db.add(repository)
    db.flush()
    return repository


def _extract_event(payload: dict[str, Any]) -> dict[str, Any]:
    kind = payload.get("object_kind") or payload.get("event_name")
    project = payload.get("project") or {}
    repository = payload.get("repository") or {}
    project_id = project.get("id") or payload.get("project_id")
    project_name = project.get("path_with_namespace") or project.get("name") or repository.get("name") or "unknown"
    url = project.get("web_url") or repository.get("homepage") or repository.get("url")

    if kind == "merge_request":
        attrs = payload.get("object_attributes") or {}
        last_commit = attrs.get("last_commit") or payload.get("last_commit") or {}
        author = (payload.get("user") or {}).get("username") or attrs.get("author_username") or "unknown"
        return {
            "kind": kind,
            "project_id": int(project_id),
            "project_name": project_name,
            "url": url,
            "branch": attrs.get("source_branch"),
            "commit_sha": last_commit.get("id") or attrs.get("last_commit_id"),
            "pr_number": attrs.get("iid"),
            "author": f"@{author}" if author and not str(author).startswith("@") else author,
        }

    after = payload.get("after")
    author = payload.get("user_username") or payload.get("user_name") or "unknown"
    return {
        "kind": "push",
        "project_id": int(project_id),
        "project_name": project_name,
        "url": url,
        "branch": _branch_from_ref(payload.get("ref")),
        "commit_sha": after,
        "pr_number": None,
        "author": f"@{author}" if author and not str(author).startswith("@") else author,
    }


def _count_added_lines(diff_text: str) -> int:
    return sum(len(file.additions) for file in parse_unified_diff(diff_text))


def _save_check(
    db: Session,
    event: dict[str, Any],
    scan_result: object,
    diff_text: str,
    *,
    origin: str = "webhook",
    enforcement: str | None = None,
) -> SecurityCheck:
    repository = _get_or_create_repository(
        db,
        name=event["project_name"],
        project_id=event.get("project_id"),
        url=event.get("url"),
    )
    check = SecurityCheck(
        pr_number=event.get("pr_number"),
        repository_id=repository.id,
        author=event.get("author"),
        commit_sha=event.get("commit_sha"),
        branch=event.get("branch"),
        status=scan_result.status,
        severity=scan_result.severity,
        summary=json.dumps(
            {
                "severity": scan_result.summary,
                "changed_lines": _count_added_lines(diff_text),
                "findings": len(scan_result.findings),
            },
            ensure_ascii=False,
        ),
        origin=origin,
        enforcement=enforcement,
    )
    db.add(check)
    db.flush()

    for item in scan_result.findings:
        db.add(
            Finding(
                check_id=check.id,
                cwe=item.cwe,
                title=item.title,
                severity=item.severity,
                file=item.file,
                line=item.line,
                code=item.code,
                reason=item.reason,
                fix=item.fix,
                fixed_example=item.fixed_example,
                llm_verdict=item.llm_verdict,
                llm_confidence=item.llm_confidence,
            )
        )
        db.add(
            AuditLog(
                level="ERROR" if item.severity in {"CRITICAL", "HIGH"} else "WARNING",
                event="vulnerability.detected",
                actor=event.get("author"),
                source="Security Scanner + LLM",
                message=(
                    f"{item.cwe} {item.title} найден в {item.file}:{item.line}. "
                    f"Как найдено: diff/context + rules/CVE/LLM review. "
                    f"Почему опасно: {item.reason} "
                    f"Как исправить: {item.fix}"
                ),
            )
        )

    if scan_result.status == "blocked":
        annotated = "\n\n".join(
            annotate_vulnerable_line(item.code, item.file, item)
            for item in scan_result.findings[:3]
        )
        text = (
            "CodeGuardian AI заблокировал изменение: найдены эксплуатируемые HIGH/CRITICAL угрозы.\n\n"
            "Inline-комментарии для вставки после опасной строки:\n"
            f"{annotated}"
        )
    elif scan_result.findings:
        text = "CodeGuardian AI нашёл предупреждения. Проверьте рекомендации перед merge."
    else:
        text = "CodeGuardian AI не обнаружил блокирующих угроз."
    db.add(BotMessage(check_id=check.id, role="bot", text=text))
    log_steps = [
        ("INFO", "webhook.received", "Webhook API", f"Получен {event['kind']} hook для {event['project_name']}"),
        ("INFO", "diff.extracted", "Diff Extractor", f"Извлечено {_count_added_lines(diff_text)} добавленных строк"),
        ("INFO", "filter.completed", "Filter Engine", "Diff подготовлен к проверке правил"),
        (
            "WARNING" if scan_result.findings else "INFO",
            "static.scan.completed",
            "Static Scanner",
            f"Найдено findings: {len(scan_result.findings)}",
        ),
        (
            "WARNING" if any(finding.llm_verdict == "BLOCK" for finding in scan_result.findings) else "INFO",
            "llm.review.completed",
            "LLM Reviewer",
            "LLM validation завершена" if settings.SECURITY_USE_LLM else "LLM validation отключена в настройках",
        ),
        ("INFO", "fix.generated", "Fix Generator", "Сформированы рекомендации по исправлению"),
        (
            "ERROR" if scan_result.status == "blocked" else "SUCCESS",
            "policy.decision",
            "Policy Engine",
            f"Решение политики: {scan_result.status.upper()}",
        ),
        ("INFO", "gitlab.comment.ready", "GitLab Bot", f"Комментарий готов для проверки #{check.id}"),
        ("INFO", "audit.saved", "Audit Logger", f"Инцидент сохранён в журнале как check #{check.id}"),
    ]
    for level, event_name, source, message in log_steps:
        db.add(
            AuditLog(
                level=level,
                event=event_name,
                actor=event.get("author"),
                source=source,
                message=message,
            )
        )
    db.commit()
    db.refresh(check)
    return check


@router.post("/gitlab")
async def gitlab_webhook(
    request: Request,
    x_gitlab_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if x_gitlab_token != settings.GITLAB_WEBHOOK_SECRET:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid GitLab webhook token")

    payload = await request.json()
    event = _extract_event(payload)
    client = GitLabClient()

    try:
        if event["kind"] == "merge_request" and event.get("pr_number"):
            diff_text = client.get_merge_request_diff(event["project_id"], int(event["pr_number"]))
        else:
            diff_text = client.get_commit_diff(event["project_id"], event["commit_sha"])
    except GitLabAPIError as exc:
        logger.warning("GitLab diff fetch failed: %s", exc)
        db.add(
            AuditLog(
                level="ERROR",
                event="gitlab.diff.failed",
                actor=event.get("author"),
                source="gitlab-webhook",
                message=str(exc),
            )
        )
        db.commit()
        raise HTTPException(status_code=502, detail="Could not fetch GitLab diff") from exc

    scan_result = scan_diff(diff_text, use_llm=settings.SECURITY_USE_LLM)

    enforcement_actions: list[str] = []
    enforcement_failures: list[str] = []
    enforcement_label: str | None = None

    if event.get("commit_sha"):
        ok, err = enforce_commit_status(
            client=client,
            project_id=event["project_id"],
            commit_sha=event["commit_sha"],
            scan_result=scan_result,
        )
        if ok:
            enforcement_actions.append("commit.status")
        elif err:
            enforcement_failures.append(f"commit.status: {err}")

    if scan_result.status == "blocked" and event["kind"] == "merge_request" and event.get("pr_number"):
        outcome = enforce_merge_request_block(
            db,
            client=client,
            project_id=event["project_id"],
            merge_request_iid=int(event["pr_number"]),
            scan_result=scan_result,
            author=event.get("author"),
        )
        enforcement_actions.extend(outcome.actions)
        enforcement_failures.extend(outcome.failures)
        enforcement_label = "mr-webhook"
    elif scan_result.status == "blocked":
        enforcement_label = "push-webhook"

    # Add inline commit comments for ANY blocked event with a commit_sha
    if scan_result.status == "blocked" and event.get("commit_sha"):
        logger.info(
            "Adding inline commit comments for %s findings on commit %s",
            len(scan_result.findings), event["commit_sha"],
        )
        for finding in scan_result.findings[:10]:
            if not finding.file or not finding.line:
                logger.debug("Skipping finding without file/line: %s", finding.title)
                continue
            try:
                client.add_commit_comment(
                    event["project_id"],
                    event["commit_sha"],
                    _inline_body_for_commit(finding),
                    file_path=finding.file,
                    line=int(finding.line),
                )
                enforcement_actions.append(f"commit.comment:{finding.file}:{finding.line}")
                logger.info("Commit comment added: %s:%s", finding.file, finding.line)
            except Exception as exc:
                logger.warning("Commit comment failed: %s:%s — %s", finding.file, finding.line, exc)
                enforcement_failures.append(f"commit.comment:{finding.file}:{finding.line}: {exc}")
                # Fallback: try without line (general commit note)
                try:
                    client.add_commit_comment(
                        event["project_id"],
                        event["commit_sha"],
                        _inline_body_for_commit(finding),
                    )
                    enforcement_actions.append(f"commit.note:{finding.file}:{finding.line}")
                except Exception:
                    pass

    check = _save_check(
        db,
        event,
        scan_result,
        diff_text,
        origin="webhook",
        enforcement=enforcement_label,
    )

    payload = {
        "check_id": check.id,
        "status": scan_result.status,
        "severity": scan_result.severity,
        "summary": scan_result.summary,
        "blocked": scan_result.status == "blocked",
        "enforcement": {
            "label": enforcement_label,
            "actions": enforcement_actions,
            "failures": enforcement_failures,
        },
        "findings": [f.to_dict() if hasattr(f, "to_dict") else {} for f in scan_result.findings],
        "block_message": build_block_message(scan_result) if scan_result.status == "blocked" else None,
    }
    if scan_result.status == "blocked":
        # 422 заставляет GitLab/CI пометить webhook как failed и не пропускать MR/push
        raise HTTPException(status_code=422, detail=payload)
    return payload

