"""Public precheck endpoint used by pre-push / pre-receive / CI."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Header
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import AuditLog, BotMessage, Finding, Repository, SecurityCheck
from app.scanner.diff_parser import parse_unified_diff
from app.scanner.engine import ScanResult, scan_diff
from app.webhooks.enforcement import build_block_message

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/git", tags=["enforcement"])


def _count_added_lines(diff_text: str) -> int:
    return sum(len(file.additions) for file in parse_unified_diff(diff_text))


def _should_enforce_origin(origin: str) -> bool:
    normalized = origin.lower().strip()
    if normalized in {"ci", "merge-request", "merge_request", "mr", "mr-webhook"}:
        return settings.SECURITY_BLOCK_MERGE_REQUESTS
    if normalized in {"pre-push", "pre-receive", "push", "push-webhook"}:
        return settings.SECURITY_BLOCK_PUSHES or settings.SECURITY_BLOCK_PRE_RECEIVE
    return normalized not in {"manual", "push-audit"}


def _effective_result(scan_result: ScanResult, *, enforce: bool) -> ScanResult:
    if enforce or scan_result.status != "blocked":
        return scan_result
    return ScanResult(
        status="warning" if scan_result.findings else "passed",
        summary=scan_result.summary,
        severity=scan_result.severity,
        findings=scan_result.findings,
    )


def _persist_check(
    db: Session,
    *,
    diff_text: str,
    scan_result,
    origin: str,
    repository_name: str,
    branch: str | None,
    commit_sha: str | None,
    author: str | None,
    enforcement_label: str | None,
) -> SecurityCheck:
    repository = db.query(Repository).filter(Repository.name == repository_name).first()
    if repository is None:
        repository = Repository(name=repository_name)
        db.add(repository)
        db.flush()

    import json
    check = SecurityCheck(
        repository_id=repository.id,
        author=author,
        commit_sha=commit_sha,
        branch=branch,
        status=scan_result.status,
        severity=scan_result.severity,
        summary=json.dumps(
            {
                "severity": scan_result.summary,
                "changed_lines": _count_added_lines(diff_text),
                "findings": len(scan_result.findings),
                "origin": origin,
            },
            ensure_ascii=False,
        ),
        origin=origin,
        enforcement=enforcement_label,
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

    bot_text = (
        build_block_message(scan_result)
        if scan_result.status == "blocked"
        else (
            "CodeGuardian AI нашёл предупреждения."
            if scan_result.findings
            else "CodeGuardian AI: изменения безопасны."
        )
    )
    db.add(BotMessage(check_id=check.id, role="bot", text=bot_text))
    db.add(
        AuditLog(
            level="ERROR" if scan_result.status == "blocked" else "INFO",
            event=f"precheck.{origin}",
            actor=author,
            source=f"Precheck/{origin}",
            message=(
                f"{origin}: {scan_result.status.upper()} ({scan_result.severity}), "
                f"findings={len(scan_result.findings)}, repo={repository_name}, branch={branch or '-'}"
            ),
        )
    )
    db.commit()
    db.refresh(check)
    return check


@router.post("/precheck")
def precheck(
    payload: dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
    x_codeguardian_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Единая точка для блокировки push/MR/CI.

    Если SECURITY_PRECHECK_PUBLIC=false — требуется заголовок
    X-CodeGuardian-Token == GITLAB_WEBHOOK_SECRET.
    """
    if not settings.SECURITY_PRECHECK_PUBLIC:
        if x_codeguardian_token != settings.GITLAB_WEBHOOK_SECRET:
            raise HTTPException(status_code=401, detail="Invalid precheck token")

    diff_text = str(payload.get("diff") or "")
    if not diff_text.strip():
        return {
            "status": "passed",
            "severity": "LOW",
            "blocked": False,
            "findings": [],
            "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "block_message": None,
            "check_id": None,
        }

    origin = str(payload.get("origin") or "pre-push")
    repository_name = str(payload.get("repository") or payload.get("project_name") or "local-precheck")
    branch = payload.get("branch")
    commit_sha = payload.get("commit_sha")
    author = payload.get("author") or "local"
    use_llm = bool(payload.get("use_llm", settings.SECURITY_USE_LLM))

    scan_result = scan_diff(diff_text, use_llm=use_llm)
    enforce = scan_result.status == "blocked" and _should_enforce_origin(origin)
    effective_result = _effective_result(scan_result, enforce=enforce)
    enforcement_label = origin if enforce else None

    check = _persist_check(
        db,
        diff_text=diff_text,
        scan_result=effective_result,
        origin=origin,
        repository_name=repository_name,
        branch=branch,
        commit_sha=commit_sha,
        author=author,
        enforcement_label=enforcement_label,
    )

    body = {
        "check_id": check.id,
        "status": effective_result.status,
        "severity": scan_result.severity,
        "summary": scan_result.summary,
        "blocked": enforce,
        "block_message": build_block_message(scan_result) if enforce else None,
        "enforcement": enforcement_label,
        "push_policy": "allowed" if origin in {"pre-push", "pre-receive", "push", "push-webhook"} and not enforce else "enforced",
        "findings": [f.to_dict() for f in scan_result.findings],
    }
    if enforce:
        # 422 — стандартный код, который легко отличить в CI/shell-скриптах от сетевых ошибок.
        raise HTTPException(status_code=422, detail=body)
    return body
