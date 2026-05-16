"""Enforcement helpers: блокирует «доход» изменений в Git при blocked-результате.

Используется и из webhook'а GitLab (для MR/push), и из /api/git/precheck (для pre-push,
pre-receive хуков и CI).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable

from sqlalchemy.orm import Session

from app.config import settings
from app.git.gitlab_client import GitLabAPIError, GitLabClient
from app.models import AuditLog
from app.scanner.engine import ScanFinding, ScanResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class EnforcementOutcome:
    actions: list[str]
    failures: list[str]

    def to_dict(self) -> dict[str, list[str]]:
        return {"actions": self.actions, "failures": self.failures}


def _truncate(text: str, limit: int = 4000) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def build_block_message(scan_result: ScanResult, *, header: str | None = None) -> str:
    title = header or "🚫 CodeGuardian AI заблокировал изменение"
    lines = [
        title,
        "",
        f"Severity: {scan_result.severity}",
        f"Findings: {len(scan_result.findings)}",
        "",
    ]
    for item in scan_result.findings[:10]:
        lines.append(f"• [{item.severity}] {item.cwe} — {item.title} ({item.file}:{item.line})")
        if item.reason:
            lines.append(f"  Почему: {_truncate(item.reason, 240)}")
        if item.fix:
            lines.append(f"  Как исправить: {_truncate(item.fix, 240)}")
        lines.append("")
    if len(scan_result.findings) > 10:
        lines.append(f"... и ещё {len(scan_result.findings) - 10} проблем(ы)")
    return "\n".join(lines)


def _safe(callable_, *, on_error: list[str], label: str) -> bool:
    try:
        callable_()
        return True
    except GitLabAPIError as exc:
        logger.warning("Enforcement step '%s' failed: %s", label, exc)
        on_error.append(f"{label}: {exc}")
    except Exception as exc:  # pragma: no cover
        logger.exception("Enforcement step '%s' crashed", label)
        on_error.append(f"{label}: {exc}")
    return False


def _inline_body(finding: ScanFinding) -> str:
    return (
        f"🚫 **CodeGuardian AI · {finding.severity}** — {finding.cwe}\n\n"
        f"**{finding.title}**\n\n"
        f"_Почему опасно:_ {finding.reason or '—'}\n\n"
        f"_Как исправить:_ {finding.fix or '—'}\n\n"
        + (f"```\n{_truncate(finding.fixed_example, 1200)}\n```" if finding.fixed_example else "")
    )


def enforce_merge_request_block(
    db: Session,
    *,
    client: GitLabClient,
    project_id: int,
    merge_request_iid: int,
    scan_result: ScanResult,
    author: str | None,
) -> EnforcementOutcome:
    actions: list[str] = []
    failures: list[str] = []

    summary_note = build_block_message(scan_result)
    if _safe(
        lambda: client.add_mr_note(project_id, merge_request_iid, summary_note),
        on_error=failures,
        label="mr.note",
    ):
        actions.append("mr.note")

    if settings.SECURITY_BLOCK_INLINE_COMMENTS:
        try:
            mr = client.get_merge_request(project_id, merge_request_iid)
            diff_refs = (mr or {}).get("diff_refs") or {}
            base_sha = diff_refs.get("base_sha")
            start_sha = diff_refs.get("start_sha")
            head_sha = diff_refs.get("head_sha")
        except GitLabAPIError as exc:
            failures.append(f"mr.diff_refs: {exc}")
            base_sha = start_sha = head_sha = None

        if base_sha and start_sha and head_sha:
            for finding in scan_result.findings[:5]:
                if not finding.file or not finding.line:
                    continue
                if _safe(
                    lambda f=finding: client.create_mr_inline_discussion(
                        project_id=project_id,
                        merge_request_iid=merge_request_iid,
                        body=_inline_body(f),
                        file_path=f.file,
                        new_line=int(f.line),
                        base_sha=base_sha,
                        start_sha=start_sha,
                        head_sha=head_sha,
                    ),
                    on_error=failures,
                    label=f"mr.inline:{finding.file}:{finding.line}",
                ):
                    actions.append("mr.inline")

    if settings.SECURITY_BLOCK_CLOSE_MR:
        if _safe(
            lambda: client.close_merge_request(project_id, merge_request_iid),
            on_error=failures,
            label="mr.close",
        ):
            actions.append("mr.close")

    db.add(
        AuditLog(
            level="ERROR",
            event="enforcement.mr.blocked",
            actor=author,
            source="Enforcement Engine",
            message=(
                f"Merge request !{merge_request_iid} проекта {project_id} заблокирован. "
                f"Actions: {', '.join(actions) or 'none'}. "
                f"Failures: {', '.join(failures) or 'none'}."
            ),
        )
    )
    return EnforcementOutcome(actions=actions, failures=failures)


def enforce_commit_status(
    *,
    client: GitLabClient,
    project_id: int,
    commit_sha: str,
    scan_result: ScanResult,
) -> tuple[bool, str | None]:
    state = "failed" if scan_result.status == "blocked" else "success"
    description = f"CodeGuardian AI: {scan_result.status} ({scan_result.severity})"
    try:
        client.set_commit_status(
            project_id=project_id,
            commit_sha=commit_sha,
            state=state,
            description=description,
            target_url=f"{settings.CODEGUARDIAN_PUBLIC_URL.rstrip('/')}/",
        )
        return True, None
    except GitLabAPIError as exc:
        return False, str(exc)
