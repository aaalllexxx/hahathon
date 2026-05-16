from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RepositoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    gitlab_project_id: int | None = None
    url: str | None = None
    created_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    check_id: int
    cwe: str
    title: str
    severity: str
    file: str | None = None
    line: int | None = None
    code: str | None = None
    reason: str | None = None
    fix: str | None = None
    fixed_example: str | None = None
    llm_verdict: str | None = None
    llm_confidence: float | None = None
    inline_comment: str | None = None
    annotated_code: str | None = None


class BotMessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    check_id: int
    role: str
    text: str
    created_at: datetime


class SecurityCheckOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    pr_number: int | None = None
    repository_id: int
    repository: RepositoryOut
    author: str | None = None
    commit_sha: str | None = None
    branch: str | None = None
    status: str
    severity: str
    summary: str | None = None
    origin: str | None = None
    enforcement: str | None = None
    created_at: datetime
    findings: list[FindingOut] = Field(default_factory=list)
    messages: list[BotMessageOut] = Field(default_factory=list)


class CheckCommentIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    check_id: int | None = None


class ChatOut(BaseModel):
    answer: str
    tools_used: list[str] = Field(default_factory=list)
    degraded: bool = False


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    level: str
    event: str
    actor: str | None = None
    source: str | None = None
    message: str
    created_at: datetime
