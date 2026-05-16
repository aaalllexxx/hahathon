from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from app.config import settings


class GitLabAPIError(RuntimeError):
    pass


@dataclass(slots=True)
class GitLabClient:
    base_url: str = settings.GITLAB_INTERNAL_URL
    private_token: str = settings.GITLAB_PRIVATE_TOKEN
    timeout: float = 20

    def _headers(self) -> dict[str, str]:
        return {"PRIVATE-TOKEN": self.private_token}

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = f"{self.base_url.rstrip('/')}/api/v4{path}"
        # Prefer json= over data= for GitLab API
        if "data" in kwargs and "json" not in kwargs:
            kwargs["json"] = kwargs.pop("data")
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.request(method, url, headers=self._headers(), **kwargs)
        except httpx.HTTPError as exc:
            raise GitLabAPIError(f"GitLab API request failed: {exc}") from exc
        if response.status_code >= 400:
            raise GitLabAPIError(f"GitLab API {response.status_code}: {response.text[:500]}")
        if response.content:
            return response.json()
        return None

    @staticmethod
    def _diffs_to_text(diffs: list[dict[str, Any]]) -> str:
        chunks: list[str] = []
        for item in diffs:
            old_path = item.get("old_path") or item.get("old_file") or item.get("new_path") or "unknown"
            new_path = item.get("new_path") or item.get("new_file") or old_path
            diff = item.get("diff") or ""
            chunks.append(f"diff --git a/{old_path} b/{new_path}\n--- a/{old_path}\n+++ b/{new_path}\n{diff}")
        return "\n".join(chunks)

    def get_commit_diff(self, project_id: int, commit_sha: str) -> str:
        data = self._request("GET", f"/projects/{project_id}/repository/commits/{commit_sha}/diff")
        return self._diffs_to_text(data or [])

    def get_merge_request_diff(self, project_id: int, merge_request_iid: int) -> str:
        data = self._request("GET", f"/projects/{project_id}/merge_requests/{merge_request_iid}/changes")
        changes = data.get("changes") if isinstance(data, dict) else data
        return self._diffs_to_text(changes or [])

    def set_commit_status(
        self,
        *,
        project_id: int,
        commit_sha: str,
        state: str,
        description: str,
        target_url: str | None = None,
    ) -> None:
        payload = {
            "state": state,
            "name": "CodeGuardian AI",
            "description": description[:255],
        }
        if target_url:
            payload["target_url"] = target_url
        self._request("POST", f"/projects/{project_id}/statuses/{commit_sha}", data=payload)

    def list_repository_tree(self, project_id: int, ref: str | None = None, recursive: bool = True) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"recursive": recursive, "per_page": 100}
        if ref:
            params["ref"] = ref
        return self._request("GET", f"/projects/{project_id}/repository/tree", params=params) or []

    def get_merge_request(self, project_id: int, merge_request_iid: int) -> dict[str, Any]:
        return self._request("GET", f"/projects/{project_id}/merge_requests/{merge_request_iid}") or {}

    def close_merge_request(self, project_id: int, merge_request_iid: int) -> None:
        self._request(
            "PUT",
            f"/projects/{project_id}/merge_requests/{merge_request_iid}",
            data={"state_event": "close"},
        )

    def add_mr_note(self, project_id: int, merge_request_iid: int, body: str) -> None:
        self._request(
            "POST",
            f"/projects/{project_id}/merge_requests/{merge_request_iid}/notes",
            data={"body": body[:60000]},
        )

    def create_mr_inline_discussion(
        self,
        *,
        project_id: int,
        merge_request_iid: int,
        body: str,
        file_path: str,
        new_line: int,
        base_sha: str,
        start_sha: str,
        head_sha: str,
    ) -> None:
        payload = {
            "body": body[:60000],
            "position": {
                "base_sha": base_sha,
                "start_sha": start_sha,
                "head_sha": head_sha,
                "position_type": "text",
                "new_path": file_path,
                "old_path": file_path,
                "new_line": new_line,
            },
        }
        self._request(
            "POST",
            f"/projects/{project_id}/merge_requests/{merge_request_iid}/discussions",
            json=payload,
        )

    def add_commit_comment(
        self,
        project_id: int,
        commit_sha: str,
        body: str,
        *,
        file_path: str | None = None,
        line: int | None = None,
        line_type: str = "new",
    ) -> None:
        """Add an inline comment to a commit."""
        payload: dict[str, Any] = {"note": body[:60000]}
        if file_path:
            payload["path"] = file_path
        if line:
            payload["line"] = line
            payload["line_type"] = line_type
        self._request(
            "POST",
            f"/projects/{project_id}/repository/commits/{commit_sha}/comments",
            data=payload,
        )

    def get_repository_file(self, project_id: int, file_path: str, ref: str = "main") -> str:
        encoded_path = quote(file_path, safe="")
        url_path = f"/projects/{project_id}/repository/files/{encoded_path}/raw"
        url = f"{self.base_url.rstrip('/')}/api/v4{url_path}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(url, headers=self._headers(), params={"ref": ref})
        except httpx.HTTPError as exc:
            raise GitLabAPIError(f"GitLab file fetch failed: {exc}") from exc
        if response.status_code >= 400:
            raise GitLabAPIError(f"GitLab API {response.status_code}: {response.text[:500]}")
        return response.text
