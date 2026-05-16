from __future__ import annotations

import subprocess


ZERO_SHA = "0" * 40


def _run_git(args: list[str], *, input_text: str | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        input=input_text,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout


def get_staged_diff() -> str:
    return _run_git(["diff", "--cached", "--unified=30"])


def get_diff_range(base_ref: str, head_ref: str) -> str:
    return _run_git(["diff", "--unified=30", base_ref, head_ref])


def _try_git(args: list[str]) -> str | None:
    result = subprocess.run(
        ["git", *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def _new_branch_base(local_sha: str) -> str | None:
    candidates = [
        ["merge-base", local_sha, "refs/remotes/origin/HEAD"],
        ["merge-base", local_sha, "origin/main"],
        ["merge-base", local_sha, "origin/master"],
    ]
    for args in candidates:
        base = _try_git(args)
        if base:
            return base
    return None


def get_pre_push_diff(stdin_text: str) -> str:
    chunks: list[str] = []
    for raw_line in stdin_text.splitlines():
        parts = raw_line.split()
        if len(parts) < 4:
            continue
        local_ref, local_sha, _remote_ref, remote_sha = parts[:4]
        if local_sha == ZERO_SHA:
            continue
        if remote_sha == ZERO_SHA:
            base = _new_branch_base(local_sha)
            if base:
                chunks.append(get_diff_range(base, local_sha))
            else:
                chunks.append(_run_git(["diff-tree", "--root", "-p", "--unified=30", local_sha]))
        else:
            chunks.append(get_diff_range(remote_sha, local_sha))
    if chunks:
        return "\n".join(chunk for chunk in chunks if chunk.strip())

    upstream = _try_git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
    if upstream:
        return get_diff_range(upstream, "HEAD")
    return get_staged_diff()
