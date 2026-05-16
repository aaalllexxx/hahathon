from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import settings
from app.git.gitlab_client import GitLabAPIError, GitLabClient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Configure GitLab merge protection for CodeGuardian AI."
    )
    parser.add_argument("--project-id", type=int, required=True, help="GitLab numeric project ID.")
    parser.add_argument("--branch", default="main", help="Target protected branch. Default: main.")
    parser.add_argument(
        "--gitlab-url",
        default=settings.GITLAB_URL,
        help="GitLab URL reachable from this machine. Default: GITLAB_URL from .env.",
    )
    parser.add_argument(
        "--token",
        default=settings.GITLAB_PRIVATE_TOKEN,
        help="Private token with project Maintainer/Owner permissions.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = GitLabClient(base_url=args.gitlab_url, private_token=args.token)

    project_payload = {
        "only_allow_merge_if_pipeline_succeeds": True,
        "only_allow_merge_if_all_discussions_are_resolved": True,
        "allow_merge_on_skipped_pipeline": False,
        "remove_source_branch_after_merge": True,
    }

    try:
        client.update_project_settings(args.project_id, project_payload)
        print("OK: merge checks enabled")

        client.protect_branch(
            args.project_id,
            args.branch,
            push_access_level=0,
            merge_access_level=40,
            unprotect_access_level=40,
        )
        print(f"OK: branch '{args.branch}' protected")
    except GitLabAPIError as exc:
        print(f"ERROR: GitLab API failed: {exc}", file=sys.stderr)
        return 1

    print("CodeGuardian policy is ready: pushes to feature branches are allowed, unsafe MR merge is blocked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
