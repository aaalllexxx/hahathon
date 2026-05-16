from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

import httpx
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Create GitLab webhook for CodeGuardian AI")
    parser.add_argument("project_id", help="GitLab project id")
    args = parser.parse_args()

    gitlab_url = os.getenv("GITLAB_URL", "http://localhost:8080").rstrip("/")
    token = os.getenv("GITLAB_PRIVATE_TOKEN", "change-me")
    secret = os.getenv("GITLAB_WEBHOOK_SECRET", "super-secret-token")
    webhook_url = os.getenv("CODEGUARDIAN_WEBHOOK_URL", "http://codeguardian:8000/webhooks/gitlab")

    payload = {
        "url": webhook_url,
        "token": secret,
        "push_events": True,
        "merge_requests_events": True,
        "enable_ssl_verification": False,
    }
    endpoint = f"{gitlab_url}/api/v4/projects/{args.project_id}/hooks"
    response = httpx.post(endpoint, headers={"PRIVATE-TOKEN": token}, data=payload, timeout=20)
    if response.status_code >= 400:
        print(f"GitLab returned {response.status_code}: {response.text}", file=sys.stderr)
        return 1
    hook = response.json()
    print(f"Webhook created: id={hook.get('id')} url={hook.get('url')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
