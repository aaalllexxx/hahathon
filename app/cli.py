from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

from app.config import settings
from app.git.repository import get_pre_push_diff, get_staged_diff
from app.scanner.engine import scan_diff


def _configure_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")


def _print_verdict(result: object) -> None:
    if result.status == "blocked":
        print("✖ CodeGuardian AI: CRITICAL SECURITY ISSUE", file=sys.stderr)
    elif result.findings:
        print("! SECURITY WARNINGS FOUND", file=sys.stderr)
    else:
        print("✓ CodeGuardian AI: changes look safe")
        return

    out = sys.stderr if result.status == "blocked" else sys.stdout
    print(file=out)
    for finding in result.findings:
        print(f"{finding.cwe}: {finding.title}", file=out)
        print(f"File: {finding.file}", file=out)
        print(f"Line: {finding.line}", file=out)
        print(file=out)
        print("Problem:", file=out)
        print(finding.reason, file=out)
        print(file=out)
        print("Dangerous code:", file=out)
        print(finding.code, file=out)
        print(file=out)
        print("Fix:", file=out)
        print(finding.fixed_example, file=out)
        print("-" * 72, file=out)


def _print_remote_verdict(payload: dict) -> None:
    blocked = bool(payload.get("blocked")) or payload.get("status") == "blocked"
    if blocked:
        print("✖ PUSH BLOCKED — CodeGuardian AI rejected changes", file=sys.stderr)
        msg = payload.get("block_message")
        if msg:
            print(msg, file=sys.stderr)
        else:
            for f in payload.get("findings") or []:
                print(f"- [{f.get('severity')}] {f.get('cwe')} {f.get('title')} @ {f.get('file')}:{f.get('line')}", file=sys.stderr)
        return
    findings = payload.get("findings") or []
    if findings:
        print("! SECURITY WARNINGS:")
        for f in findings:
            print(f"- [{f.get('severity')}] {f.get('cwe')} {f.get('title')} @ {f.get('file')}:{f.get('line')}")
    else:
        print("✓ CodeGuardian AI: changes look safe")


def _call_precheck_api(api_url: str, payload: dict, *, token: str | None, timeout: float) -> tuple[int, dict]:
    """Returns (http_status, json_body). Raises URLError on network failure."""
    req = urllib.request.Request(
        api_url.rstrip("/") + "/api/git/precheck",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    if token:
        req.add_header("X-CodeGuardian-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8") or "{}")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and "detail" in data and isinstance(data["detail"], dict):
                return exc.code, data["detail"]
            return exc.code, data if isinstance(data, dict) else {"raw": raw}
        except Exception:
            return exc.code, {"raw": raw}


def _read_diff(args: argparse.ArgumentParser, parsed) -> str:
    if parsed.staged:
        return get_staged_diff()
    if parsed.pre_push:
        return get_pre_push_diff(sys.stdin.read())
    if parsed.diff_file:
        with open(parsed.diff_file, encoding="utf-8") as fh:
            return fh.read()
    args.error("scan requires --staged, --pre-push, --diff-file or --ci")
    return ""  # pragma: no cover


def main(argv: list[str] | None = None) -> int:
    _configure_console()
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="CodeGuardian AI local scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="Scan Git diff")
    scan_parser.add_argument("--staged", action="store_true", help="Scan staged changes (git diff --cached)")
    scan_parser.add_argument("--pre-push", action="store_true", help="Scan outgoing commits from pre-push hook stdin")
    scan_parser.add_argument("--diff-file", help="Scan diff from file")
    scan_parser.add_argument("--ci", action="store_true", help="CI mode: scan diff against target branch (uses CI_MERGE_REQUEST_DIFF_BASE_SHA)")
    scan_parser.add_argument("--no-llm", action="store_true", help="Disable LLM review for this local scan")
    scan_parser.add_argument(
        "--api",
        default=os.environ.get("CODEGUARDIAN_API"),
        help="Use remote /api/git/precheck endpoint (e.g. http://host:8000). Falls back to local scan on failure.",
    )
    scan_parser.add_argument(
        "--api-token",
        default=os.environ.get("CODEGUARDIAN_API_TOKEN"),
        help="Optional X-CodeGuardian-Token for non-public precheck",
    )
    scan_parser.add_argument(
        "--api-timeout",
        type=float,
        default=float(os.environ.get("CODEGUARDIAN_API_TIMEOUT", "20")),
    )
    scan_parser.add_argument(
        "--no-fallback",
        action="store_true",
        help="If --api fails, do not fall back to local scanner — exit non-zero.",
    )
    scan_parser.add_argument("--origin", default=None, help="Origin label sent to API (pre-push, pre-receive, ci, manual)")
    scan_parser.add_argument("--repository", default=None, help="Repository name to send to API")
    scan_parser.add_argument("--branch", default=None, help="Branch name to send to API")
    scan_parser.add_argument("--warn-only", action="store_true", help="Print findings but always exit 0. Useful for branch pushes.")
    args = parser.parse_args(argv)

    if args.command != "scan":
        return 2

    # Compute diff
    try:
        if args.ci:
            base = os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA") or os.environ.get("CI_COMMIT_BEFORE_SHA")
            head = os.environ.get("CI_COMMIT_SHA", "HEAD")
            import subprocess
            if base and base != "0000000000000000000000000000000000000000":
                diff_text = subprocess.check_output(
                    ["git", "diff", "--unified=0", f"{base}..{head}"],
                    text=True, encoding="utf-8", errors="replace",
                )
            else:
                diff_text = subprocess.check_output(
                    ["git", "show", "--unified=0", head],
                    text=True, encoding="utf-8", errors="replace",
                )
        else:
            diff_text = _read_diff(parser, args)
    except Exception as exc:
        print(f"CodeGuardian AI failed to read diff: {exc}", file=sys.stderr)
        return 2

    if not diff_text.strip():
        print("✓ CodeGuardian AI: no changes to scan")
        return 0

    origin_default = "ci" if args.ci else ("pre-push" if args.pre_push else "manual")
    origin = args.origin or origin_default

    # Remote API path
    if args.api:
        payload = {
            "diff": diff_text,
            "origin": origin,
            "repository": args.repository or os.environ.get("CI_PROJECT_PATH") or os.path.basename(os.getcwd()),
            "branch": args.branch or os.environ.get("CI_COMMIT_REF_NAME"),
            "commit_sha": os.environ.get("CI_COMMIT_SHA"),
            "author": os.environ.get("GITLAB_USER_LOGIN") or os.environ.get("USER") or os.environ.get("USERNAME"),
            "use_llm": not args.no_llm,
        }
        try:
            status, body = _call_precheck_api(args.api, payload, token=args.api_token, timeout=args.api_timeout)
            _print_remote_verdict(body)
            blocked = body.get("blocked") or body.get("status") == "blocked" or status == 422
            if args.warn_only and blocked:
                print("⚠ CodeGuardian AI: push разрешён, блокировка будет применена на Merge Request.", file=sys.stderr)
                return 0
            return 1 if blocked else 0
        except Exception as exc:
            if args.no_fallback:
                print(f"CodeGuardian AI: API call failed ({exc}) — refusing to proceed (--no-fallback).", file=sys.stderr)
                return 2
            print(f"CodeGuardian AI: API call failed ({exc}) — falling back to local scan.", file=sys.stderr)

    result = scan_diff(diff_text, use_llm=not args.no_llm)
    _print_verdict(result)
    if args.warn_only and result.status == "blocked":
        print("⚠ CodeGuardian AI: push разрешён, блокировка будет применена на Merge Request.", file=sys.stderr)
        return 0
    return 1 if result.status == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
