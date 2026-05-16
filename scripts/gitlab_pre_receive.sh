#!/usr/bin/env bash
# CodeGuardian AI server-side pre-receive hook for GitLab.
#
# Install on the GitLab server:
#   sudo mkdir -p /var/opt/gitlab/git-data/repositories/<group>/<project>.git/custom_hooks
#   sudo cp gitlab_pre_receive.sh /var/opt/gitlab/git-data/repositories/<group>/<project>.git/custom_hooks/pre-receive
#   sudo chmod +x .../custom_hooks/pre-receive
#   sudo chown git:git .../custom_hooks/pre-receive
#
# Required env on GitLab host:
#   CODEGUARDIAN_API       - base URL of CodeGuardian server (e.g. http://codeguardian:8000)
#   CODEGUARDIAN_API_TOKEN - optional, equals GITLAB_WEBHOOK_SECRET when SECURITY_PRECHECK_PUBLIC=false
#
# Behaviour:
#   - reads <old> <new> <ref> tuples from stdin
#   - computes git diff for the pushed range
#   - sends diff to /api/git/precheck (origin=pre-receive)
#   - HTTP 422 (blocked) -> exit 1, push rejected by GitLab
#   - network error -> exit 0 (fail-open, рассчитывайте на client + webhook)
#   - изменить на fail-closed: установите CODEGUARDIAN_STRICT=1

set -uo pipefail

API="${CODEGUARDIAN_API:-}"
TOKEN="${CODEGUARDIAN_API_TOKEN:-}"
STRICT="${CODEGUARDIAN_STRICT:-0}"

if [ -z "$API" ]; then
  echo "[CodeGuardian] CODEGUARDIAN_API не настроен, пропуск pre-receive." >&2
  exit 0
fi

ZERO="0000000000000000000000000000000000000000"

block_reason=""
while read -r OLD NEW REF; do
  if [ "$NEW" = "$ZERO" ]; then
    continue   # branch deletion
  fi

  if [ "$OLD" = "$ZERO" ]; then
    # new branch: compare against default branch tip if available
    BASE=$(git for-each-ref --format='%(objectname)' refs/heads/main refs/heads/master 2>/dev/null | head -n1)
    if [ -z "$BASE" ] || [ "$BASE" = "$NEW" ]; then
      DIFF=$(git show --unified=0 "$NEW" 2>/dev/null || true)
    else
      DIFF=$(git diff --unified=0 "$BASE..$NEW" 2>/dev/null || true)
    fi
  else
    DIFF=$(git diff --unified=0 "$OLD..$NEW" 2>/dev/null || true)
  fi

  if [ -z "$DIFF" ]; then
    continue
  fi

  TMP=$(mktemp)
  python3 - "$DIFF" >"$TMP" <<'PY'
import json, sys
diff = sys.argv[1]
print(json.dumps({
  "diff": diff,
  "origin": "pre-receive",
  "repository": __import__("os").environ.get("GL_PROJECT_PATH") or __import__("os").environ.get("GL_REPOSITORY") or "unknown",
  "branch": (__import__("os").environ.get("GL_REF") or "").replace("refs/heads/", "") or None,
  "commit_sha": __import__("os").environ.get("GL_NEW_REV"),
  "author": __import__("os").environ.get("GL_USERNAME"),
}))
PY

  HTTP_CODE=$(
    curl -sS -o /tmp/cg_resp.json -w "%{http_code}" \
      -X POST \
      -H "Content-Type: application/json" \
      ${TOKEN:+-H "X-CodeGuardian-Token: $TOKEN"} \
      --data-binary @"$TMP" \
      "$API/api/git/precheck" || echo "000"
  )
  rm -f "$TMP"

  if [ "$HTTP_CODE" = "422" ]; then
    echo "" >&2
    echo "✖ CodeGuardian AI rejected push to $REF" >&2
    python3 -c "import json,sys;d=json.load(open('/tmp/cg_resp.json'));b=d.get('detail',d);print(b.get('block_message') or '');[print(f\"- [{f.get('severity')}] {f.get('cwe')} {f.get('title')} @ {f.get('file')}:{f.get('line')}\") for f in (b.get('findings') or [])]" >&2 || cat /tmp/cg_resp.json >&2
    block_reason="blocked"
  elif [ "$HTTP_CODE" = "000" ] || [ "$HTTP_CODE" = "" ]; then
    echo "[CodeGuardian] WARNING: API недоступен ($API)." >&2
    if [ "$STRICT" = "1" ]; then
      block_reason="api-down"
    fi
  elif [ "$HTTP_CODE" != "200" ]; then
    echo "[CodeGuardian] WARNING: неожиданный код $HTTP_CODE от API." >&2
    if [ "$STRICT" = "1" ]; then
      block_reason="api-error"
    fi
  fi
done

if [ -n "$block_reason" ]; then
  exit 1
fi
exit 0
