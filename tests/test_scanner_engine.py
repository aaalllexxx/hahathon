from app.scanner.engine import ScanFinding, _anchor_llm_findings, scan_diff
from app.scanner.severity import build_summary, highest_severity, should_block


def test_empty_diff_passes():
    result = scan_diff("", use_llm=False)

    assert result.status == "passed"
    assert result.summary == {"critical": 0, "high": 0, "medium": 0, "low": 0}


def test_scans_context_lines_around_changes():
    diff = """diff --git a/test.sql b/test.sql
--- a/test.sql
+++ b/test.sql
@@ -1,2 +1,4 @@
 query = "SELECT * FROM users WHERE username = '" + username + "'"
-cursor.execute(query)
+cursor.execute(query)
+if __name__ == "__main__":
+    pass
"""
    result = scan_diff(diff, use_llm=False)

    assert result.status == "blocked"
    assert result.findings[0].cwe == "CWE-89"
    assert result.findings[0].line == 1


def test_severity_decision_logic_blocks_critical_and_high():
    findings = [
        ScanFinding(
            cwe="CWE-89",
            title="SQL Injection",
            severity="CRITICAL",
            file="auth/login.py",
            line=23,
            code="query = ...",
            reason="danger",
            fix="fix",
            fixed_example="safe",
        ),
        ScanFinding(
            cwe="CWE-79",
            title="XSS",
            severity="HIGH",
            file="app.js",
            line=7,
            code="innerHTML",
            reason="danger",
            fix="fix",
            fixed_example="safe",
        ),
    ]

    assert highest_severity([finding.severity for finding in findings]) == "CRITICAL"
    assert build_summary(findings) == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert should_block(findings, block_on_critical=True, block_on_high=True)


def test_anchor_llm_cve_finding_to_dependency_line():
    diff = """diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -0,0 +1,1 @@
+flask==0.12
"""
    finding = ScanFinding(
        cwe="CVE",
        title="CVE-2025-47278: flask fallback key",
        severity="HIGH",
        file="unknown",
        line=1,
        code="",
        reason="Flask uses fallback key instead of current signing key",
        fix="Update Flask",
        fixed_example="flask>=3",
    )

    _anchor_llm_findings(diff, [finding])

    assert finding.file == "requirements.txt"
    assert finding.line == 1
    assert finding.code == "flask==0.12"


def test_anchor_llm_cve_finding_to_import_line():
    diff = """diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -0,0 +1,4 @@
+# safe_jwt_auth.py
+
+import jwt
+from flask import Flask, request, jsonify
"""
    finding = ScanFinding(
        cwe="CVE",
        title="CVE-2025-47278: flask fallback key",
        severity="HIGH",
        file="unknown",
        line=1,
        code="import jwt",
        reason="Flask uses fallback key instead of current signing key",
        fix="Update Flask",
        fixed_example="flask>=3",
    )

    _anchor_llm_findings(diff, [finding])

    assert finding.file == "test.py"
    assert finding.line == 4
    assert finding.code == "from flask import Flask, request, jsonify"
