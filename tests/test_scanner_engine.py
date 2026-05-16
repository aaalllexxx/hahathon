from app.scanner.engine import ScanFinding, scan_diff
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
