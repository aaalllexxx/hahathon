from app.llm.tools import explain_cwe, scan_code_snippet, select_tools
from app.scanner.annotations import annotate_vulnerable_line
from app.scanner.cve_checker import parse_dependencies_from_diff


def test_chat_tool_scans_code_snippet():
    result = scan_code_snippet('query = "SELECT * FROM users WHERE id = " + request.args["id"]')

    assert result["scanned"] is True
    assert result["status"] == "blocked"
    assert result["findings"][0]["cwe"] == "CWE-89"


def test_explain_cwe_filters_requested_code():
    result = explain_cwe("что такое CWE-918")

    assert "CWE-918" in result["items"]
    assert "CWE-89" not in result["items"]


def test_select_tools_for_gitlab_and_code_question():
    tools = select_tools("как настроить webhook и проверить код SELECT")

    assert "gitlab_setup_guide" in tools
    assert "scan_code_snippet" in tools


def test_select_tools_for_dependency_version():
    tools = select_tools("проверь django==1.2")

    assert "query_cve_database" in tools


def test_annotation_uses_python_comments():
    class Finding:
        cwe = "CWE-89"
        title = "SQL Injection"
        severity = "CRITICAL"
        reason = "SQL собирается через конкатенацию."
        fix = "Используйте параметры запроса."
        fixed_example = ""
        file = "auth/login.py"

    annotated = annotate_vulnerable_line("query = 'SELECT ' + user", "auth/login.py", Finding())

    assert "# CodeGuardian AI: CWE-89" in annotated
    assert "# Как исправить:" in annotated


def test_parse_dependencies_from_diff_for_osv_tool():
    diff = """diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -0,0 +1,1 @@
+django==1.2
"""
    dependencies = parse_dependencies_from_diff(diff)

    assert dependencies[0].name == "django"
    assert dependencies[0].version == "1.2"
    assert dependencies[0].ecosystem == "PyPI"
