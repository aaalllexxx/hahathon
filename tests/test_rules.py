from app.scanner.engine import scan_diff


def wrap(code: str, path: str = "app.py") -> str:
    lines = "\n".join(f"+{line}" for line in code.strip("\n").splitlines())
    return f"""diff --git a/{path} b/{path}
--- a/{path}
+++ b/{path}
@@ -0,0 +1,10 @@
{lines}
"""


def test_detect_sql_injection_concat():
    diff = wrap(
        """
username = request.args["username"]
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)
"""
    )
    result = scan_diff(diff, use_llm=False)

    assert result.status == "blocked"
    assert result.findings[0].cwe == "CWE-89"


def test_detect_hardcoded_secret():
    result = scan_diff(wrap('API_TOKEN = "sk_live_4d91e2f8a9b0"'), use_llm=False)

    assert result.status == "blocked"
    assert any(finding.cwe == "CWE-798" for finding in result.findings)


def test_detect_xss_inner_html():
    result = scan_diff(wrap("element.innerHTML = userInput", path="static/app.js"), use_llm=False)

    assert result.status == "blocked"
    assert any(finding.cwe == "CWE-79" for finding in result.findings)


def test_detect_os_command_injection():
    result = scan_diff(wrap("subprocess.run(command, shell=True)"), use_llm=False)

    assert result.status == "blocked"
    assert any(finding.cwe == "CWE-78" for finding in result.findings)


def test_detect_path_traversal():
    result = scan_diff(wrap('open(request.args["file"])'), use_llm=False)

    assert result.status == "blocked"
    assert any(finding.cwe == "CWE-22" for finding in result.findings)


def test_detect_ssrf():
    result = scan_diff(wrap('requests.get(request.args["url"])'), use_llm=False)

    assert result.status == "blocked"
    assert any(finding.cwe == "CWE-918" for finding in result.findings)


def test_detect_insecure_deserialization():
    result = scan_diff(wrap("pickle.loads(request.data)"), use_llm=False)

    assert result.status == "blocked"
    assert any(finding.cwe == "CWE-502" for finding in result.findings)


def test_detect_weak_crypto_for_passwords():
    result = scan_diff(wrap("digest = hashlib.md5(password.encode()).hexdigest()"), use_llm=False)

    assert result.status == "blocked"
    assert any(finding.cwe == "CWE-327" for finding in result.findings)

