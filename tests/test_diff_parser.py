from app.scanner.diff_parser import parse_unified_diff


def test_parse_added_lines_with_file_and_line_numbers():
    diff = """diff --git a/auth/login.py b/auth/login.py
--- a/auth/login.py
+++ b/auth/login.py
@@ -20,2 +20,4 @@
 context
+ username = request.args["username"]
+ query = "SELECT * FROM users WHERE username = '" + username + "'"
"""
    files = parse_unified_diff(diff)

    assert len(files) == 1
    assert files[0].path == "auth/login.py"
    assert files[0].additions[0].number == 21
    assert files[0].additions[1].content.startswith(" query =")

