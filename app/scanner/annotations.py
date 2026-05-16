from __future__ import annotations

from pathlib import PurePosixPath


SLASH_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cc", ".cpp", ".cs", ".go", ".php",
    ".swift", ".kt", ".kts", ".rs", ".scala", ".dart",
}
HASH_EXTENSIONS = {".py", ".rb", ".sh", ".bash", ".zsh", ".ps1", ".yaml", ".yml", ".toml", ".ini", ".conf"}
SQL_EXTENSIONS = {".sql"}
HTML_EXTENSIONS = {".html", ".htm", ".xml", ".vue"}
CSS_EXTENSIONS = {".css", ".scss", ".less"}


def _extension(file_path: str) -> str:
    return PurePosixPath(file_path.replace("\\", "/")).suffix.lower()


def _comment_lines(file_path: str, messages: list[str]) -> list[str]:
    ext = _extension(file_path)
    if ext in SQL_EXTENSIONS:
        return [f"-- {message}" for message in messages]
    if ext in SLASH_EXTENSIONS:
        return [f"// {message}" for message in messages]
    if ext in HTML_EXTENSIONS:
        return [f"<!-- {message} -->" for message in messages]
    if ext in CSS_EXTENSIONS:
        return [f"/* {message} */" for message in messages]
    return [f"# {message}" for message in messages]


def build_inline_comment(finding: object) -> str:
    cwe = getattr(finding, "cwe", "CWE")
    title = getattr(finding, "title", "Security issue")
    severity = getattr(finding, "severity", "HIGH")
    reason = str(getattr(finding, "reason", "") or "Найдена потенциально эксплуатируемая уязвимость.").strip()
    fix = str(getattr(finding, "fix", "") or getattr(finding, "fixed_example", "") or "Исправьте опасный паттерн безопасной конструкцией.").strip()
    messages = [
        f"CodeGuardian AI: {cwe} / {title} ({severity}). {reason}",
        f"Как исправить: {fix}",
    ]
    return "\n".join(_comment_lines(str(getattr(finding, "file", "") or ""), messages))


def annotate_vulnerable_line(code: str, file_path: str, finding: object) -> str:
    code = (code or "").rstrip()
    comment = build_inline_comment(finding)
    if not code:
        return comment
    return f"{code}\n{comment}"
