from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import PurePosixPath
import re

from app.config import settings
from app.scanner.cve_checker import cve_findings_from_diff, parse_dependencies_from_diff
from app.scanner.diff_parser import parse_unified_diff
from app.scanner.rules import RuleMatch, detect_findings
from app.scanner.severity import build_summary, highest_severity, should_block


IGNORED_SUFFIXES = {
    ".md",
    ".rst",
    ".txt",
    ".lock",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
}
IGNORED_NAMES = {".env.example", "README.md"}
IGNORED_PARTS = {"tests", "test", "docs", "materilals", "materials"}


@dataclass(slots=True)
class ScanFinding:
    cwe: str
    title: str
    severity: str
    file: str
    line: int
    code: str
    reason: str
    fix: str
    fixed_example: str
    exploitable: bool = True
    llm_verdict: str | None = None
    llm_confidence: float | None = None
    llm_explanation: str | None = None

    @classmethod
    def from_rule_match(cls, match: RuleMatch) -> "ScanFinding":
        return cls(**asdict(match))

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    status: str
    summary: dict[str, int]
    severity: str
    findings: list[ScanFinding]

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "summary": self.summary,
            "severity": self.severity,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


def _is_ignored_path(path: str) -> bool:
    pure = PurePosixPath(path.replace("\\", "/"))
    if pure.name in IGNORED_NAMES:
        return True
    if pure.suffix.lower() in IGNORED_SUFFIXES:
        return True
    return any(part in IGNORED_PARTS for part in pure.parts)


def _deduplicate(findings: list[ScanFinding]) -> list[ScanFinding]:
    seen: set[tuple[str, str, int, str]] = set()
    unique: list[ScanFinding] = []
    for finding in findings:
        key = (finding.cwe, finding.file, finding.line, finding.code)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _review_with_llm(diff_text: str, findings: list[ScanFinding]) -> None:
    if not findings:
        return
    try:
        from app.llm.reviewer import review_findings

        reviews = review_findings(diff_text=diff_text, findings=findings)
    except Exception as exc:  # pragma: no cover - network/service dependent
        for finding in findings:
            finding.llm_verdict = "UNAVAILABLE"
            finding.llm_explanation = f"LLM reviewer недоступен: {exc}"
        return

    for finding, review in zip(findings, reviews, strict=False):
        finding.llm_verdict = review.get("verdict")
        confidence = review.get("confidence")
        finding.llm_confidence = float(confidence) if isinstance(confidence, int | float) else None
        finding.llm_explanation = review.get("explanation")
        if review.get("safe_fix"):
            finding.fix = str(review["safe_fix"])
        if review.get("fixed_code"):
            finding.fixed_example = str(review["fixed_code"])


def _llm_finding_to_scan_finding(item: dict[str, object]) -> ScanFinding | None:
    verdict = str(item.get("verdict") or "WARN").upper()
    if verdict == "PASS":
        return None
    severity = str(item.get("severity") or ("CRITICAL" if verdict == "BLOCK" else "MEDIUM")).upper()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        severity = "HIGH" if verdict == "BLOCK" else "MEDIUM"
    confidence = item.get("confidence")
    try:
        line = int(item.get("line") or 1)
    except (TypeError, ValueError):
        line = 1
    return ScanFinding(
        cwe=str(item.get("cwe") or "CWE-UNKNOWN"),
        title=str(item.get("title") or "AI Security Finding"),
        severity=severity,
        file=str(item.get("file") or "unknown"),
        line=line,
        code=str(item.get("code") or ""),
        reason=str(item.get("reason") or item.get("explanation") or "AI reviewer detected a potentially exploitable security issue."),
        fix=str(item.get("safe_fix") or item.get("fix") or "Review and replace the dangerous pattern with a safe implementation."),
        fixed_example=str(item.get("fixed_code") or item.get("fixed_example") or ""),
        exploitable=verdict == "BLOCK" or severity in {"CRITICAL", "HIGH"},
        llm_verdict=verdict,
        llm_confidence=float(confidence) if isinstance(confidence, int | float) else None,
    )


def _needs_diff_anchor(finding: ScanFinding) -> bool:
    return finding.file in {"", "unknown", "diff"} or not finding.line


ANCHOR_STOPWORDS = {
    "cve",
    "cwe",
    "high",
    "medium",
    "critical",
    "warning",
    "uses",
    "instead",
    "current",
    "signing",
    "found",
    "detected",
    "vulnerability",
    "vulnerable",
    "dependency",
    "security",
    "review",
}


def _anchor_tokens(finding: ScanFinding) -> set[str]:
    haystack = " ".join(
        [
            finding.title,
            finding.reason,
            finding.fix,
            finding.fixed_example,
            finding.code,
        ]
    ).lower()
    tokens: set[str] = set()
    for raw_token in re.findall(r"[a-zа-я0-9_.:-]{3,}", haystack, flags=re.IGNORECASE):
        for token in re.split(r"[_.:-]+", raw_token):
            token = token.strip().lower()
            if len(token) >= 4 and token not in ANCHOR_STOPWORDS and not token.isdigit():
                tokens.add(token)
    return tokens


def _package_hints(finding: ScanFinding) -> list[str]:
    haystack = " ".join([finding.title, finding.reason, finding.fix, finding.fixed_example]).lower()
    hints: list[str] = []
    patterns = [
        r"cve-\d{4}-\d+:\s*([@a-z0-9_.-]+)",
        r"vulnerable dependency:\s*([@a-z0-9_.-]+)",
        r"(?:package|library|библиотека|пакет)\s+([@a-z0-9_.-]+)",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, haystack, flags=re.IGNORECASE):
            name = match.group(1).strip(" .,:;()[]{}").lower()
            if len(name) >= 3 and name not in ANCHOR_STOPWORDS and name not in hints:
                hints.append(name)
    return hints


def _matches_python_import(content_lower: str, package_name: str) -> bool:
    module = package_name.replace("-", "_").split(".")[0]
    return (
        content_lower == f"import {module}"
        or content_lower.startswith(f"import {module} ")
        or content_lower.startswith(f"import {module}.")
        or content_lower.startswith(f"from {module} import")
        or content_lower.startswith(f"from {module}.")
    )


def _anchor_to_package_import(diff_files: list, finding: ScanFinding, package_name: str) -> bool:
    for diff_file in diff_files:
        for line in diff_file.additions:
            content = line.content.strip()
            if _matches_python_import(content.lower(), package_name):
                finding.file = diff_file.path
                finding.line = line.number
                finding.code = content
                return True
    return False


def _anchor_llm_findings(diff_text: str, llm_findings: list[ScanFinding]) -> None:
    dependencies = parse_dependencies_from_diff(diff_text)
    diff_files = parse_unified_diff(diff_text)

    for finding in llm_findings:
        if not _needs_diff_anchor(finding) or finding.cwe == "AI-REVIEW":
            continue

        haystack = " ".join(
            [
                finding.title,
                finding.reason,
                finding.fix,
                finding.fixed_example,
                finding.code,
            ]
        ).lower()
        tokens = _anchor_tokens(finding)
        package_hints = _package_hints(finding)

        for dep in dependencies:
            dep_name = dep.name.lower()
            if dep_name in haystack or dep_name in package_hints:
                finding.file = dep.file
                finding.line = dep.line
                finding.code = dep.raw.strip()
                if "dependency" not in finding.reason.lower() and "зависим" not in finding.reason.lower():
                    finding.reason = f"{finding.reason} Найдено в зависимости {dep.name}=={dep.version}."
                break

        if not _needs_diff_anchor(finding):
            continue

        for package_name in package_hints:
            if _anchor_to_package_import(diff_files, finding, package_name):
                break

        if not _needs_diff_anchor(finding):
            continue

        code_hint = finding.code.strip().lower()
        import_name = ""
        if code_hint.startswith("import "):
            import_name = code_hint.removeprefix("import ").split()[0].split(".")[0]
        elif code_hint.startswith("from "):
            import_name = code_hint.removeprefix("from ").split()[0].split(".")[0]

        for diff_file in diff_files:
            for line in diff_file.additions:
                content = line.content.strip()
                content_lower = content.lower()
                if import_name and (
                    content_lower.startswith(f"import {import_name}")
                    or content_lower.startswith(f"from {import_name}")
                ):
                    finding.file = diff_file.path
                    finding.line = line.number
                    finding.code = content
                    break
                if tokens and any(token in content_lower for token in tokens):
                    finding.file = diff_file.path
                    finding.line = line.number
                    finding.code = content
                    break
            if not _needs_diff_anchor(finding):
                break


def _review_diff_with_llm(diff_text: str, findings: list[ScanFinding]) -> list[ScanFinding]:
    try:
        from app.llm.reviewer import review_diff

        review = review_diff(diff_text=diff_text, scanner_findings=findings)
        llm_findings = [
            converted
            for item in review.get("findings", [])
            if isinstance(item, dict)
            for converted in [_llm_finding_to_scan_finding(item)]
            if converted is not None
        ]
        _anchor_llm_findings(diff_text, llm_findings)
        for finding in findings:
            finding.llm_verdict = finding.llm_verdict or "REVIEWED"
        return llm_findings
    except Exception as exc:  # pragma: no cover - external LLM dependent
        for finding in findings:
            finding.llm_verdict = "UNAVAILABLE"
            finding.llm_explanation = f"LLM reviewer недоступен: {exc}"
        if settings.SECURITY_FAIL_CLOSED_ON_LLM_ERROR:
            return [
                ScanFinding(
                    cwe="AI-REVIEW",
                    title="AI Reviewer Unavailable",
                    severity="HIGH",
                    file="diff",
                    line=1,
                    code="",
                    reason=f"Обязательная AI-проверка не завершилась: {exc}",
                    fix="Проверьте OPENAI_BASE_URL, OPENAI_API_KEY, OPENAI_MODEL и доступность DeepSeek/OpenAI-compatible API.",
                    fixed_example="SECURITY_USE_LLM=true; OPENAI_MODEL=deepseek-v4",
                    exploitable=True,
                    llm_verdict="UNAVAILABLE",
                )
            ]
        return []


# ── CVE pattern rules (always active, independent of LLM) ──
CVE_PATTERNS: list[tuple[str, str, str, str, str, str, str]] = [
    # (regex, cwe, title, severity, reason, fix, fixed_code)
    (r"\bzipfile\.Path\b",
     "CVE", "CVE-2024-8088: zipfile.Path DoS via infinite loop", "HIGH",
     "zipfile.Path().iterdir() может уйти в бесконечный цикл на специально сформированном ZIP-архиве (CVE-2024-8088).",
     "Используйте zipfile.ZipFile.namelist() вместо zipfile.Path или обновите Python >= 3.12.5.",
     "with zipfile.ZipFile(path) as zf:\n    for name in zf.namelist():\n        print(name)"),
    (r"\btarfile\.(extract|extractall)\s*\(",
     "CVE", "CVE-2007-4559: tarfile path traversal", "HIGH",
     "tarfile.extractall() без фильтра допускает path traversal через ../../ в именах файлов.",
     "Используйте параметр filter='data' (Python 3.12+) или вручную проверяйте имена файлов.",
     "tar.extractall(path, filter='data')"),
    (r"\bpickle\.(loads?|Unpickler)\s*\(",
     "CWE-502", "CVE-2024-pickle: Insecure deserialization via pickle", "CRITICAL",
     "pickle.load/loads выполняет произвольный код при десериализации недоверенных данных.",
     "Используйте json, msgpack или другой безопасный формат.",
     "data = json.loads(payload)"),
    (r"\byaml\.load\s*\([^)]*\)(?!.*SafeLoader|.*safe_load)",
     "CWE-502", "CVE-2020-1747: Unsafe YAML loading", "CRITICAL",
     "yaml.load() без SafeLoader допускает выполнение произвольного кода.",
     "Используйте yaml.safe_load() или Loader=yaml.SafeLoader.",
     "data = yaml.safe_load(payload)"),
    (r"\beval\s*\([^)]*(?:request|input|argv|query|params|body)",
     "CWE-94", "Code Injection via eval()", "CRITICAL",
     "eval() выполняет произвольный код из пользовательского ввода.",
     "Не используйте eval() с недоверенными данными.",
     "result = ast.literal_eval(user_input)"),
    (r"\btempfile\.mktemp\s*\(",
     "CWE-377", "CVE-tempfile: Race condition in mktemp", "MEDIUM",
     "tempfile.mktemp() создаёт предсказуемое имя файла, допускающее race condition.",
     "Используйте tempfile.mkstemp() или tempfile.NamedTemporaryFile().",
     "fd, path = tempfile.mkstemp()"),
    (r"verify\s*=\s*False",
     "CWE-295", "TLS certificate verification disabled", "HIGH",
     "Отключение проверки сертификатов делает соединение уязвимым к MitM-атакам.",
     "Не отключайте verify. Используйте verify=True или укажите путь к CA bundle.",
     "requests.get(url, verify=True)"),
]


def _scan_cve_patterns(diff_text: str) -> list[ScanFinding]:
    """Scan diff for known CVE-affected code patterns using regex."""
    import re as _re
    findings: list[ScanFinding] = []
    for diff_file in parse_unified_diff(diff_text):
        if _is_ignored_path(diff_file.path):
            continue
        for line_obj in diff_file.scan_lines or diff_file.additions:
            for pattern, cwe, title, severity, reason, fix, fixed_code in CVE_PATTERNS:
                if _re.search(pattern, line_obj.content):
                    findings.append(ScanFinding(
                        cwe=cwe, title=title, severity=severity,
                        file=diff_file.path, line=line_obj.number,
                        code=line_obj.content.strip(),
                        reason=reason, fix=fix, fixed_example=fixed_code,
                        exploitable=True, llm_verdict="BLOCK",
                    ))
    return findings


def scan_diff(diff_text: str, *, use_llm: bool | None = None) -> ScanResult:
    if not diff_text.strip():
        return ScanResult(status="passed", summary=build_summary([]), severity="LOW", findings=[])

    limited_diff = diff_text[: settings.SECURITY_MAX_DIFF_CHARS]
    findings: list[ScanFinding] = []

    if use_llm is None:
        use_llm = settings.SECURITY_USE_LLM

    findings.extend(_scan_cve_patterns(limited_diff))
    for diff_file in parse_unified_diff(limited_diff):
        if _is_ignored_path(diff_file.path):
            continue
        findings.extend(ScanFinding.from_rule_match(match) for match in detect_findings(diff_file))

    # LLM review is mandatory when enabled, but static rules always remain active.
    if use_llm:
        findings.extend(_review_diff_with_llm(limited_diff, findings))

    if settings.CVE_ENABLE:
        try:
            findings.extend(
                ScanFinding(
                    cwe=item.cwe,
                    title=item.title,
                    severity=item.severity,
                    file=item.file,
                    line=item.line,
                    code=item.code,
                    reason=item.reason,
                    fix=item.fix,
                    fixed_example=item.fixed_example,
                    exploitable=item.severity in {"CRITICAL", "HIGH"},
                    llm_verdict="CVE_TOOL",
                )
                for item in cve_findings_from_diff(limited_diff)
            )
        except Exception as exc:
            findings.append(
                ScanFinding(
                    cwe="CVE-TOOL",
                    title="CVE Database Unavailable",
                    severity="MEDIUM",
                    file="dependency-diff",
                    line=1,
                    code="",
                    reason=f"CVE/OSV база недоступна: {exc}",
                    fix="Проверьте CVE_OSV_API_URL, сеть контейнера и повторите проверку.",
                    fixed_example="CVE_OSV_API_URL=https://api.osv.dev",
                    exploitable=False,
                    llm_verdict="CVE_UNAVAILABLE",
                )
            )

    _anchor_llm_findings(limited_diff, findings)
    findings = _deduplicate(findings)

    summary = build_summary(findings)
    severity = highest_severity([finding.severity for finding in findings])
    blocked = should_block(
        findings,
        block_on_critical=settings.SECURITY_BLOCK_ON_CRITICAL,
        block_on_high=settings.SECURITY_BLOCK_ON_HIGH,
        block_on_warning=getattr(settings, "SECURITY_BLOCK_ON_WARNING", False),
    )
    status = "blocked" if blocked else ("warning" if findings else "passed")
    return ScanResult(status=status, summary=summary, severity=severity, findings=findings)
