from __future__ import annotations

from dataclasses import dataclass
import re

from app.scanner.diff_parser import DiffFile


@dataclass(slots=True)
class RuleMatch:
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


SQL_RE = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|REPLACE|DROP|ALTER)\b", re.IGNORECASE)
SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b[A-Za-z0-9_.-]*(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|connection[_-]?string)"
    r"[A-Za-z0-9_.-]*\b\s*[:=]\s*[rubfRUBF]*(['\"])([^'\"]{6,})\2"
)
CONNECTION_STRING_RE = re.compile(r"(['\"])[a-z][a-z0-9+.-]*://[^/\s:'\"]+:[^@\s'\"]+@[^'\"]+\1", re.IGNORECASE)
CRYPTO_KEY_RE = re.compile(
    r"(?i)\b(aes_key|crypto_key|encryption_key|secret_key|private_key|fixed_iv|iv|salt)\b"
    r"\s*[:=]\s*[rubfRUBF]*(['\"])([^'\"]{8,})\2"
)
USER_INPUT_RE = re.compile(
    r"(?i)(request\.|req\.|params|query|form|body|cookies|headers|user_input|userinput|input\(|argv|location\.|document\.location)"
)
URL_VAR_RE = re.compile(r"(?i)(url|uri|callback|redirect|target|next|webhook)")

PLACEHOLDER_VALUES = {
    "change-me",
    "changeme",
    "your-api-key",
    "your-secret",
    "replace-me",
    "example",
    "dummy",
}


def _match(
    *,
    cwe: str,
    title: str,
    severity: str,
    file: str,
    line: int,
    code: str,
    reason: str,
    fix: str,
    fixed_example: str,
    exploitable: bool = True,
) -> RuleMatch:
    return RuleMatch(
        cwe=cwe,
        title=title,
        severity=severity,
        file=file,
        line=line,
        code=code.strip(),
        reason=reason,
        fix=fix,
        fixed_example=fixed_example,
        exploitable=exploitable,
    )


def _has_user_input(line: str) -> bool:
    return bool(USER_INPUT_RE.search(line))


def _lines_to_scan(file: DiffFile):
    return file.scan_lines or file.additions


def _looks_dynamic(line: str) -> bool:
    stripped = line.strip()
    return (
        " + " in line
        or '"+' in line
        or "+'" in line
        or '" +' in line
        or "' +" in line
        or re.search(r"(^|[=\(\s])f(['\"])", stripped)
        or ".format(" in line
        or "${" in line
        or "createStatement(" in line
    )


def detect_sql_injection(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        if SQL_RE.search(line) and _looks_dynamic(line):
            findings.append(
                _match(
                    cwe="CWE-89",
                    title="SQL Injection",
                    severity="CRITICAL",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="SQL-запрос собирается динамически через конкатенацию, f-string или форматирование. Пользовательский ввод может изменить структуру запроса.",
                    fix="Используйте параметризованные запросы или prepared statements.",
                    fixed_example='cursor.execute("SELECT * FROM users WHERE username = ?", (username,))',
                )
            )
        elif re.search(r"\bexecute(Query)?\(", line) and SQL_RE.search(line) and ("+" in line or _has_user_input(line)):
            findings.append(
                _match(
                    cwe="CWE-89",
                    title="SQL Injection",
                    severity="CRITICAL",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="SQL выполняется с динамически собранным выражением, что допускает SQL-инъекцию.",
                    fix="Передавайте данные отдельно от SQL-шаблона.",
                    fixed_example='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                )
            )
    return findings


def detect_hardcoded_credentials(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        secret_match = SECRET_ASSIGN_RE.search(line)
        connection_match = CONNECTION_STRING_RE.search(line)
        if not secret_match and not connection_match:
            continue
        value = secret_match.group(3).strip().lower() if secret_match else ""
        if value in PLACEHOLDER_VALUES:
            continue
        findings.append(
            _match(
                cwe="CWE-798",
                title="Hardcoded Credentials",
                severity="CRITICAL",
                file=file.path,
                line=added.number,
                code=line,
                reason="Секрет или пароль записан строковым литералом в коде и может попасть в репозиторий.",
                fix="Перенесите секрет в переменные окружения или защищённое хранилище секретов.",
                fixed_example='api_key = os.environ["SERVICE_API_KEY"]',
            )
        )
    return findings


def detect_hardcoded_crypto_key(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        if CRYPTO_KEY_RE.search(line):
            findings.append(
                _match(
                    cwe="CWE-321",
                    title="Hardcoded Cryptographic Key",
                    severity="CRITICAL",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="Криптографический ключ, IV или salt зафиксирован в исходном коде.",
                    fix="Генерируйте ключи безопасно и храните их вне репозитория.",
                    fixed_example='aes_key = os.environ["AES_KEY"].encode("utf-8")',
                )
            )
    return findings


def detect_xss(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    patterns = [
        r"\.(innerHTML|outerHTML)\s*=",
        r"\bdocument\.write\s*\(",
        r"\bdangerouslySetInnerHTML\b",
        r"\bHtml\.Raw\s*\(",
        r"\bautoescape\s*=\s*(False|false)",
    ]
    for added in _lines_to_scan(file):
        line = added.content
        if any(re.search(pattern, line) for pattern in patterns):
            findings.append(
                _match(
                    cwe="CWE-79",
                    title="Cross-Site Scripting",
                    severity="HIGH",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="HTML формируется из потенциально недоверенного ввода без безопасного экранирования.",
                    fix="Используйте textContent, DOM API или безопасное шаблонизирование с включённым escaping.",
                    fixed_example="element.textContent = userInput",
                )
            )
    return findings


def detect_os_command_injection(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        risky = (
            re.search(r"\bos\.system\s*\(", line)
            or re.search(r"\bsubprocess\.(run|Popen|call)\s*\(.*shell\s*=\s*True", line)
            or re.search(r"\bchild_process\.exec\s*\(", line)
            or re.search(r"\bRuntime\.getRuntime\(\)\.exec\s*\(", line)
        )
        if risky:
            findings.append(
                _match(
                    cwe="CWE-78",
                    title="OS Command Injection",
                    severity="CRITICAL",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="Команда ОС выполняется через shell или с недоверенным вводом.",
                    fix="Передавайте аргументы списком без shell=True и валидируйте разрешённые значения.",
                    fixed_example='subprocess.run(["git", "status"], check=True)',
                )
            )
    return findings


def detect_path_traversal(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        risky = (
            re.search(r"\bopen\s*\(\s*(request\.|req\.|user_|.*input)", line, re.IGNORECASE)
            or re.search(r"\bfs\.readFile\s*\(\s*(req\.|request\.|user_|.*path)", line, re.IGNORECASE)
            or re.search(r"\bFile\.ReadAllText\s*\(\s*(userInput|Request\.)", line)
            or re.search(r"\bsend_file\s*\(\s*(request\.|user_)", line, re.IGNORECASE)
        )
        if risky:
            findings.append(
                _match(
                    cwe="CWE-22",
                    title="Path Traversal",
                    severity="HIGH",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="Путь к файлу берётся из пользовательского ввода без нормализации и allowlist.",
                    fix="Нормализуйте путь, ограничьте базовую директорию и используйте allowlist файлов.",
                    fixed_example='safe_path = (BASE_DIR / filename).resolve(); assert safe_path.is_relative_to(BASE_DIR)',
                )
            )
    return findings


def detect_ssrf(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        call = re.search(r"\b(requests|httpx)\.(get|post|put|delete|request)\s*\(([^)]*)", line)
        js_fetch = re.search(r"\bfetch\s*\(([^)]*)", line)
        if not call and not js_fetch:
            continue
        first_arg = (call.group(3) if call else js_fetch.group(1)).split(",", 1)[0].strip()
        if first_arg.startswith(("'", '"')):
            continue
        if _has_user_input(first_arg) or URL_VAR_RE.search(first_arg):
            findings.append(
                _match(
                    cwe="CWE-918",
                    title="Server-Side Request Forgery",
                    severity="HIGH",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="Сервер выполняет HTTP-запрос по URL из пользовательского ввода.",
                    fix="Проверяйте URL по allowlist доменов и запрещайте private/link-local адреса.",
                    fixed_example='if parsed.hostname in ALLOWED_HOSTS: response = httpx.get(url, timeout=5)',
                )
            )
    return findings


def detect_insecure_deserialization(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        risky = (
            re.search(r"\bpickle\.loads?\s*\(", line)
            or (re.search(r"\byaml\.load\s*\(", line) and "SafeLoader" not in line and "safe_load" not in line)
            or "BinaryFormatter" in line
            or "ObjectInputStream" in line
            or "TypeNameHandling.All" in line
        )
        if risky:
            findings.append(
                _match(
                    cwe="CWE-502",
                    title="Insecure Deserialization",
                    severity="CRITICAL",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="Недоверенные данные десериализуются небезопасным механизмом, который может выполнить код.",
                    fix="Используйте безопасный формат данных и safe_load/валидаторы схемы.",
                    fixed_example="data = yaml.safe_load(payload)",
                )
            )
    return findings


def detect_xxe(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        risky = (
            "DocumentBuilderFactory.newInstance()" in line
            or "SAXParserFactory.newInstance()" in line
            or re.search(r"\betree\.XMLParser\s*\(.*resolve_entities\s*=\s*True", line)
            or re.search(r"\bxml\.sax\.make_parser\s*\(", line)
        )
        if risky:
            findings.append(
                _match(
                    cwe="CWE-611",
                    title="XML External Entity",
                    severity="HIGH",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="XML-парсер создаётся без явного запрета external entities.",
                    fix="Отключите DTD, external entities и сетевые загрузки в XML-парсере.",
                    fixed_example="parser = etree.XMLParser(resolve_entities=False, no_network=True)",
                )
            )
    return findings


def detect_weak_crypto(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        weak_hash_for_secret = re.search(r"\bhashlib\.(md5|sha1)\s*\(", line) and re.search(
            r"(?i)(password|passwd|secret|token)", line
        )
        risky = (
            weak_hash_for_secret
            or re.search(r"\b(DES|RC4|ARC4)\b", line)
            or "MODE_ECB" in line
            or re.search(r'Cipher\.getInstance\s*\(\s*["\'](DES|.*ECB)', line)
            or re.search(r"\brandom\.(random|randint|choice)\s*\(.*(token|secret|password)", line, re.IGNORECASE)
        )
        if risky:
            findings.append(
                _match(
                    cwe="CWE-327",
                    title="Weak Cryptography",
                    severity="HIGH",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="Используется слабый криптографический алгоритм или небезопасный режим.",
                    fix="Для паролей используйте Argon2/bcrypt/scrypt, для симметричного шифрования - AES-GCM.",
                    fixed_example="password_hash = pwd_context.hash(password)",
                )
            )
    return findings


def detect_open_redirect(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        risky = (
            re.search(r"\bredirect\s*\(\s*(request\.|req\.|user_|.*url)", line, re.IGNORECASE)
            or re.search(r"\bres\.redirect\s*\(\s*req\.", line)
            or re.search(r"\bResponse\.Redirect\s*\(\s*(userInput|Request\.)", line)
        )
        if risky:
            findings.append(
                _match(
                    cwe="CWE-601",
                    title="Open Redirect",
                    severity="MEDIUM",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="Редирект использует URL из недоверенного ввода.",
                    fix="Разрешайте только относительные пути или allowlist доменов.",
                    fixed_example='return redirect("/dashboard")',
                    exploitable=False,
                )
            )
    return findings


def detect_nosql_injection(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        risky = (
            "$where" in line
            or re.search(r"\bfind(_one)?\s*\(\s*(req\.body|request\.json|request\.get_json\(\))", line)
            or re.search(r"\bupdate(_one|Many)?\s*\(\s*(req\.body|request\.json)", line)
        )
        if risky:
            findings.append(
                _match(
                    cwe="CWE-943",
                    title="NoSQL Injection",
                    severity="HIGH",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="Mongo/NoSQL-запрос строится напрямую из пользовательского объекта.",
                    fix="Используйте whitelist полей и явно собирайте фильтр запроса.",
                    fixed_example='query = {"email": str(payload["email"])}',
                )
            )
    return findings


def detect_csrf(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        post_route = (
            re.search(r"@app\.route\(.*methods\s*=\s*\[.*['\"]POST['\"]", line)
            or re.search(r"router\.(post|put|delete)\s*\(", line)
            or re.search(r"app\.(post|put|delete)\s*\(", line)
        )
        if post_route and "csrf" not in line.lower():
            findings.append(
                _match(
                    cwe="CWE-352",
                    title="Cross-Site Request Forgery",
                    severity="MEDIUM",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="Изменяющий состояние endpoint объявлен без видимой CSRF-защиты.",
                    fix="Добавьте CSRF-токен, SameSite cookies или другую защиту для браузерных сессий.",
                    fixed_example='@csrf.exempt  # only for API tokens; otherwise require CSRF token',
                    exploitable=False,
                )
            )
    return findings


def detect_log_injection(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        risky = re.search(r"\b(logger|logging)\.(info|warning|error|critical|debug)\s*\(.*(request\.|req\.|user_input|input\()", line)
        if risky:
            findings.append(
                _match(
                    cwe="CWE-117",
                    title="Log Injection",
                    severity="MEDIUM",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="Недоверенный ввод попадает в логи без нормализации переносов строк.",
                    fix="Нормализуйте управляющие символы или логируйте структурированные поля.",
                    fixed_example='logger.info("login failed", extra={"username": clean_username})',
                    exploitable=False,
                )
            )
    return findings


def detect_information_exposure(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for added in _lines_to_scan(file):
        line = added.content
        risky = (
            re.search(r"\breturn\s+str\((e|ex|exception)\)", line, re.IGNORECASE)
            or "traceback.format_exc()" in line
            or "return traceback" in line
            or "ex.ToString()" in line
            or "debug=True" in line
        )
        if risky:
            findings.append(
                _match(
                    cwe="CWE-209",
                    title="Information Exposure Through Error Message",
                    severity="MEDIUM",
                    file=file.path,
                    line=added.number,
                    code=line,
                    reason="Ответ может раскрыть стек вызовов или внутренние детали приложения.",
                    fix="Возвращайте пользователю нейтральную ошибку, а детали пишите в защищённые логи.",
                    fixed_example='raise HTTPException(status_code=500, detail="Internal server error")',
                    exploitable=False,
                )
            )
    return findings


RULES = [
    detect_sql_injection,
    detect_hardcoded_credentials,
    detect_hardcoded_crypto_key,
    detect_xss,
    detect_os_command_injection,
    detect_path_traversal,
    detect_ssrf,
    detect_insecure_deserialization,
    detect_xxe,
    detect_weak_crypto,
    detect_open_redirect,
    detect_nosql_injection,
    detect_csrf,
    detect_log_injection,
    detect_information_exposure,
]


def detect_findings(file: DiffFile) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    for rule in RULES:
        findings.extend(rule(file))
    return findings
