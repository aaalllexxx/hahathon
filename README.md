# CodeGuardian AI

CodeGuardian AI — MVP защитной прослойки для Git-процесса разработки. Сервис принимает GitLab webhook-события, получает diff, запускает OWASP/CWE scanner, при необходимости валидирует findings через OpenAI-compatible LLM и показывает результат в админ-панели.

Проект сейчас стартует без тестовых данных. Таблицы, карточки и логи заполняются только реальными webhook-событиями, ручным подключением репозитория через UI или действиями пользователя в панели.

## Архитектура

- `gitlab` — локальный GitLab CE в Docker Compose.
- `codeguardian` — FastAPI backend, dashboard и REST API.
- `scanner` — IDS/IPS слой с правилами CWE-89, CWE-798, CWE-79, CWE-78, CWE-22, CWE-918 и другими.
- `llm` — reviewer через официальный SDK `openai`.
- `SQLite` — репозитории, проверки, findings, сообщения бота и audit logs.
- `dashboard` — экраны Дашборд, Проверки PR, Репозитории и Логи анализа.

## Быстрый запуск

```bash
cp .env.example .env
docker compose up -d
```

Откройте:

```text
http://localhost:8000
```

GitLab будет доступен на:

```text
http://localhost:8080
```

Первый старт GitLab может занять несколько минут.

## Настройка `.env`

Минимум для локального запуска:

```env
GITLAB_URL=http://localhost:8080
GITLAB_INTERNAL_URL=http://gitlab
GITLAB_PRIVATE_TOKEN=change-me
GITLAB_WEBHOOK_SECRET=super-secret-token
OPENAI_BASE_URL=http://localhost:1234/v1
OPENAI_API_KEY=change-me
OPENAI_MODEL=qwen2.5-coder-32b-instruct
SECURITY_BLOCK_ON_CRITICAL=true
SECURITY_BLOCK_ON_HIGH=true
SECURITY_USE_LLM=true
```

Если LLM пока не поднят, можно поставить:

```env
SECURITY_USE_LLM=false
```

Rule-based scanner продолжит работать.

Для обязательной проверки кода именно моделью оставьте:

```env
SECURITY_USE_LLM=true
SECURITY_REQUIRE_LLM_REVIEW=true
SECURITY_FAIL_CLOSED_ON_LLM_ERROR=true
```

Если AI API недоступен, проверка не будет молча помечена успешной: CodeGuardian создаст блокирующий finding `AI Reviewer Unavailable`.

## DeepSeek V4 / OpenAI-compatible API

CodeGuardian использует официальный Python SDK:

```python
from openai import OpenAI
```

Для DeepSeek V4 или другого OpenAI-compatible endpoint настройте:

```env
OPENAI_BASE_URL=https://your-openai-compatible-endpoint/v1
OPENAI_API_KEY=your-key
OPENAI_MODEL=deepseek-v4
OPENAI_TIMEOUT=60
OPENAI_TEMPERATURE=0.1
OPENAI_MAX_TOKENS=900
```

Промпты сделаны короткими: JSON-only для pre-push review, максимум 5 findings за проход, без chain-of-thought. Это быстрее и стабильнее для DeepSeek/OpenAI-compatible моделей.

## GitLab: первый вход

Root-пароль:

```bash
docker exec -it codeguardian-gitlab grep 'Password:' /etc/gitlab/initial_root_password
```

Войдите в `http://localhost:8080` под `root`, создайте Personal Access Token с правами `api` и укажите его в `.env` как `GITLAB_PRIVATE_TOKEN`.

После изменения `.env` перезапустите сервис:

```bash
docker compose up -d --build codeguardian
```

## Подключение репозитория

Есть два способа.

Через UI:

1. Откройте `http://localhost:8000`.
2. Перейдите в **Репозитории**.
3. Нажмите **Подключить репозиторий**.
4. Укажите `group/project`, URL проекта и GitLab project id.

Через скрипт webhook:

```bash
python scripts/create_gitlab_webhook.py <project_id>
```

Ручные настройки webhook в GitLab:

```text
URL: http://codeguardian:8000/webhooks/gitlab
Secret token: super-secret-token
Events: Push events, Merge request events
```

## Как пользоваться панелью

**Дашборд** показывает реальные KPI: количество проверок, найденные уязвимости, критичные findings, заблокированные PR, график за 7 дней и последние проверки.

**Проверки PR** повторяет экран из макетов: верхние карточки, фильтры по поиску, severity и статусу, таблица PR и правая панель деталей. Нажмите **Детали**, чтобы увидеть файл, строку, уязвимый фрагмент, комментарий бота, fix suggestion и диалог.

**Репозитории** показывает подключённые проекты, provider, ветку, webhook, merge protection и статус. Кнопка **Подключить репозиторий** создаёт запись в SQLite и пишет событие в журнал.

**Логи** показывает pipeline анализа: таблицу событий, цепочку обнаружения, raw log output, компоненты, фильтры и быстрые действия. Кнопки позволяют скопировать или экспортировать raw logs и открыть правую панель разбора инцидента.

**AI Assistant** открывается кликом по карточке ассистента внизу sidebar или через чат в деталях проверки. Можно спрашивать:

- почему проверка заблокирована;
- что значит конкретный CWE;
- как настроить GitLab webhook;
- что видно в логах;
- как исправить finding;
- безопасен ли вставленный фрагмент кода.

Чат использует tools CodeGuardian:

- `get_stats` — статистика проверок и findings;
- `get_check_context` — текущая или последняя проверка;
- `list_recent_checks` — последние проверки;
- `list_repositories` — подключённые репозитории;
- `list_audit_logs` — последние события pipeline;
- `scan_code_snippet` — быстрый scanner для вставленного кода;
- `query_cve_database` — запрос в OSV/CVE базу по зависимости `package==version`;
- `read_gitlab_file` — чтение файла из GitLab целиком или частично;
- `search_gitlab_regex` — regex-поиск по файлам репозитория;
- `explain_cwe` — объяснение CWE;
- `gitlab_setup_guide` — шаги настройки GitLab webhook;
- `integrity_status` — состояние контроля целостности MVP;
- `monitoring_status` — состояние API/БД/последнего события.

Каждый вызов tool пишется в **Логи** как `ai.tool.called`.

## Inline-комментарии в коде

Если проверка заблокирована, finding содержит `annotated_code`: CodeGuardian вставляет русские комментарии сразу после опасной строки и использует синтаксис языка файла:

```python
query = "SELECT * FROM users WHERE username = '" + username + "'"
# CodeGuardian AI: CWE-89 / SQL Injection (CRITICAL). SQL-запрос собирается через конкатенацию.
# Как исправить: Используйте параметризованные запросы.
```

Для JS/TS/Java/Go/C# используются `//`, для SQL — `--`, для HTML/XML — `<!-- -->`, для CSS — `/* */`.

## Проверка на опасном коде

Пример SQL injection:

```python
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)
```

CodeGuardian AI создаст finding `CWE-89`, предложит параметризованный запрос и пометит проверку как `blocked`, если включена блокировка CRITICAL/HIGH.

## Локальный pre-push scanner

```bash
python -m app.cli scan --staged
```

Для Git hook добавьте в `.git/hooks/pre-push`:

```bash
#!/usr/bin/env bash
python -m app.cli scan --staged
```

При блокирующей угрозе команда завершится с exit code `1`.

## REST API

```http
GET /api/checks
GET /api/checks/{id}
GET /api/repositories
POST /api/repositories
GET /api/stats
GET /api/logs
POST /api/chat
POST /api/checks/{id}/rerun
POST /api/checks/{id}/comment
POST /webhooks/gitlab
```

## Запуск без Docker

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python run.py
```

Откройте `http://localhost:8000`.

## Тесты

```bash
pip install -r requirements.txt
pytest
```

Покрыты SQL Injection, hardcoded secrets, XSS, OS command injection, path traversal, SSRF, insecure deserialization, weak crypto, diff parser и severity decision logic.

## Очистка данных

Локальная SQLite БД создаётся в `codeguardian.db`. Чтобы начать с чистого состояния:

```bash
Remove-Item .\codeguardian.db
```

Для Docker volume:

```bash
docker compose down -v
docker compose up -d --build
```

## Ограничения MVP

- Webhook обрабатывает push/MR после события. Для жёсткой pre-receive блокировки нужен GitLab server hook или обязательный status check.
- Время анализа отображается как `—`, пока не подключён отдельный трекинг длительности pipeline.
- Scanner rule-based и рассчитан на демонстрационные security-паттерны.
- SQLite подходит для MVP, для команды лучше PostgreSQL.

## Идеи развития

- Очередь фоновых задач для больших diff.
- GitLab approvals и protected branch policy.
- Контроль целостности репозитория по baseline hashes.
- SARIF export и отчёты для AppSec.
- MR comments с auto-fix suggestions.
