from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.config import settings
from app.llm.client import get_openai_client
from app.llm.prompts import CHAT_SYSTEM_PROMPT, build_chat_prompt
from app.llm.tools import run_tools


def _fallback_answer(message: str, tool_context: dict[str, Any], error: Exception) -> str:
    outputs = tool_context.get("outputs", {})
    check = outputs.get("get_check_context")
    snippet = outputs.get("scan_code_snippet")
    if snippet and snippet.get("scanned"):
        findings = snippet.get("findings") or []
        if findings:
            first = findings[0]
            return (
                f"ИИ сейчас недоступен, но локальный scanner нашёл {first.get('cwe')} / {first.get('title')}. "
                f"Проблема: {first.get('reason')} Исправление: {first.get('fixed_example') or first.get('fix')}"
            )
    if check and check.get("found") and check.get("findings"):
        first = check["findings"][0]
        return (
            f"ИИ сейчас недоступен. По данным проверки #{check.get('id')} статус {check.get('status')}. "
            f"Главная проблема: {first.get('cwe')} {first.get('title')} в {first.get('file')}:{first.get('line')}. "
            f"Фикс: {first.get('fixed_example') or first.get('fix')}"
        )
    return f"ИИ сейчас недоступен: {error}. Инструменты CodeGuardian отработали, но полноценный ответ модели не получен."


def ask_assistant(db: Session, message: str, check_id: int | None = None) -> dict[str, Any]:
    tool_context = run_tools(db, message, check_id)
    try:
        client = get_openai_client()
        response = client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            messages=[
                {"role": "system", "content": CHAT_SYSTEM_PROMPT},
                {"role": "user", "content": build_chat_prompt(user_message=message, tool_context=tool_context)},
            ],
            temperature=0.2,
            max_tokens=settings.OPENAI_MAX_TOKENS,
        )
        answer = response.choices[0].message.content or "Модель вернула пустой ответ."
        return {"answer": answer.strip(), "tools_used": tool_context["tools_used"], "degraded": False}
    except Exception as exc:  # pragma: no cover - external LLM dependent
        return {
            "answer": _fallback_answer(message, tool_context, exc),
            "tools_used": tool_context["tools_used"],
            "degraded": True,
        }


def stream_assistant(db: Session, message: str, check_id: int | None = None) -> tuple[dict[str, Any], Any]:
    """Return (tool_context, generator_of_text_chunks)."""
    tool_context = run_tools(db, message, check_id)

    def _generate():
        try:
            client = get_openai_client()
            stream = client.chat.completions.create(
                model=settings.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": CHAT_SYSTEM_PROMPT},
                    {"role": "user", "content": build_chat_prompt(user_message=message, tool_context=tool_context)},
                ],
                temperature=0.2,
                max_tokens=settings.OPENAI_MAX_TOKENS,
                stream=True,
            )
            for chunk in stream:
                delta = chunk.choices[0].delta if chunk.choices else None
                if delta and delta.content:
                    yield delta.content
        except Exception as exc:
            yield _fallback_answer(message, tool_context, exc)

    return tool_context, _generate()
