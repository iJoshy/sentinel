"""LLM helpers — supports OpenRouter (default local) and AWS Bedrock."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from typing import Any

import boto3
import httpx

from common.config import (
    active_model,
    bedrock_region,
    openrouter_api_key,
    openrouter_base_url,
    openrouter_model,
    use_bedrock,
    use_openrouter,
    use_vertex_ai,
    vertex_ai_location,
    vertex_ai_model,
    vertex_ai_project_id,
)


logger = logging.getLogger(__name__)

_OPENROUTER_TIMEOUT = 60.0
_VERTEX_TIMEOUT = 60.0


def _openrouter_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {openrouter_api_key()}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://sentinel.local",
        "X-Title": "Sentinel",
    }


def _converse_json_openrouter(
    system_prompt: str, user_prompt: str, max_tokens: int = 1500
) -> dict[str, Any] | None:
    """Call OpenRouter chat completions and parse the JSON response."""
    payload = {
        "model": openrouter_model(),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
        "max_tokens": max_tokens,
        "temperature": 0.1,
    }
    try:
        resp = httpx.post(
            f"{openrouter_base_url()}/chat/completions",
            headers=_openrouter_headers(),
            json=payload,
            timeout=_OPENROUTER_TIMEOUT,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"].strip()
        return json.loads(content)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "OpenRouter converse_json failed; falling back to heuristics: %s", exc
        )
        return None


def _converse_stream_text_openrouter(
    system_prompt: str, user_prompt: str
) -> Iterator[str]:
    """Stream text chunks from OpenRouter chat completions (SSE)."""
    payload = {
        "model": openrouter_model(),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": True,
        "max_tokens": 700,
        "temperature": 0.1,
    }
    try:
        with httpx.stream(
            "POST",
            f"{openrouter_base_url()}/chat/completions",
            headers=_openrouter_headers(),
            json=payload,
            timeout=_OPENROUTER_TIMEOUT,
        ) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line.startswith("data: "):
                    continue
                raw = line[6:].strip()
                if raw == "[DONE]":
                    break
                try:
                    event = json.loads(raw)
                    piece = event["choices"][0].get("delta", {}).get("content") or ""
                    if piece:
                        yield piece
                except Exception:  # noqa: BLE001
                    continue
    except Exception as exc:  # noqa: BLE001
        logger.warning("OpenRouter converse_stream failed: %s", exc)
        yield from ()


# Google Vertex AI / Gemini


def _vertex_access_token() -> str:
    try:
        import google.auth
        from google.auth.transport.requests import Request

        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        credentials.refresh(Request())
        return str(credentials.token or "")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Vertex auth failed; falling back to heuristics: %s", exc)
        return ""


def _vertex_endpoint(method: str = "generateContent") -> str:
    project_id = vertex_ai_project_id()
    location = vertex_ai_location()
    model = vertex_ai_model()
    return (
        f"https://{location}-aiplatform.googleapis.com/v1/"
        f"projects/{project_id}/locations/{location}/publishers/google/models/{model}:{method}"
    )


def _vertex_text_from_response(data: dict[str, Any]) -> str:
    pieces: list[str] = []
    for candidate in data.get("candidates") or []:
        content = candidate.get("content") or {}
        for part in content.get("parts") or []:
            text = part.get("text")
            if isinstance(text, str):
                pieces.append(text)
    return "".join(pieces).strip()


def _converse_json_vertex(
    system_prompt: str, user_prompt: str, max_tokens: int = 1500
) -> dict[str, Any] | None:
    if not vertex_ai_project_id():
        logger.warning("GCP_PROJECT_ID not set; Vertex AI disabled")
        return None
    token = _vertex_access_token()
    if not token:
        return None
    payload = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }
    try:
        resp = httpx.post(
            _vertex_endpoint(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=_VERTEX_TIMEOUT,
        )
        resp.raise_for_status()
        content = _vertex_text_from_response(resp.json())
        return json.loads(content or "{}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Vertex converse_json failed; falling back to heuristics: %s", exc)
        return None


def _converse_stream_text_vertex(
    system_prompt: str, user_prompt: str, max_tokens: int = 700
) -> Iterator[str]:
    if not vertex_ai_project_id():
        logger.warning("GCP_PROJECT_ID not set; Vertex AI disabled")
        yield from ()
        return
    token = _vertex_access_token()
    if not token:
        yield from ()
        return
    payload = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.1},
    }
    try:
        resp = httpx.post(
            _vertex_endpoint(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=_VERTEX_TIMEOUT,
        )
        resp.raise_for_status()
        text = _vertex_text_from_response(resp.json())
        if text:
            yield text
    except Exception as exc:  # noqa: BLE001
        logger.warning("Vertex converse_stream failed: %s", exc)
        yield from ()


def _converse_stream_chat_vertex(
    system_prompt: str, messages: list[dict[str, str]]
) -> Iterator[str]:
    if not vertex_ai_project_id():
        logger.warning("GCP_PROJECT_ID not set; Vertex AI disabled")
        yield from ()
        return
    token = _vertex_access_token()
    if not token:
        yield from ()
        return
    contents = []
    for msg in messages:
        role = "model" if msg.get("role") == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": msg.get("content", "")}]})
    payload = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": contents,
        "generationConfig": {"maxOutputTokens": 1200, "temperature": 0.2},
    }
    try:
        resp = httpx.post(
            _vertex_endpoint(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=_VERTEX_TIMEOUT,
        )
        resp.raise_for_status()
        text = _vertex_text_from_response(resp.json())
        if text:
            yield text
    except Exception as exc:  # noqa: BLE001
        logger.warning("Vertex converse_stream_chat failed: %s", exc)
        yield from ()


# AWS Bedrock


def _converse_json_bedrock(
    model_id: str, system_prompt: str, user_prompt: str, max_tokens: int = 1500
) -> dict[str, Any] | None:
    try:
        client = boto3.client("bedrock-runtime", region_name=bedrock_region())
        response = client.converse(
            modelId=model_id,
            system=[{"text": system_prompt}],
            messages=[{"role": "user", "content": [{"text": user_prompt}]}],
            inferenceConfig={"maxTokens": max_tokens, "temperature": 0.1},
        )
        content = response["output"]["message"]["content"][0].get("text", "{}").strip()
        return json.loads(content)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Bedrock converse failed; falling back to heuristics: %s", exc)
        return None


def _converse_stream_text_bedrock(
    model_id: str, system_prompt: str, user_prompt: str
) -> Iterator[str]:
    try:
        client = boto3.client("bedrock-runtime", region_name=bedrock_region())
        response = client.converse_stream(
            modelId=model_id,
            system=[{"text": system_prompt}],
            messages=[{"role": "user", "content": [{"text": user_prompt}]}],
            inferenceConfig={"maxTokens": 700, "temperature": 0.1},
        )
        stream = response.get("stream")
        if not stream:
            yield from ()
            return
        for event in stream:
            if "contentBlockDelta" not in event:
                continue
            block = event["contentBlockDelta"]
            delta = block.get("delta") or {}
            piece = delta.get("text") or ""
            if piece:
                yield piece
    except Exception as exc:  # noqa: BLE001
        logger.warning("Bedrock converse_stream failed: %s", exc)
        yield from ()


# Multi-turn chat streaming


def _converse_stream_chat_openrouter(
    system_prompt: str, messages: list[dict[str, str]]
) -> Iterator[str]:
    """Stream text from OpenRouter using a full multi-turn message history."""
    payload = {
        "model": openrouter_model(),
        "messages": [{"role": "system", "content": system_prompt}] + messages,
        "stream": True,
        "max_tokens": 1200,
        "temperature": 0.2,
    }
    try:
        with httpx.stream(
            "POST",
            f"{openrouter_base_url()}/chat/completions",
            headers=_openrouter_headers(),
            json=payload,
            timeout=_OPENROUTER_TIMEOUT,
        ) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line.startswith("data: "):
                    continue
                raw = line[6:].strip()
                if raw == "[DONE]":
                    break
                try:
                    event = json.loads(raw)
                    piece = event["choices"][0].get("delta", {}).get("content") or ""
                    if piece:
                        yield piece
                except Exception:  # noqa: BLE001
                    continue
    except Exception as exc:  # noqa: BLE001
        logger.warning("OpenRouter converse_stream_chat failed: %s", exc)
        yield from ()


def _converse_stream_chat_bedrock(
    model_id: str, system_prompt: str, messages: list[dict[str, str]]
) -> Iterator[str]:
    """Stream text from Bedrock using a full multi-turn conversation."""
    try:
        client = boto3.client("bedrock-runtime", region_name=bedrock_region())
        bedrock_messages = [
            {"role": m["role"], "content": [{"text": m["content"]}]} for m in messages
        ]
        response = client.converse_stream(
            modelId=model_id,
            system=[{"text": system_prompt}],
            messages=bedrock_messages,
            inferenceConfig={"maxTokens": 1200, "temperature": 0.2},
        )
        stream = response.get("stream")
        if not stream:
            yield from ()
            return
        for event in stream:
            if "contentBlockDelta" not in event:
                continue
            block = event["contentBlockDelta"]
            delta = block.get("delta") or {}
            piece = delta.get("text") or ""
            if piece:
                yield piece
    except Exception as exc:  # noqa: BLE001
        logger.warning("Bedrock converse_stream_chat failed: %s", exc)
        yield from ()


def converse_json(
    system_prompt: str, user_prompt: str, max_tokens: int = 1500
) -> dict[str, Any] | None:
    """Best-effort LLM call that expects JSON output.

    Routes to the active backend (USE_OPEN_ROUTER or USE_BEDROCK) and uses
    the model returned by ``active_model()``. Returns ``None`` when neither
    backend is configured or if the call fails.
    """
    model_id = active_model()
    if use_vertex_ai():
        return _converse_json_vertex(system_prompt, user_prompt, max_tokens=max_tokens)
    if use_openrouter():
        return _converse_json_openrouter(system_prompt, user_prompt, max_tokens=max_tokens)
    if use_bedrock():
        return _converse_json_bedrock(model_id, system_prompt, user_prompt, max_tokens=max_tokens)
    return None


def converse_stream_text(
    system_prompt: str, user_prompt: str
) -> Iterator[str]:
    """Stream plain-text fragments from the configured LLM (best-effort)."""
    model_id = active_model()
    if use_vertex_ai():
        yield from _converse_stream_text_vertex(system_prompt, user_prompt)
        return
    if use_openrouter():
        yield from _converse_stream_text_openrouter(system_prompt, user_prompt)
        return
    if use_bedrock():
        yield from _converse_stream_text_bedrock(model_id, system_prompt, user_prompt)
        return
    yield from ()


def converse_stream_chat(
    system_prompt: str, messages: list[dict[str, str]]
) -> Iterator[str]:
    """Stream plain-text from the LLM given a full multi-turn message history.

    ``messages`` is a list of ``{"role": "user"|"assistant", "content": str}`` dicts.
    The model is resolved from ``active_model()`` — set via OPENROUTER_MODEL or
    BEDROCK_MODEL_ID depending on which backend is enabled.
    """
    model_id = active_model()
    if use_vertex_ai():
        yield from _converse_stream_chat_vertex(system_prompt, messages)
        return
    if use_openrouter():
        yield from _converse_stream_chat_openrouter(system_prompt, messages)
        return
    if use_bedrock():
        yield from _converse_stream_chat_bedrock(model_id, system_prompt, messages)
        return
    yield from ()
