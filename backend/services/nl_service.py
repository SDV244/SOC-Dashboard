"""
Natural language → structured filter params via OpenRouter free LLMs.
SECURITY: Only the user's typed query is sent. No log data, IPs, or events leave the server.
"""

import asyncio
import json
import re
import time
from typing import Any

import httpx

from backend.config import get_settings

_models_cache: list[dict] = []
_models_loaded_at: float = 0.0
_models_lock = asyncio.Lock()

# Cached working model: (model_id, probed_at)
_probed_model: str | None = None
_probed_at: float = 0.0
_probe_lock = asyncio.Lock()
_PROBE_TTL = 1800.0  # re-probe every 30 min

SYSTEM_PROMPT = """Eres un asistente de búsqueda de logs de seguridad (SOC).
El usuario describe en lenguaje natural lo que quiere buscar en los logs.
Tu tarea es devolver únicamente un objeto JSON con los filtros a aplicar.

Filtros disponibles (todos opcionales, solo incluir los relevantes):
- "index": índice a consultar. Valores válidos: "adr","ade","syslog","wineventlog","users","assets","maltrace","scan","ser","audit","cloudtrail"
- "search": texto libre (hostname, IP, nombre de evento, proceso)
- "threat_score_min": entero 0-100, puntuación mínima de amenaza
- "is_dga": "yes" para detectar Domain Generation Algorithm (malware DNS)
- "is_tunneling": true para detectar exfiltración por túnel DNS/HTTP
- "app_name": nombre de aplicación de red (dns, http, https, smtp, ssh, rdp, smb, ftp)
- "src_country": código ISO-2 del país origen (ej: "CN","RU","US","VE","IR")
- "domain": dominio o fragmento de dominio a buscar

Responde SOLO con el JSON, sin markdown ni explicaciones adicionales.

Ejemplos:
Usuario: "eventos DGA de China con score alto"
Respuesta: {"is_dga":"yes","src_country":"CN","threat_score_min":50}

Usuario: "túneles DNS en la última semana"
Respuesta: {"index":"adr","is_tunneling":true,"app_name":"dns"}

Usuario: "inicios de sesión fallidos en Windows"
Respuesta: {"index":"wineventlog","search":"4625"}

Usuario: "actividad del usuario jdoe"
Respuesta: {"search":"jdoe"}

Si no puedes extraer ningún filtro útil, devuelve: {}"""

# Ordered by preference: largest/most capable models first for accurate JSON extraction
_PREFERRED_MODELS = [
    "meta-llama/llama-3.3-70b-instruct:free",
    "openai/gpt-oss-120b:free",
    "google/gemma-4-31b-it:free",
    "nousresearch/hermes-3-llama-3.1-405b:free",
    "openai/gpt-oss-20b:free",
    "google/gemma-4-26b-a4b-it:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "liquid/lfm-2.5-1.2b-instruct:free",
]

_VALID_INDEXES = {"adr","ade","syslog","wineventlog","users","assets","maltrace","scan","ser","audit","cloudtrail"}
_VALID_DGA = {"yes", "no"}
_VALID_APPS = {"dns","http","https","smtp","ssh","rdp","smb","ftp","unknown"}

_PROBE_MESSAGES = [
    {"role": "system", "content": "Reply ONLY with JSON, no markdown."},
    {"role": "user", "content": 'DGA events from China. Return: {"is_dga":"yes","src_country":"CN"}'},
]


async def get_free_models() -> list[dict]:
    """Fetch free-tier models from OpenRouter. Cached 1 hour."""
    global _models_cache, _models_loaded_at
    async with _models_lock:
        if _models_cache and time.monotonic() - _models_loaded_at < 3600:
            return _models_cache
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get("https://openrouter.ai/api/v1/models")
                resp.raise_for_status()
                all_models = resp.json().get("data", [])
                _models_cache = [
                    {"id": m["id"], "name": m.get("name", m["id"])}
                    for m in all_models
                    if str(m.get("pricing", {}).get("prompt", "1")) == "0"
                ]
                _models_loaded_at = time.monotonic()
                return _models_cache
        except Exception:
            return _models_cache or []


async def probe_working_model(api_key: str) -> str | None:
    """
    Send a trivial probe query to each candidate model in order.
    Returns the first model that responds 200, or None if all fail.
    Result is cached for _PROBE_TTL seconds.
    """
    global _probed_model, _probed_at
    async with _probe_lock:
        if _probed_model and time.monotonic() - _probed_at < _PROBE_TTL:
            return _probed_model

        # Build candidate list: preferred first, then any other free models
        models = await get_free_models()
        available_ids = {m["id"] for m in models}
        candidates = list(_PREFERRED_MODELS)
        # Append any free models not already in our list
        for m in models:
            if m["id"] not in candidates:
                candidates.append(m["id"])

        async with httpx.AsyncClient(timeout=8) as client:
            for model in candidates:
                try:
                    resp = await client.post(
                        "https://openrouter.ai/api/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {api_key}",
                            "HTTP-Referer": "https://soc-dashboard.local",
                            "X-Title": "SOC Dashboard NL Search",
                        },
                        json={
                            "model": model,
                            "messages": _PROBE_MESSAGES,
                            "temperature": 0.0,
                            "max_tokens": 32,
                        },
                    )
                    if resp.status_code == 200:
                        _probed_model = model
                        _probed_at = time.monotonic()
                        return model
                    # 429 or other error → try next
                except Exception:
                    continue

        _probed_model = None
        return None


def _sanitize_filters(raw_filters: dict) -> dict[str, Any]:
    """Validate and sanitize LLM output. Prevents injection via type checking."""
    clean: dict[str, Any] = {}

    if "index" in raw_filters and isinstance(raw_filters["index"], str):
        if raw_filters["index"] in _VALID_INDEXES:
            clean["index"] = raw_filters["index"]

    if "search" in raw_filters and isinstance(raw_filters["search"], str):
        clean["search"] = raw_filters["search"][:200]

    if "threat_score_min" in raw_filters:
        try:
            v = int(raw_filters["threat_score_min"])
            clean["threat_score_min"] = max(0, min(100, v))
        except (TypeError, ValueError):
            pass

    if "is_dga" in raw_filters and raw_filters["is_dga"] in _VALID_DGA:
        clean["is_dga"] = raw_filters["is_dga"]

    if "is_tunneling" in raw_filters:
        if isinstance(raw_filters["is_tunneling"], bool):
            clean["is_tunneling"] = raw_filters["is_tunneling"]
        elif raw_filters["is_tunneling"] is True or raw_filters["is_tunneling"] == "true":
            clean["is_tunneling"] = True

    if "app_name" in raw_filters and isinstance(raw_filters["app_name"], str):
        app = raw_filters["app_name"].lower()[:50]
        clean["app_name"] = app

    if "src_country" in raw_filters and isinstance(raw_filters["src_country"], str):
        code = raw_filters["src_country"].upper()[:3]
        if code.isalpha():
            clean["src_country"] = code

    if "domain" in raw_filters and isinstance(raw_filters["domain"], str):
        clean["domain"] = raw_filters["domain"][:200]

    return clean


async def _call_openrouter(api_key: str, model: str, query: str) -> str:
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "HTTP-Referer": "https://soc-dashboard.local",
                "X-Title": "SOC Dashboard NL Search",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": query[:500]},
                ],
                "temperature": 0.1,
                "max_tokens": 256,
            },
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()


async def nl_to_filters(query: str) -> dict[str, Any]:
    """
    Convert natural language query to structured filter dict.
    Only query text is sent to OpenRouter — no log data leaves the server.
    Probes models first to find one that responds, then retries on 429.
    Returns empty dict if API key not configured or on error.
    """
    settings = get_settings()
    if not settings.openrouter_api_key:
        return {}

    # If a model is explicitly configured, use it directly
    if settings.nl_model:
        try:
            content = await _call_openrouter(settings.openrouter_api_key, settings.nl_model, query)
            json_match = re.search(r"\{[^{}]*\}", content, re.DOTALL)
            if json_match:
                return _sanitize_filters(json.loads(json_match.group()))
        except Exception:
            pass
        return {}

    # Probe to find a working model, then use it
    working = await probe_working_model(settings.openrouter_api_key)
    if not working:
        raise RuntimeError(
            "Límite de peticiones alcanzado en todos los modelos gratuitos. "
            "Intenta de nuevo en un momento."
        )

    # Try the probed model; if it 429s now, invalidate cache and try fallbacks
    global _probed_model, _probed_at
    models = await get_free_models()
    candidates = [working] + [m for m in _PREFERRED_MODELS if m != working]
    candidates += [m["id"] for m in models if m["id"] not in candidates]
    candidates = candidates[:8]

    for model in candidates:
        try:
            content = await _call_openrouter(settings.openrouter_api_key, model, query)
            # Successful call — update probe cache to this model
            async with _probe_lock:
                _probed_model = model
                _probed_at = time.monotonic()
            break
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 429:
                # Invalidate cache so next call re-probes
                async with _probe_lock:
                    _probed_model = None
                continue
            raise RuntimeError(f"OpenRouter error: {exc}") from exc
        except Exception as exc:
            raise RuntimeError(f"OpenRouter error: {exc}") from exc
    else:
        raise RuntimeError(
            "Límite de peticiones alcanzado en todos los modelos gratuitos. "
            "Intenta de nuevo en un momento."
        )

    json_match = re.search(r"\{[^{}]*\}", content, re.DOTALL)
    if not json_match:
        return {}

    try:
        parsed = json.loads(json_match.group())
        return _sanitize_filters(parsed)
    except json.JSONDecodeError:
        return {}
