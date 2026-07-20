"""
common/llm.py — Single wrapper for the Foundry Local on-device LLM.

The whole project talks to the model through here. Model loading (download -> load
into memory) and chat-call details are hidden here; other layers just call
`complete(system, user)`. This makes swapping the model or updating the API a
one-file change.

Note: the model runs entirely locally, on the CPU, with no internet.
"""

import sys
import json
import common.console  # noqa: F401
from foundry_local_sdk import Configuration, FoundryLocalManager
from config import APP_NAME, CHAT_MODEL, EMBED_MODEL

# Caches so we don't rebuild clients on every call (alias -> client)
_chat_clients: dict[str, object] = {}
_embed_clients: dict[str, object] = {}


def _get_manager() -> FoundryLocalManager:
    """Return the Foundry Local manager (singleton); initialize it if needed."""
    if FoundryLocalManager.instance is None:
        FoundryLocalManager.initialize(Configuration(app_name=APP_NAME))
    return FoundryLocalManager.instance


def _load_model(alias: str):
    """Download (if needed) and load a model into memory, returning the IModel.
    Chat and embedding clients share this common loader."""
    manager = _get_manager()
    model = manager.catalog.get_model(alias)
    if model is None:
        raise ValueError(f"Model not found: {alias}")

    # Show download progress so large models don't look "stuck".
    # Only update a single line in a real terminal; stay quiet when piped/logged.
    is_tty = sys.stdout.isatty()

    def _progress(pct: float) -> None:
        if is_tty:
            print(f"\r  [{alias}] downloading: {pct:5.1f}%", end="", flush=True)

    model.download(progress_callback=_progress)  # instant if already cached
    if is_tty:
        print(f"\r  [{alias}] ready, loading into memory...        ")
    model.load()  # load model into memory
    return model


def get_chat_client(alias: str = CHAT_MODEL):
    """Return a chat client for the model (downloads + loads on first call)."""
    if alias not in _chat_clients:
        _chat_clients[alias] = _load_model(alias).get_chat_client()
    return _chat_clients[alias]


def get_embedding_client(alias: str = EMBED_MODEL):
    """Return an embedding client for the model (downloads + loads on first call)."""
    if alias not in _embed_clients:
        _embed_clients[alias] = _load_model(alias).get_embedding_client()
    return _embed_clients[alias]


def complete(system: str, user: str, alias: str = CHAT_MODEL, json_mode: bool = False) -> str:
    """Send a system + user message to the model and return the raw text response.

    If json_mode=True, ask the model for JSON output (on models that support it).
    """
    client = get_chat_client(alias)
    client.settings.temperature = 0.2  # low temperature = more consistent, less made up

    if json_mode:
        try:
            client.settings.response_format = {"type": "json_object"}
        except Exception:
            client.settings.response_format = None

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    response = client.complete_chat(messages=messages)
    return response.choices[0].message.content


def parse_json(text: str) -> dict:
    """Safely parse JSON out of the model output.

    Small models sometimes embed JSON inside prose; so we try direct parsing first,
    then fall back to extracting the substring between the first '{' and last '}'.
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
    # If unparseable, return the raw text so the caller can see what happened
    return {"_parse_error": True, "raw": text}


def embed(text: str, alias: str = EMBED_MODEL) -> list[float]:
    """Turn a single text into an embedding vector."""
    resp = get_embedding_client(alias).generate_embedding(text)
    return list(resp.data[0].embedding)


def embed_batch(texts: list[str], alias: str = EMBED_MODEL) -> list[list[float]]:
    """Turn multiple texts into embedding vectors in a single call."""
    resp = get_embedding_client(alias).generate_embeddings(texts)
    return [list(d.embedding) for d in resp.data]
