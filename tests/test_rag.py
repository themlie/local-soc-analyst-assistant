"""
tests/test_rag.py — the retrieval half of the assistant.

Retrieval decides what the model is allowed to say, so the failure that matters is not
a clumsy answer: it is answering at all when the knowledge base has nothing relevant.
These tests cover chunking and the refusal path without needing the model, so they run
in CI where no model runtime exists.
"""

import pytest

from config import CHUNK_MAX_CHARS, KB_DIR
from rag.index import chunk_document, load_documents
from rag.answer import answer_question, _format_passages

SAMPLE = """# Runbook: Example

## Detection criteria

First paragraph about detection, long enough to be a real passage rather than a
fragment that carries no context on its own.

Second paragraph, still about detection, adding the detail that makes the first one
actionable rather than merely descriptive.

## Containment

A paragraph under a different heading entirely, which must not be merged with the
detection section above it.
"""


def test_documents_are_present_and_readable():
    """The assistant is only as good as its knowledge base."""
    docs = load_documents()
    assert len(docs) >= 5, f"expected a small document collection, found {len(docs)}"
    assert all(text.strip() for _, text in docs)


def test_chunking_respects_the_size_budget():
    for _, text in load_documents(KB_DIR):
        for _, content in chunk_document(text):
            assert len(content) <= CHUNK_MAX_CHARS * 1.5, "passage far over budget"


def test_chunks_do_not_span_headings():
    """A passage mixing 'Detection criteria' with 'Containment' retrieves badly: it
    matches both questions and answers neither cleanly."""
    chunks = chunk_document(SAMPLE)
    headings = [h for h, _ in chunks]
    assert "Detection criteria" in headings and "Containment" in headings
    containment = next(c for h, c in chunks if h == "Containment")
    assert "First paragraph about detection" not in containment


def test_headings_are_kept_for_citation():
    """An answer a reader cannot trace to a section is a claim, not a citation."""
    for heading, content in chunk_document(SAMPLE):
        assert heading, f"passage lost its heading: {content[:40]}"


def test_uncovered_question_is_refused_without_calling_the_model(monkeypatch):
    """The knowledge base says nothing about cooking. Answering anyway — from the
    model's own memory — is the exact failure RAG exists to prevent.

    Retrieval is stubbed to return nothing, so this asserts the refusal itself rather
    than the embedding model's judgement, and needs no model runtime.
    """
    monkeypatch.setattr("rag.answer.search", lambda *a, **k: [])

    result = answer_question("What is the best way to bake sourdough bread?")
    assert result["answered"] is False
    assert result["passages"] == []
    assert "does not cover" in result["answer"].lower()


def test_passages_are_clipped_before_reaching_the_prompt():
    """Long passages push prompt processing past the local runtime's budget."""
    formatted = _format_passages([
        {"source": "x.md", "heading": "H", "content": "word " * 500, "similarity": 0.9},
    ])
    assert len(formatted) < 1000
    assert "…" in formatted


@pytest.mark.parametrize("field", ["source", "heading", "content"])
def test_formatted_passages_carry_their_source(field):
    formatted = _format_passages([
        {"source": "runbook-brute-force.md", "heading": "Containment",
         "content": "Reset the password.", "similarity": 0.8},
    ])
    assert "runbook-brute-force.md" in formatted and "Containment" in formatted
