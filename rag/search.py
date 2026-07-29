"""
rag/search.py — find the passages that answer a question.

The retrieval step: the question is turned into a vector by the same embedding model
that indexed the passages, and the closest passages are returned by cosine similarity.
Using the same model for both sides is not optional — vectors from different models
are not comparable, and mixing them produces confident nonsense.

Similarity has a floor. Nearest is not the same as relevant: for a question the
knowledge base does not cover, brute-force search still returns its three closest
passages, and handing those to the model invites it to answer anyway. Below the floor
we return nothing, which is what lets the assistant say it does not know.
"""

import json

import numpy as np

import common.console  # noqa: F401
from common.db import get_kb_connection
from config import RAG_TOP_K, RAG_MIN_SIMILARITY


def _cosine(matrix: np.ndarray, vector: np.ndarray) -> np.ndarray:
    """Cosine similarity between every row of the matrix and the vector."""
    denom = np.linalg.norm(matrix, axis=1) * np.linalg.norm(vector)
    denom[denom == 0] = 1e-9
    return (matrix @ vector) / denom


def _load_chunks() -> list:
    conn = get_kb_connection()
    try:
        rows = conn.execute("SELECT id, source, heading, content, embedding FROM chunks").fetchall()
    except Exception:
        rows = []  # index not built yet
    conn.close()
    return rows


def search(question: str, k: int = RAG_TOP_K,
           min_similarity: float = RAG_MIN_SIMILARITY) -> list[dict]:
    """Return up to k passages relevant to the question, most similar first.

    Returns an empty list when nothing clears the similarity floor — the caller is
    expected to treat that as "not covered by the knowledge base".
    """
    rows = _load_chunks()
    if not rows:
        return []

    # Imported here, not at module scope: loading the model runtime is expensive and
    # only this path needs it, which also lets the chunking and refusal logic be
    # tested (and run in CI) on a machine with no model installed.
    from common.llm import embed

    matrix = np.array([json.loads(r["embedding"]) for r in rows], dtype=np.float32)
    scores = _cosine(matrix, np.array(embed(question), dtype=np.float32))

    ranked = sorted(zip(rows, scores), key=lambda pair: pair[1], reverse=True)[:k]
    return [{
        "id": row["id"],
        "source": row["source"],
        "heading": row["heading"],
        "content": row["content"],
        "similarity": round(float(score), 3),
    } for row, score in ranked if score >= min_similarity]


if __name__ == "__main__":
    import sys

    question = " ".join(sys.argv[1:]) or "How should I respond to a password spray?"
    print(f"Q: {question}\n")
    hits = search(question)
    if not hits:
        print("  no passage cleared the similarity floor — the knowledge base does not cover this.")
    for hit in hits:
        print(f"  [{hit['similarity']}] {hit['source']} — {hit['heading']}")
        print(f"      {hit['content'][:160]}...\n")
