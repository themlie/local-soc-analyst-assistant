"""
reason/retrieve.py — SEMANTIC SEARCH over ATT&CK (embeddings + vector similarity).

This is the pure "retrieval" step of classic RAG. Detectors are rule-based and only
catch patterns they know. But to map a free-text observation (e.g. "running code
in memory via PowerShell") to the closest ATT&CK technique, keywords aren't enough —
we need MEANING similarity.

Here we:
  1) Embed every ATT&CK technique description with the local embedding model.
  2) Embed a query and find the closest techniques by cosine similarity.

This module runs standalone (has its own demo) and can be used to enrich the LLM
context later. Fully offline; the embedding model is local too.
"""

import common.console  # noqa: F401
import numpy as np
from common.llm import embed, embed_batch
from common.attack import TECHNIQUES

# Compute the ATT&CK index (id list + vector matrix) once and cache it.
_index_cache = None


def _cosine(matrix: np.ndarray, vector: np.ndarray) -> np.ndarray:
    """Cosine similarity between each row of the matrix and the vector (vectorized)."""
    m_norm = np.linalg.norm(matrix, axis=1)
    v_norm = np.linalg.norm(vector)
    denom = m_norm * v_norm
    denom[denom == 0] = 1e-9  # avoid division by zero
    return (matrix @ vector) / denom


def _build_index():
    """Embed all ATT&CK techniques and return (ids, matrix) — cached."""
    global _index_cache
    if _index_cache is None:
        ids = list(TECHNIQUES.keys())
        # Embed name + description for each technique
        texts = [f"{TECHNIQUES[t]['name']}. {TECHNIQUES[t]['description']}" for t in ids]
        vectors = embed_batch(texts)
        _index_cache = (ids, np.array(vectors, dtype=np.float32))
    return _index_cache


def search(query: str, k: int = 3) -> list[tuple[str, float]]:
    """Return the k ATT&CK techniques most semantically similar to the query (id, score)."""
    ids, matrix = _build_index()
    q_vec = np.array(embed(query), dtype=np.float32)
    sims = _cosine(matrix, q_vec)
    top_idx = np.argsort(sims)[::-1][:k]
    return [(ids[i], float(sims[i])) for i in top_idx]


if __name__ == "__main__":
    print("ATT&CK semantic search demo (loading embedding model)...\n")
    queries = [
        "script running a base64-encoded command in a hidden window",
        "repeated wrong-password attempts against the same account",
        "unusual outbound connection to an external server on a strange port",
    ]
    for q in queries:
        print(f"QUERY: {q}")
        for tid, score in search(q, k=2):
            print(f"   -> {tid} {TECHNIQUES[tid]['name']}  (similarity: {score:.3f})")
        print()
