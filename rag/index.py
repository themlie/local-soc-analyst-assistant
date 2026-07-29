"""
rag/index.py — turn the knowledge base into searchable passages.

This is the "retrieval" half of RAG, built once and reused: every document in `kb/` is
split into passages, each passage is turned into a vector by the local embedding model,
and both are stored in SQLite.

Why passages rather than whole documents: a whole runbook is too coarse to be an
answer — retrieving it hands the model four pages when it needed one paragraph, and the
answer drowns. A single sentence is the opposite problem, too small to carry the
context that makes it meaningful. A few paragraphs is the useful middle.

Each passage keeps the file it came from and the heading it sits under, because an
answer a reader cannot trace back to a source is just a claim.

    python -m rag.index          # (re)build the index
"""

import json
import re
from pathlib import Path

import common.console  # noqa: F401
from common.db import get_kb_connection
from config import KB_DIR, CHUNK_MAX_CHARS, CHUNK_OVERLAP_PARAGRAPHS, EMBED_BATCH_SIZE


def _paragraphs_with_headings(markdown: str) -> list[tuple[str, str]]:
    """Split markdown into (heading, paragraph) pairs, carrying the current heading."""
    heading = ""
    out: list[tuple[str, str]] = []
    for block in re.split(r"\n\s*\n", markdown):
        block = block.strip()
        if not block:
            continue
        if block.startswith("#"):
            heading = block.lstrip("#").strip()
            continue  # a heading is a label, not content to answer from
        out.append((heading, block))
    return out


def chunk_document(markdown: str) -> list[tuple[str, str]]:
    """Group paragraphs into passages of at most CHUNK_MAX_CHARS.

    Consecutive paragraphs under the same heading are joined until the budget is
    reached. The last paragraph of a passage also opens the next one, so an idea that
    straddles a boundary is still findable from either side.
    """
    chunks: list[tuple[str, str]] = []
    current: list[str] = []
    current_heading = ""

    def flush() -> None:
        if current:
            chunks.append((current_heading, "\n\n".join(current)))

    for heading, para in _paragraphs_with_headings(markdown):
        starting_new_section = heading != current_heading and current
        too_long = sum(len(p) for p in current) + len(para) > CHUNK_MAX_CHARS

        if starting_new_section or too_long:
            flush()
            overlap = current[-CHUNK_OVERLAP_PARAGRAPHS:] if (current and not starting_new_section) else []
            current = list(overlap)
        current_heading = heading
        current.append(para)

    flush()
    return chunks


def _create_table(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS chunks (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            source    TEXT NOT NULL,
            heading   TEXT,
            content   TEXT NOT NULL,
            embedding TEXT NOT NULL
        )
    """)


def load_documents(kb_dir: Path = KB_DIR) -> list[tuple[str, str]]:
    """Return (filename, text) for every document in the knowledge base."""
    if not kb_dir.exists():
        raise FileNotFoundError(f"Knowledge base directory not found: {kb_dir}")
    docs = [(p.name, p.read_text(encoding="utf-8"))
            for p in sorted(kb_dir.glob("*.md")) if p.is_file()]
    if not docs:
        raise ValueError(f"No .md documents found in {kb_dir}")
    return docs


def build_index(kb_dir: Path = KB_DIR, verbose: bool = True) -> int:
    """Chunk, embed and store every document. Returns the number of passages."""
    # Imported here so chunking and index inspection work — and can be tested in CI —
    # on a machine with no model runtime installed.
    from common.llm import embed_batch

    documents = load_documents(kb_dir)

    passages = []  # (source, heading, content)
    for name, text in documents:
        for heading, content in chunk_document(text):
            passages.append((name, heading, content))

    if verbose:
        print(f"{len(documents)} document(s) -> {len(passages)} passage(s); embedding...")

    # Batched rather than one call per passage (slow) or one call for everything (the
    # runtime cancels requests that take too long on CPU). The heading is prepended so
    # a passage carries the section it belongs to into its vector.
    texts = [f"{h}. {c}" if h else c for _, h, c in passages]
    vectors = []
    for start in range(0, len(texts), EMBED_BATCH_SIZE):
        vectors.extend(embed_batch(texts[start:start + EMBED_BATCH_SIZE]))
        if verbose:
            print(f"  embedded {min(start + EMBED_BATCH_SIZE, len(texts))}/{len(texts)}")

    conn = get_kb_connection()
    _create_table(conn)
    conn.execute("DELETE FROM chunks")  # a rebuild replaces the index entirely
    conn.executemany(
        "INSERT INTO chunks (source, heading, content, embedding) VALUES (?, ?, ?, ?)",
        [(src, head, content, json.dumps(vec))
         for (src, head, content), vec in zip(passages, vectors)],
    )
    conn.commit()
    conn.close()

    if verbose:
        print(f"indexed {len(passages)} passage(s) from {len(documents)} document(s)")
    return len(passages)


def index_stats() -> dict:
    """How many passages are indexed, and from which documents."""
    conn = get_kb_connection()
    _create_table(conn)
    rows = conn.execute(
        "SELECT source, COUNT(*) AS n FROM chunks GROUP BY source ORDER BY source"
    ).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    conn.close()
    return {"total": total, "by_source": {r["source"]: r["n"] for r in rows}}


if __name__ == "__main__":
    build_index()
    stats = index_stats()
    print()
    for source, n in stats["by_source"].items():
        print(f"  {n:3} passage(s)  {source}")
