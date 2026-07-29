"""
rag/answer.py — answer a question from the knowledge base, with sources.

The generation half of RAG. Retrieved passages are placed in the prompt, and the model
is told to answer from them alone and to cite the document each claim came from.

Two behaviours matter more than fluency:

  - **Refusal.** If retrieval returns nothing above the similarity floor, the model is
    never asked. The assistant says the knowledge base does not cover the question.
    An assistant that answers anyway is worse than no assistant, because a confident
    wrong answer about incident response gets acted on.
  - **Citation.** Every answer carries the passages it came from, so a reader can check
    it rather than trust it.

    python -m rag.answer "How do I respond to a password spray?"
"""

import time

import common.console  # noqa: F401
from rag.search import search

SYSTEM_PROMPT = """You are a security operations assistant answering questions from a
team's own runbooks and policy.

RULES:
- Answer ONLY from the passages provided below. They are the team's documented
  procedure and they override anything you believe from general knowledge.
- If the passages do not contain the answer, say exactly: "The knowledge base does not
  cover this." Do not fill the gap from memory.
- Put the source file name in brackets right after the claim it supports, like this:
  Disable the account only if it is privileged [runbook-brute-force.md].
  Write plain sentences; never wrap the whole answer in brackets.
- Answer in at most 4 sentences. An analyst is reading this during an incident, and a
  long answer gets cancelled by the local runtime before it finishes.
"""

# Passages are clipped before they reach the prompt. Three full passages plus the
# instructions push prompt processing past the runtime's request budget on CPU, and a
# cancelled request is a worse answer than a slightly shorter one.
_MAX_PASSAGE_CHARS = 600
_RETRIES = 1


def _format_passages(passages: list[dict]) -> str:
    blocks = []
    for p in passages:
        label = f"{p['source']}" + (f" — {p['heading']}" if p["heading"] else "")
        content = p["content"]
        if len(content) > _MAX_PASSAGE_CHARS:
            content = content[:_MAX_PASSAGE_CHARS].rsplit(" ", 1)[0] + " …"
        blocks.append(f"[{label}]\n{content}")
    return "\n\n".join(blocks)


def answer_question(question: str, alias: str | None = None, on_chunk=None) -> dict:
    """Answer a question from the knowledge base.

    Returns the answer text, the passages it was based on, and whether the knowledge
    base covered the question at all.
    """
    passages = search(question)
    if not passages:
        return {
            "answer": "The knowledge base does not cover this.",
            "passages": [],
            "answered": False,
        }

    user_prompt = (
        f"PASSAGES FROM THE KNOWLEDGE BASE:\n\n{_format_passages(passages)}\n\n"
        f"QUESTION: {question}"
    )
    # Imported here so the refusal path above needs no model runtime at all.
    from common.llm import complete, complete_streamed

    kwargs = {"alias": alias} if alias else {}
    last_exc = None
    for attempt in range(_RETRIES + 1):
        try:
            text = (complete_streamed(SYSTEM_PROMPT, user_prompt, on_chunk=on_chunk, **kwargs)
                    if on_chunk else complete(SYSTEM_PROMPT, user_prompt, **kwargs))
            return {"answer": text.strip(), "passages": passages, "answered": True}
        except Exception as exc:
            last_exc = exc
            if attempt < _RETRIES:
                time.sleep(1.0)

    # The retrieval succeeded even though generation did not, so return the passages:
    # a reader can still act on the runbook text, which is the part that matters.
    return {
        "answer": ("The local model could not finish an answer in time. The relevant "
                   "passages are shown below — they are the documented procedure."),
        "passages": passages,
        "answered": False,
        "error": str(last_exc),
    }


def runbook_for_incident(incident: dict, k: int = 2) -> list[dict]:
    """Passages from the team's runbooks that apply to a detected incident.

    This is what connects the two halves of the tool. Without it an incident report
    ends in whatever remediation the model can think of — which is generic advice at
    best. With it, the actions come from the team's documented procedure, with the
    document named, and an analyst can check them.

    Retrieval is driven by the detected technique names rather than the free text of
    the report, so it depends on the deterministic layer, not on the model's wording.
    """
    from common.attack import get_technique

    names = []
    for tid in incident.get("techniques", []):
        technique = get_technique(tid)
        names.append(f"{tid} {technique['name']}" if technique else tid)
    if not names:
        return []

    query = "incident response for " + ", ".join(names)
    return search(query, k=k)


if __name__ == "__main__":
    import sys

    question = " ".join(sys.argv[1:]) or "How should I respond to a Kerberos password spray?"
    print(f"Q: {question}\n")
    result = answer_question(question)
    print(result["answer"])
    if result["passages"]:
        print("\nSources:")
        for p in result["passages"]:
            print(f"  - {p['source']} — {p['heading']}  (similarity {p['similarity']})")
