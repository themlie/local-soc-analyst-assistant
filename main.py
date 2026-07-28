"""
main.py — Orchestrator: runs the whole pipeline end to end.

Flow:
    ingest  ->  detect + correlate  ->  reason (LLM)  ->  validate  ->  report

Usage:
    python main.py                       # default model from config.py
    python main.py --model phi-4-mini    # higher-quality model
    python main.py --evtx <file.evtx>    # analyze a real EVTX file
"""

import argparse
import asyncio
import sys
import common.console  # noqa: F401

from ingest.ingest import ingest_file, ingest_events
from detect.correlate import build_incidents
from reason.analyst import analyze_incident
from reason.context import build_context
from validate.grounding import validate_report
from ui.report import render_report
from config import CHAT_MODEL, LLM_CONCURRENCY
from common.logger import get_logger

logger = get_logger()


async def process_incident(incident, model, limit):
    # Build the evidence once and reuse it, so the validator checks the report against
    # exactly the text the model was given rather than a rebuilt approximation.
    context = build_context(incident)
    async with limit:  # bound how many incidents may occupy the model at once
        try:
            # LLM calls are synchronous in the SDK, so we run them in a separate thread
            report = await asyncio.to_thread(
                analyze_incident, incident, alias=model, context=context
            )
        except Exception:
            logger.error(f"Could not analyze incident on {incident['host']}", exc_info=True)
            return
    validation = validate_report(report, incident, context=context)
    render_report(incident, report, validation)

async def async_run(model: str = CHAT_MODEL, evtx: str | None = None, file: str | None = None) -> None:
    try:
        # 1) Normalize raw logs and write them to the database
        if evtx:
            from ingest.win_evtx import parse_evtx
            n = ingest_events(parse_evtx(evtx))
            logger.info(f"[ingest]    {n} events (real EVTX): {evtx}")
        elif file:
            from pathlib import Path
            import json as _json
            n = ingest_events(_json.loads(Path(file).read_text(encoding="utf-8")))
            logger.info(f"[ingest]    {n} events (JSON): {file}")
        else:
            n = ingest_file()
            logger.info(f"[ingest]    {n} events written to the database.")

        # 2) Run detectors + group signals into incidents
        incidents = build_incidents()
        logger.info(f"[correlate] {len(incidents)} incident(s) built.\n")

        if not incidents:
            logger.info("No suspicious activity found. Logs look clean.")
            return

        # 3) For each incident: LLM analysis + validation + report
        logger.info(f"[reason]    Loading model: {model} (may download on first run)...\n")
        
        # Incidents are dispatched together, but LLM_CONCURRENCY decides how many may
        # actually hold the model — with a single local model that is deliberately 1.
        limit = asyncio.Semaphore(LLM_CONCURRENCY)
        tasks = [process_incident(incident, model, limit) for incident in incidents]
        await asyncio.gather(*tasks)
    except Exception as e:
        logger.error("A fatal error occurred during the run", exc_info=True)
        sys.exit(1)

def run(model: str = CHAT_MODEL, evtx: str | None = None, file: str | None = None) -> None:
    asyncio.run(async_run(model=model, evtx=evtx, file=file))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Local SOC Analyst Assistant")
    parser.add_argument("--model", default=CHAT_MODEL,
                        help="Foundry Local model to use (alias)")
    parser.add_argument("--evtx", default=None,
                        help="Analyze a real .evtx file instead of the synthetic data")
    parser.add_argument("--file", default=None,
                        help="Analyze an arbitrary JSON log file")
    args = parser.parse_args()
    run(model=args.model, evtx=args.evtx, file=args.file)
