"""
config.py — Central configuration.

All "magic numbers" and choices (model name, thresholds, file paths) live here in
one place, so tuning a threshold never means hunting through the codebase.
Keeping configuration separate from logic is standard practice.
"""

from pathlib import Path
from datetime import timedelta

# --- File paths ---
ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "soc.db"
LOG_PATH = DATA_DIR / "sample_logs.json"

# --- Foundry Local model selection ---
# Application name (tells the SDK where to store data; no spaces/special chars).
APP_NAME = "soc-assistant"

# LLM used for reasoning (analysis).
# Default is a small, FAST model: runs instantly, small download.
# For higher quality (but slower on CPU, large download): "phi-4-mini" or "qwen2.5-7b".
CHAT_MODEL = "qwen2.5-1.5b"

# Embedding model for retrieval (finding the most relevant ATT&CK technique).
EMBED_MODEL = "qwen3-embedding-0.6b"

# --- Detection thresholds ---
# Brute force: how many failed logons within what time window count as suspicious.
BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW = timedelta(minutes=5)

# Kerberos password spray: threshold of 4771 pre-authentication failures.
# The threshold is low because spraying uses few attempts against many accounts.
KERBEROS_FAILURE_THRESHOLD = 2

# --- LLM execution ---
# Foundry Local serves a single model instance on the CPU, so analysing incidents in
# parallel does not make them finish sooner — the requests contend and the runtime
# starts cancelling them. Raise this only on a runtime that genuinely serves
# concurrent requests.
LLM_CONCURRENCY = 1

# The local runtime cancels a request that takes too long to generate on CPU — it
# surfaces as "Operation was cancelled". Capping the answer length keeps a report
# inside that budget; raise it only if your machine generates faster.
LLM_MAX_TOKENS = 700

# A fixed seed makes the same incident produce the same report. A security finding
# that changes between runs cannot be reviewed or audited.
LLM_SEED = 42

# --- Evidence package (LLM context) ---
# Log fields are attacker-controlled and unbounded: a crafted command line could fill
# the whole context window on its own. Clip each field and cap how many events go in.
MAX_FIELD_CHARS = 300
MAX_CONTEXT_EVENTS = 50

# --- Correlation ---
# Signals on the same host within this window are grouped into a single incident.
CORRELATION_WINDOW = timedelta(minutes=15)
