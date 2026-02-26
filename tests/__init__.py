import logging
import os

from loguru import logger

# Intercept the configuration pipeline at the root of test discovery.
# This strictly isolates the physical database, ensuring TestClient lifespan
# events or un-mocked sessions operate exclusively in ephemeral memory.
os.environ["SQLITE_DB_PATH"] = ":memory:"

# Globally mute application logs during testing to prevent terminal noise
# from unhappy-path testing (404s, validation errors, etc.)
logger.disable("src")

# Suppress native asyncio debug warnings caused by simulated latency
# (e.g., WAL lock contention tests) exceeding the 100ms slow callback threshold.
logging.getLogger("asyncio").setLevel(logging.ERROR)
