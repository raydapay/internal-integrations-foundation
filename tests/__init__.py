import os

# Intercept the configuration pipeline at the root of test discovery.
# This strictly isolates the physical database, ensuring TestClient lifespan
# events or un-mocked sessions operate exclusively in ephemeral memory.
os.environ["SQLITE_DB_PATH"] = ":memory:"
