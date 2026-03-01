import sqlite3
from pathlib import Path


def run_migration() -> None:
    """Safely executes ALTER TABLE statements to append the search context columns."""

    # Assumption: Your SQLite DB is named 'database.db' in the project root.
    # Adjust this path if you are using a different environment variable/file name.
    db_path = Path("data/integration.db")

    if not db_path.exists():
        print(f"Error: Database file not found at {db_path.absolute()}")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # 1. Update SyncState to hold the persistent search memory
        print("Migrating 'syncstate' table...")
        cursor.execute("ALTER TABLE syncstate ADD COLUMN search_context VARCHAR;")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("  -> 'search_context' already exists in 'syncstate'. Skipping.")
        else:
            raise

    try:
        # 2. Update SyncAuditLog to hold the searchable index
        print("Migrating 'syncauditlog' table...")
        cursor.execute("ALTER TABLE syncauditlog ADD COLUMN search_vector VARCHAR;")

        # 3. Create the index for fast ILIKE/LIKE lookups
        print("Creating index on 'syncauditlog.search_vector'...")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_syncauditlog_search_vector ON syncauditlog (search_vector);")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("  -> 'search_vector' already exists in 'syncauditlog'. Skipping.")
        else:
            raise

    conn.commit()
    conn.close()
    print("Migration completed successfully.")


if __name__ == "__main__":
    run_migration()
