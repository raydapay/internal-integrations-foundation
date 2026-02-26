import asyncio
import logging

from sqlalchemy import text

from src.core.database import engine

logger = logging.getLogger(__name__)


async def fix_mapping_enum_case() -> None:
    """Aligns raw SQLite enum strings with SQLAlchemy's uppercase expectations."""
    async with engine.begin() as conn:
        print("Fixing Enum casing in rulefieldmapping table...")

        await conn.execute(text("UPDATE rulefieldmapping SET source_type = 'STATIC' WHERE source_type = 'static'"))
        await conn.execute(
            text("UPDATE rulefieldmapping SET source_type = 'PF_PAYLOAD' WHERE source_type = 'pf_payload'")
        )
        await conn.execute(text("UPDATE rulefieldmapping SET source_type = 'TEMPLATE' WHERE source_type = 'template'"))

        print("Database fix complete. Enum names aligned.")


if __name__ == "__main__":
    asyncio.run(fix_mapping_enum_case())
