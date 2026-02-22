import asyncio

from sqlalchemy import text

from src.core.database import engine


async def fix_enum_case() -> None:
    async with engine.begin() as conn:
        print("Fixing Enum casing in routingrule table...")
        await conn.execute(text("UPDATE routingrule SET action = 'SYNC' WHERE action = 'sync'"))
        await conn.execute(text("UPDATE routingrule SET action = 'DROP' WHERE action = 'drop'"))
        print("Database fix complete. Enum names aligned.")


if __name__ == "__main__":
    asyncio.run(fix_enum_case())
