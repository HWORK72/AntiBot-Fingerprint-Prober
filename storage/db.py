from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from core.config import settings
from core.logger import logger


class Base(DeclarativeBase):
    pass


class DatabaseSessionManager:

    def __init__(self) -> None:
        self.engine: AsyncEngine | None = None
        self.session_factory: async_sessionmaker[AsyncSession] | None = None
        self.is_connected: bool = False

    def initialize(self) -> None:
        try:
            self.engine = create_async_engine(
                url=settings.postgres_async_url,
                echo=False,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True
            )
            self.session_factory = async_sessionmaker(
                bind=self.engine,
                autoflush=False,
                expire_on_commit=False,
                class_=AsyncSession
            )
        except Exception as exc:
            logger.warning(f"PostgreSQL configuration initialization error: {exc}")

    async def create_tables(self) -> bool:
        if not self.engine:
            return False
        try:
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            self.is_connected = True
            logger.info("PostgreSQL schema successfully synchronized.")
            return True
        except Exception as exc:
            logger.warning(f"PostgreSQL unreachable ({exc}). Operating in graceful fallback mode without persistence.")
            self.is_connected = False
            return False

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        if not self.session_factory:
            return
        async with self.session_factory() as session:
            try:
                yield session
            except Exception as exc:
                await session.rollback()
                logger.error(f"Database transaction failure: {exc}", exc_info=True)
                raise
            finally:
                await session.close()

    async def close(self) -> None:
        if self.engine:
            await self.engine.dispose()
            logger.info("PostgreSQL connection pool disposed.")


db_manager: DatabaseSessionManager = DatabaseSessionManager()