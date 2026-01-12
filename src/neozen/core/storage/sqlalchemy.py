"""SQLAlchemy storage implementation for NeoZen."""

from __future__ import annotations

import typing
from collections.abc import AsyncIterable, Callable, Coroutine, Iterable

import dishka
from sqlalchemy import URL, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from neozen.core.storage.base import DoesNotExist, StorageProtocol, StorageProvider


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for NeoZen models."""


class SQLAlchemyStorage[Model](StorageProtocol[Model]):
    """SQLAlchemy-based storage implementation."""

    def __init__(self, model: type[Model], session: AsyncSession) -> None:
        self.model = model
        self.session = session

    async def get_one_by(self, **filters: typing.Any) -> Model:
        statement = select(self.model).filter_by(**filters)
        result = await self.session.execute(statement)
        obj = result.scalar_one_or_none()
        if obj is None:
            raise DoesNotExist
        return obj

    async def create(self, **data: typing.Any) -> Model:
        obj = self.model(**data)
        self.session.add(obj)
        await self.session.flush()
        return obj

    async def update(self, obj: Model, **data: typing.Any) -> Model:
        for key, value in data.items():
            setattr(obj, key, value)
        self.session.add(obj)
        await self.session.flush()
        return obj


class SQLAlchemyEngineProvider(StorageProvider):
    """Dishka provider for SQLAlchemy engine and session management."""

    def __init__[Model](
        self, url: str | URL, models: Iterable[type[Model]] | None = None
    ) -> None:
        super().__init__(models=models)
        self.url = url

    @dishka.provide(scope=dishka.Scope.APP)
    async def get_engine(self) -> AsyncIterable[AsyncEngine]:
        engine = create_async_engine(self.url)
        yield engine
        await engine.dispose()

    @dishka.provide(scope=dishka.Scope.APP)
    async def get_sessionmaker(
        self, engine: AsyncEngine
    ) -> async_sessionmaker[AsyncSession]:
        return async_sessionmaker(engine, expire_on_commit=False)

    @dishka.provide(scope=dishka.Scope.REQUEST)
    async def get_session(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> AsyncIterable[AsyncSession]:
        async with sessionmaker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            else:
                await session.commit()

    def _get_storage_factory(
        self,
    ) -> Callable[..., Coroutine[None, None, StorageProtocol[typing.Any]]]:
        async def _get_storage[Model](
            model: type[Model],
            session: AsyncSession,
        ) -> StorageProtocol[Model]:
            return SQLAlchemyStorage[Model](model, session)

        return _get_storage


__all__ = [
    "Base",
    "SQLAlchemyEngineProvider",
    "SQLAlchemyStorage",
]
