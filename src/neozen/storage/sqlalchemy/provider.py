"""Dishka provider for the SQLAlchemy storage backend."""

from __future__ import annotations

import typing
from collections.abc import AsyncIterator

import dishka
import sqlalchemy
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from neozen.core.repository import RepositoryProtocol
from neozen.storage.sqlalchemy.repositories import NeoZenRepository

# A dict, not functools.cache: mypy doesn't treat class objects as Hashable.
_repository_classes: dict[type[typing.Any], type[NeoZenRepository[typing.Any]]] = {}


def _repository_class(model: type[typing.Any]) -> type[NeoZenRepository[typing.Any]]:
    """One ``NeoZenRepository`` subclass per model, keyed on its primary key."""
    if model in _repository_classes:
        return _repository_classes[model]
    attributes: dict[str, typing.Any] = {"model_type": model}
    mapper = sqlalchemy.inspect(model)
    # Composite keys keep Advanced Alchemy's default, which handles them.
    if len(mapper.primary_key) == 1:
        column = mapper.primary_key[0]
        attributes["id_attribute"] = mapper.get_property_by_column(column).key
    cls = type(f"{model.__name__}Repository", (NeoZenRepository,), attributes)
    _repository_classes[model] = cls
    return cls


class SQLAlchemyProvider(dishka.Provider):
    """Provides the engine, a per-request session and a repository per model.

    The request session never commits on its own: callers commit what they
    mean to keep, and anything uncommitted is rolled back when the request
    scope closes. (Committing on scope exit would be wrong under Litestar,
    whose exception handler runs inside the scope, so failed requests would
    commit, after the response was sent.)

    Example:
        container = dishka.make_async_container(
            SQLAlchemyProvider("sqlite+aiosqlite:///app.db"),
            EmailIdentifierProvider(),
        )
        async with container() as request:
            identifier = await request.get(IdentifierProtocol[Subject])
    """

    def __init__(self, url: str) -> None:
        super().__init__()
        self.url = url

    @dishka.provide(scope=dishka.Scope.APP)
    async def engine(self) -> AsyncIterator[AsyncEngine]:
        engine = create_async_engine(self.url)
        yield engine
        await engine.dispose()

    @dishka.provide(scope=dishka.Scope.APP)
    def sessionmaker(self, engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
        return async_sessionmaker(engine, expire_on_commit=False)

    @dishka.provide(scope=dishka.Scope.REQUEST)
    async def session(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> AsyncIterator[AsyncSession]:
        async with sessionmaker() as session:
            yield session

    @dishka.provide(scope=dishka.Scope.REQUEST)
    def repository[M](
        self, model: type[M], session: AsyncSession
    ) -> RepositoryProtocol[M]:
        return _repository_class(model)(session=session)


__all__ = ["SQLAlchemyProvider"]
