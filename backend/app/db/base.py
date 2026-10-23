"""Declarative base class for SQLAlchemy 2.0 ORM models."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all persistent database models."""

    pass
