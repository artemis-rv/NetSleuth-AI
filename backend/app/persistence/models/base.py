from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    """
    SQLAlchemy Declarative Base.
    This acts purely as the mapping layer to the DB-7 Alembic physical schema.
    It does NOT serve as the source of truth for creating constraints.
    """
    pass
