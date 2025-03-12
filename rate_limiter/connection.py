import os
import databases
import sqlalchemy
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()
engine = sqlalchemy.create_engine(DATABASE_URL)


async def connect_db():
    """Connects to the database."""
    await database.connect()


async def disconnect_db():
    """Disconnects from the database."""
    await database.disconnect()


def create_tables():
    """Creates all tables defined in the metadata."""
    metadata.create_all(engine)


async def get_db():
    """Provides a database session to route handlers.

    Yields:
        databases.Database: A database connection object.
    """
    try:
        await database.connect()
        yield database
    finally:
        await database.disconnect()
