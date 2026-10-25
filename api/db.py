import os
from dotenv import load_dotenv
from sqlmodel import SQLModel, create_engine, Session
from api.config import settings

# Ensure environment is loaded
load_dotenv()

# Ensure connection string explicitly uses the postgresql:// protocol prefix
raw_db_url = settings.database_url or os.getenv("DATABASE_URL", "")
if raw_db_url.startswith("postgres://"):
    database_url = raw_db_url.replace("postgres://", "postgresql://", 1)
else:
    database_url = raw_db_url

# Configure connect_args based on DB dialect
connect_args = {}
if database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False
else:
    # Explicitly pass sslmode: require for PostgreSQL / Aiven Cloud
    connect_args["sslmode"] = "require"

engine = create_engine(
    database_url,
    connect_args=connect_args,
    echo=False
)

def init_db():
    """Build all missing tables automatically on startup."""
    import api.models  # noqa: F401 - Register SQLModel tables
    SQLModel.metadata.create_all(engine)

def get_session():
    """FastAPI dependency session generator."""
    with Session(engine) as session:
        yield session

def reset_db():
    """Drops and re-creates all tables cleanly for reset/demo routines."""
    import api.models  # noqa: F401
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
