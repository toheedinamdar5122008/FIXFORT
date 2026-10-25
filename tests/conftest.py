import os
import tempfile
import pytest
from pathlib import Path
from sqlmodel import SQLModel, create_engine, Session
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from api.config import settings
from api.db import get_session
from api.main import app

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    temp_dir = tempfile.TemporaryDirectory()
    temp_path = Path(temp_dir.name)
    
    settings.environment = "test"
    settings.shield_exec_mode = "local"
    settings.rules_live_dir = temp_path / "shield" / "rules-live"
    settings.rules_sandbox_dir = temp_path / "shield" / "rules-sandbox"
    settings.logs_file_path = temp_path / "shield" / "logs" / "access.log"
    settings.rules_live_dir.mkdir(parents=True, exist_ok=True)
    settings.rules_sandbox_dir.mkdir(parents=True, exist_ok=True)
    settings.logs_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    yield
    
    temp_dir.cleanup()

@pytest.fixture(name="db_session")
def db_session_fixture():
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    SQLModel.metadata.create_all(test_engine)
    
    import api.db
    old_engine = api.db.engine
    api.db.engine = test_engine
    
    with Session(test_engine) as session:
        yield session
        
    SQLModel.metadata.drop_all(test_engine)
    api.db.engine = old_engine

@pytest.fixture(name="client")
def client_fixture(db_session: Session):
    def get_session_override():
        yield db_session

    app.dependency_overrides[get_session] = get_session_override
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
