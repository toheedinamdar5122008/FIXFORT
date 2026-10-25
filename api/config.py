import os
from pathlib import Path
from pydantic import BaseModel

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env file from project root
load_dotenv(dotenv_path=BASE_DIR / ".env")

class Settings(BaseModel):
    environment: str = os.getenv("ENVIRONMENT", "demonstration")
    database_url: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./fixfort.db"
    )
    
    live_shield_url: str = os.getenv("LIVE_SHIELD_URL", "http://localhost:8080")
    sandbox_shield_url: str = os.getenv("SANDBOX_SHIELD_URL", "http://localhost:8081")
    
    live_shield_container: str = os.getenv("LIVE_SHIELD_CONTAINER", "shield-live")
    sandbox_shield_container: str = os.getenv("SANDBOX_SHIELD_CONTAINER", "shield-sandbox")
    
    rules_live_dir: Path = Path(os.getenv("RULES_LIVE_DIR", str(BASE_DIR / "shield" / "rules-live")))
    rules_sandbox_dir: Path = Path(os.getenv("RULES_SANDBOX_DIR", str(BASE_DIR / "shield" / "rules-sandbox")))
    logs_file_path: Path = Path(os.getenv("SHIELD_LOGS_PATH", str(BASE_DIR / "shield" / "logs" / "access.log")))
    
    # Execution mode: 'docker' uses subprocess docker exec. 'local' allows running without docker container.
    shield_exec_mode: str = os.getenv("SHIELD_EXEC_MODE", "local")
    
    cors_origins: list[str] = [
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,*"
        ).split(",")
        if origin.strip()
    ]
    
    event_poll_interval_sec: float = float(os.getenv("EVENT_POLL_INTERVAL_SEC", "0.5"))
    demo_target_url: str = os.getenv("DEMO_TARGET_URL", "http://localhost:8080")

    # Agent37 Cloud Configuration
    agent37_api_key: str = os.getenv("AGENT37_API_KEY", "")
    agent37_instance_id: str = os.getenv("AGENT37_INSTANCE_ID", "d1r7b60za3")
    agent37_base_url: str = os.getenv("AGENT37_BASE_URL", "https://d1r7b60za3.agent37.app")
    agent37_timeout_seconds: float = float(os.getenv("AGENT37_TIMEOUT_SECONDS", "25"))

settings = Settings()

