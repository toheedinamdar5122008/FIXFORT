import json
import logging
from pathlib import Path
from sqlmodel import Session, select
from api.models import Finding, FindingStatus, get_utc_now
from api.db import engine
from api.config import BASE_DIR

logger = logging.getLogger("fixfort.seed")

def seed_sample_findings():
    """Seeds sample findings into the database, guaranteeing mock finding F-001 exists."""
    findings_dir = BASE_DIR / "findings"
    
    if findings_dir.exists():
        with Session(engine) as session:
            for json_path in findings_dir.glob("*.json"):
                if "zap" in json_path.name.lower():
                    continue
                try:
                    data = json.loads(json_path.read_text(encoding="utf-8"))
                    f_id = data.get("id")
                    if not f_id:
                        continue

                    existing = session.get(Finding, f_id)
                    if not existing:
                        finding = Finding(
                            id=f_id,
                            target=data.get("target", "/login"),
                            parameter=data.get("parameter", "username"),
                            type=data.get("type", "sqli"),
                            severity=data.get("severity", "high"),
                            source=data.get("source", "zap"),
                            description=data.get("description", ""),
                            status=FindingStatus.NEW,
                            created_at=get_utc_now()
                        )
                        session.add(finding)
                        logger.info("Seeded finding: %s", f_id)
                except Exception as e:
                    logger.error("Failed seeding finding from %s: %s", json_path, e)
            session.commit()

    # Always ensure initial mock finding F-001 is populated
    with Session(engine) as session:
        if not session.get(Finding, "F-001"):
            finding = Finding(
                id="F-001",
                target="/login",
                parameter="username",
                type="sqli",
                severity="high",
                source="zap",
                description="Login query built by string concatenation",
                status=FindingStatus.NEW,
                created_at=get_utc_now()
            )
            session.add(finding)
            session.commit()
            logger.info("Default mock finding F-001 seeded.")

if __name__ == "__main__":
    from api.db import init_db
    init_db()
    seed_sample_findings()
