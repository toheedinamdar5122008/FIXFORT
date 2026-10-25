import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List
from sqlmodel import Session
from api.config import settings
from api.db import engine
from api.models import Event

logger = logging.getLogger("fixfort.events")

# Sanitization regex to mask passwords or tokens in logged query strings
SENSITIVE_PARAM_PATTERN = re.compile(r"(password|pwd|token|secret|auth|apikey|access_token)=([^&]+)", re.IGNORECASE)

def sanitize_query(query: Optional[str]) -> Optional[str]:
    if not query:
        return None
    return SENSITIVE_PARAM_PATTERN.sub(r"\1=[REDACTED]", query)

class EventFeedReader:
    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path or settings.logs_file_path
        self.offset = 0
        self.running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="FixFortEventFeed")
        self._thread.start()
        logger.info("Event feed reader started on %s", self.log_path)

    def stop(self):
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("Event feed reader stopped.")

    def _run_loop(self):
        while self.running:
            try:
                self.process_new_events()
            except Exception as e:
                logger.error("Error processing access log events: %s", e)
            time.sleep(settings.event_poll_interval_sec)

    def process_new_events(self) -> int:
        """
        Reads newly appended lines from the Nginx JSON access log, parses them,
        and saves them into the events table. Returns the count of new events inserted.
        """
        if not self.log_path.exists():
            return 0

        current_size = self.log_path.stat().st_size
        # Handle log file truncation or rotation
        if current_size < self.offset:
            logger.info("Log file truncated or rotated; resetting offset from %d to 0", self.offset)
            self.offset = 0

        new_events: List[Event] = []

        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self.offset)
                lines = f.readlines()
                self.offset = f.tell()

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    event = self._parse_log_entry(data)
                    if event:
                        new_events.append(event)
                except json.JSONDecodeError:
                    # Ignore incomplete trailing fragments or malformed lines
                    continue
                except Exception as e:
                    logger.warning("Failed parsing log record: %s (line: %s)", e, line[:100])

            if new_events:
                with Session(engine) as session:
                    for evt in new_events:
                        session.add(evt)
                    session.commit()
                logger.debug("Ingested %d new shield events", len(new_events))

            return len(new_events)

        except Exception as e:
            logger.error("Exception reading log file %s: %s", self.log_path, e)
            return 0

    def _parse_log_entry(self, data: dict) -> Optional[Event]:
        # Extract timestamp
        ts_str = data.get("time") or data.get("time_local")
        ts = None
        if ts_str:
            try:
                # Handle ISO 8601 e.g. 2026-10-16T15:20:00+00:00
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                ts = datetime.now(timezone.utc)
        if not ts:
            ts = datetime.now(timezone.utc)

        method = str(data.get("method") or data.get("request_method") or "GET").upper()
        path = str(data.get("path") or data.get("uri") or "/")
        raw_query = data.get("query") or data.get("args") or None
        query = sanitize_query(str(raw_query)) if raw_query else None
        
        try:
            status_code = int(data.get("status", 200))
        except (ValueError, TypeError):
            status_code = 200

        outcome = "blocked" if status_code == 403 else "allowed"
        rule_id = data.get("rule_id") or None
        if rule_id and str(rule_id).strip() in ("-", "null", ""):
            rule_id = None

        return Event(
            ts=ts,
            method=method,
            path=path,
            query=query,
            status_code=status_code,
            outcome=outcome,
            rule_id=rule_id
        )

# Global singleton event reader instance
event_reader = EventFeedReader()
