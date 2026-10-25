"""
FixFort Aiven PostgreSQL Database & Schema Verification Script
"""
import sys
from sqlmodel import inspect, Session, select
from api.db import engine, init_db
from api.models import Finding, RuleAttempt, Deployment, Event

def verify_database():
    print("=" * 60)
    print("FixFort Database Verification (Aiven PostgreSQL)")
    print("=" * 60)
    
    # 1. Ping / Connect & Init
    print(f"[*] Connecting to: {engine.url.render_as_string(hide_password=True)}")
    init_db()
    print("[+] Database connected and init_db() completed.")
    
    # 2. Inspect Tables
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()
    print(f"[*] Detected tables: {existing_tables}")
    
    expected_tables = ["findings", "rule_attempts", "deployments", "events"]
    for table_name in expected_tables:
        if table_name in existing_tables:
            columns = [c["name"] for c in inspector.get_columns(table_name)]
            print(f"  [+] Table '{table_name}': OK (Columns: {', '.join(columns)})")
        else:
            print(f"  [-] Table '{table_name}': MISSING")
            sys.exit(1)
            
    # 3. Query Mock Finding F-001
    with Session(engine) as session:
        f = session.get(Finding, "F-001")
        if f:
            print(f"[+] Verified seed finding: {f.id} (target={f.target}, status={f.status})")
        else:
            print("[-] Warning: Seed finding F-001 not found.")
            
    print("=" * 60)
    print("[SUCCESS] All 4 SQLModel tables verified on Aiven Cloud!")
    print("=" * 60)

if __name__ == "__main__":
    verify_database()
