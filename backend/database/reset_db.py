"""Reset Aurora DB schema used by Sentinel development workflows."""

from __future__ import annotations

import argparse

from src.pathing import ensure_backend_root_on_path

ensure_backend_root_on_path()

from src.db import get_database, load_sql_statements, migration_file
from seed_data import main as seed_main


DROP_STATEMENTS = [
    "DROP TABLE IF EXISTS chat_messages",
    "DROP TABLE IF EXISTS follow_ups",
    "DROP TABLE IF EXISTS remediation_actions",
    "DROP TABLE IF EXISTS live_incidents",
    "DROP TABLE IF EXISTS live_signals",
    "DROP TABLE IF EXISTS live_log_events",
    "DROP TABLE IF EXISTS live_log_sources",
    "DROP TABLE IF EXISTS live_services",
    "DROP TABLE IF EXISTS live_applications",
    "DROP TABLE IF EXISTS integrations",
    "DROP TABLE IF EXISTS jobs",
    "DROP TABLE IF EXISTS incidents",
    "DROP TABLE IF EXISTS live_monitor_configs",
    "DROP TABLE IF EXISTS user_entitlements",
    "DROP TABLE IF EXISTS users",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--with-test-data",
        action="store_true",
        help="Seed sample incidents after reset and migration.",
    )
    args = parser.parse_args()

    db = get_database()
    try:
        db.execute_script(DROP_STATEMENTS)
        statements = load_sql_statements(migration_file())
        db.execute_script(statements)
        print("Reset complete (schema dropped and recreated).")
    finally:
        db.close()

    if args.with_test_data:
        seed_main()


if __name__ == "__main__":
    main()
