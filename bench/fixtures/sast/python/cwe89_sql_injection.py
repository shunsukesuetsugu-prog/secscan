"""CWE-89 fixture: SQL injection via string concatenation.

Expected to be detected by p/python or p/owasp-top-ten rules.
"""

from __future__ import annotations

import sqlite3


def fetch_user(conn: sqlite3.Connection, user_id: str) -> object:
    cur = conn.cursor()
    # CWE-89: user_id concatenated directly into the SQL statement.
    cur.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
    return cur.fetchone()


def search_by_name(conn: sqlite3.Connection, name: str) -> object:
    cur = conn.cursor()
    # CWE-89: f-string interpolation into SQL.
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchall()
