"""Borderline-clean counterpart to cwe89_sql_injection.py.

Uses parameter binding (the documented safe pattern). A scanner that
flags this is a false positive.
"""

from __future__ import annotations

import sqlite3


def fetch_user_safely(conn: sqlite3.Connection, user_id: str) -> object:
    cur = conn.cursor()
    # NOT a CWE-89: parameterised query.
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def search_by_name_safely(conn: sqlite3.Connection, name: str) -> object:
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cur.fetchall()
