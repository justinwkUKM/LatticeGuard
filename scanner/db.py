import sqlite3
import json
from typing import List
from schemas.models import Suspect

def init_db(db_path: str):
    """Initializes the SQLite database with required tables."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Enable WAL mode for better concurrency
    c.execute('PRAGMA journal_mode=WAL;')
    
    c.execute('''
    CREATE TABLE IF NOT EXISTS suspects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT,
        line INTEGER,
        content_snippet TEXT,
        type TEXT,
        pattern_matched TEXT,
        confidence TEXT,
        run_id TEXT
    )
    ''')
    
    c.execute('''
    CREATE TABLE IF NOT EXISTS inventory (
        id TEXT PRIMARY KEY,
        path TEXT,
        line INTEGER,
        name TEXT,
        category TEXT,
        algorithm TEXT,
        key_size INTEGER,
        is_pqc_vulnerable BOOLEAN,
        description TEXT,
        run_id TEXT
    )
    ''')

    conn.commit()
    conn.close()

def save_suspects(db_path: str, run_id: str, suspects: List[Suspect]):
    """Bulk inserts suspects into the DB."""
    if not suspects:
        return

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    data = [
        (s.path, s.line, s.content_snippet, s.type, s.pattern_matched, s.confidence, run_id)
        for s in suspects
    ]
    
    c.executemany('''
    INSERT INTO suspects (path, line, content_snippet, type, pattern_matched, confidence, run_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', data)
    
    conn.commit()
    conn.close()
