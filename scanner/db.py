import sqlite3
import json
from typing import List
from schemas.models import Suspect, InventoryItem

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
        run_id TEXT,
        status TEXT DEFAULT 'Open',
        resolution_metadata TEXT,
        -- Algorithm Details (Must-Capture)
        cipher_mode TEXT,
        hash_algorithm TEXT,
        -- Key Lifecycle (Must-Capture)
        key_created_at TEXT,
        key_expires_at TEXT,
        rotation_frequency_days INTEGER,
        -- Library Info (Must-Capture)
        library_name TEXT,
        library_version TEXT,
        -- Protocol Details (Must-Capture)
        protocol_version TEXT,
        has_pfs BOOLEAN,
        -- Ownership (Must-Capture)
        owner_team TEXT,
        owner_contact TEXT,
        -- Risk Scoring
        remediation TEXT,
        data_longevity_years INTEGER,
        data_sensitivity TEXT,
        hndl_score REAL,
        risk_level TEXT,
        source_type TEXT,
        cloud_provider TEXT
    )
    ''')
    
    # Migration: Add columns if they don't exist (SQLite doesn't support IF NOT EXISTS in ALTER)
    new_columns = [
        ('status', 'TEXT DEFAULT "Open"'),
        ('resolution_metadata', 'TEXT'),
        ('cipher_mode', 'TEXT'),
        ('hash_algorithm', 'TEXT'),
        ('key_created_at', 'TEXT'),
        ('key_expires_at', 'TEXT'),
        ('rotation_frequency_days', 'INTEGER'),
        ('library_name', 'TEXT'),
        ('library_version', 'TEXT'),
        ('protocol_version', 'TEXT'),
        ('has_pfs', 'BOOLEAN'),
        ('owner_team', 'TEXT'),
        ('owner_contact', 'TEXT'),
        ('remediation', 'TEXT'),
        ('data_longevity_years', 'INTEGER'),
        ('data_sensitivity', 'TEXT'),
        ('hndl_score', 'REAL'),
        ('risk_level', 'TEXT'),
        ('source_type', 'TEXT'),
        ('cloud_provider', 'TEXT'),
    ]
    for col_name, col_type in new_columns:
        try:
            c.execute(f'ALTER TABLE inventory ADD COLUMN {col_name} {col_type}')
        except sqlite3.OperationalError:
            pass  # Column already exists

    # New Table: Scan Metrics
    c.execute('''
    CREATE TABLE IF NOT EXISTS scan_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT,
        model TEXT,
        input_tokens INTEGER,
        output_tokens INTEGER,
        cost_usd REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
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

def save_scan_metric(db_path: str, run_id: str, model: str, input_tokens: int, output_tokens: int, cost: float):
    """Saves a single AI interaction metric."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
    INSERT INTO scan_metrics (run_id, model, input_tokens, output_tokens, cost_usd)
    VALUES (?, ?, ?, ?, ?)
    ''', (run_id, model, input_tokens, output_tokens, cost))
    conn.commit()
    conn.close()

def save_inventory_item(db_path: str, item: InventoryItem, run_id: str):
    """Saves a single InventoryItem to the database with all Must-Capture fields."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
    INSERT OR REPLACE INTO inventory (
        id, path, line, name, category, algorithm, key_size, is_pqc_vulnerable, 
        description, run_id, remediation, cipher_mode, hash_algorithm,
        key_created_at, key_expires_at, rotation_frequency_days,
        library_name, library_version, protocol_version, has_pfs,
        owner_team, owner_contact, data_longevity_years, data_sensitivity,
        hndl_score, risk_level, source_type, cloud_provider
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        item.id,
        item.path,
        item.line,
        item.name,
        item.category,
        item.algorithm,
        item.key_size,
        item.is_pqc_vulnerable,
        item.description,
        run_id,
        item.remediation,
        item.cipher_mode,
        item.hash_algorithm,
        item.key_created_at,
        item.key_expires_at,
        item.rotation_frequency_days,
        item.library_name,
        item.library_version,
        item.protocol_version,
        item.has_pfs,
        item.owner_team,
        item.owner_contact,
        item.data_longevity_years,
        item.data_sensitivity,
        item.hndl_score,
        item.risk_level,
        item.source_type,
        item.cloud_provider
    ))
    conn.commit()
    conn.close()
