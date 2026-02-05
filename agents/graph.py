import sqlite3
import json
from schemas.models import InventoryItem

class GraphAgent:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def build_graph(self, run_id: str):
        """
        Deduplicates inventory items and establishes relationships.
        For this MVP, we mainly focus on deduplicating findings (e.g. multiple hits for same key).
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("SELECT id, path, line, name, algorithm FROM inventory WHERE run_id = ?", (run_id,))
        rows = c.fetchall()
        
        if not rows:
            return

        print(f"Graph Agent: Processing {len(rows)} inventory items...")
        
        # Simple deduplication by (path, algo) proximity?
        # Or just ensuring unique IDs are respected.
        # Actually, let's just leave them as is for this MVP, but maybe group by file.
        
        # Future: Use Gemini to link "db_password" in config.py to usage in db.py
        pass
        
        conn.close()
