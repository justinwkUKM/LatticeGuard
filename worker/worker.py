import redis
import os
import json
import time

# Redis Connection
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)

print(f"Worker started. Listening on {REDIS_HOST}:{REDIS_PORT}...")

from scanner.files import ArtifactScanner
from scanner.db import save_suspects, init_db
from pathlib import Path

# ... (Previous Redis setup remains)

import subprocess
import shutil

def process_discovery(job_id, repo_path):
    if not repo_path:
        print(f"[{job_id}] ❌ Error: No repo_path provided.")
        return False

    target_path = repo_path
    is_temp = False
    
    # Check if Remote URL
    if repo_path.startswith(("http://", "https://", "git@")):
        print(f"[{job_id}] 🌍 Detected Remote Repo: {repo_path}")
        is_temp = True
        target_path = f"/data/temp/{job_id}"
        
        # Clone strategy: Partial clone for speed
        # SECURITY: Use '--' to prevent argument injection from repo_path
        try:
            subprocess.run(["git", "clone", "--depth", "1", "--", repo_path, target_path], check=True, timeout=300)
            print(f"[{job_id}] ✅ Cloned to {target_path}")
        except subprocess.CalledProcessError as e:
            print(f"[{job_id}] ❌ Clone Failed: {e}")
            return False

    print(f"[{job_id}] 🔍 Starting Discovery on {target_path}")
    scanner = ArtifactScanner(target_path)
    
    count = 0
    pipe = redis_client.pipeline()
    
    for file_path in scanner.scan():
        # Push sub-task for individual file analysis
        sub_task = {
            "type": "ANALYZE_FILE",
            "parent_job_id": job_id,
            "repo_path": target_path,
            "file_path": file_path,
            "cleanup": is_temp # Propagate cleanup flag if needed
        }
        pipe.lpush("pqc_tasks", json.dumps(sub_task))
        count += 1
        
        # Batch push every 100 items
        if count % 100 == 0:
            pipe.execute()
            
    pipe.execute() # Push remaining
    print(f"[{job_id}] 🚀 Discovered {count} files. Queued for analysis.")
    return True

from scanner.patterns import PatternScanner
import shutil
import hashlib

from scanner.dependencies import DependencyScanner

def process_analysis(parent_job_id, repo_path, file_path, cleanup=False):
    full_path = Path(repo_path) / file_path
    db_url = os.getenv("DATABASE_URL", "/data/pqc.db").replace("sqlite:///", "")
    
    # Ensuring DB is ready (normally done on startup, but safe here)
    init_db(db_url)

    # --- STEP 1: SCA (Dependency Scan) ---
    if file_path.endswith(("requirements.txt", "package.json", "pom.xml", "go.mod", "Cargo.toml", "pyproject.toml")):
        print(f"[{parent_job_id}] 📦 Manifest detected: {file_path}. Running SCA...")
        sca = DependencyScanner()
        vulns = sca.scan(full_path)
        
        if vulns:
             # Save SCA results
             import sqlite3
             conn = sqlite3.connect(db_url)
             c = conn.cursor()
             for item in vulns:
                # Use parent_job_id as run_id
                c.execute('''
                INSERT OR REPLACE INTO inventory (id, path, line, name, category, algorithm, key_size, is_pqc_vulnerable, description, run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (item.id, item.path, item.line, item.name, item.category, item.algorithm, item.key_size, item.is_pqc_vulnerable, item.description, parent_job_id))
             conn.commit()
             conn.close()
             print(f"[{parent_job_id}] 📦 SCA Found {len(vulns)} issues.")
             return True # Skip Regex/AI for manifests to save time, or continue? Let's skip.

    # 0. Deduplication (Smart Cache)
    try:
        with open(full_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Check cache
        cached_result = redis_client.get(f"pqc_cache:{file_hash}")
        if cached_result:
            print(f"[{parent_job_id}] ⚡️ Cache Hit for {file_path}. Skipping analysis.")
            return True
    except Exception as e:
        print(f"[{parent_job_id}] ⚠️ Deduplication failed (hashing error): {e}")

    # 1. Advanced Scanning (Regex/Patterns)
    scanner = PatternScanner(repo_path)
    suspects = scanner.scan_file(full_path)
    
    if not suspects:
        # Mark as safe in cache (TTL 24h)
        redis_client.setex(f"pqc_cache:{file_hash}", 86400, "safe")
        return True
        
    print(f"[{parent_job_id}] ⚠️ Found {len(suspects)} patterns in {file_path}. Saving suspects...")
    
    # Save findings to DB
    save_suspects(db_url, parent_job_id, suspects)
    
    # 2. Deep Check (AI)
    # Tiered Analysis: Flash -> Pro
    try:
        from agents.file_analyst import FileAnalystAgent
        # Using correct DB Path mapped in Docker
        agent = FileAnalystAgent("/data/pqc.db")
        agent.analyze_file_tiered(str(full_path), suspects, parent_job_id)
    except Exception as e:
        print(f"[{parent_job_id}] ❌ AI Analysis Failed: {e}")
    
    # Cache result as "analyzed"
    redis_client.setex(f"pqc_cache:{file_hash}", 86400, "risk_found")
    
    # Cleanup if this was a remote clone
    if cleanup and os.path.exists(repo_path):
        # Note: In a production fan-out, we'd only cleanup after ALL files are done.
        # But for this MVP, we want to avoid disk bloat.
        # If we delete here, other file analyses for the same repo will fail.
        # CORRECT LOGIC: Cleanup should happen in a separate MONITOR task.
        pass

    return True

from scanner.network import NetworkScanner

def process_network_scan(job_id, host):
    print(f"[{job_id}] 🌐 Starting Network Scan on {host}")
    db_url = os.getenv("DATABASE_URL", "/data/pqc.db").replace("sqlite:///", "")
    init_db(db_url)
    
    scanner = NetworkScanner(host)
    items = scanner.scan()
    
    # Save to Inventory
    conn = redis_client  # Hack: reusing redis connection variable name for simplicity? No wait.
    # Need to use save_suspects? No, NetworkScanner returns InventoryItem objects directly.
    # Let's save them manually to DB for now or standardize.
    
    import sqlite3
    conn = sqlite3.connect(db_url)
    c = conn.cursor()
    
    for item in items:
        c.execute('''
        INSERT OR REPLACE INTO inventory (id, path, line, name, category, algorithm, key_size, is_pqc_vulnerable, description, run_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (item.id, item.path, item.line, item.name, item.category, item.algorithm, item.key_size, item.is_pqc_vulnerable, item.description, job_id))
    
    conn.commit()
    conn.close()
    
    print(f"[{job_id}] ✅ Network Scan Complete. Found {len(items)} ciphers.")
    return True

def process_task(task_data):
    task_type = task_data.get("type", "UNKNOWN")
    
    if task_type == "SCAN_REPO":
        return process_discovery(task_data.get("job_id"), task_data.get("repo_path"))

    elif task_type == "SCAN_HOST":
        return process_network_scan(task_data.get("job_id"), task_data.get("host"))
        
    elif task_type == "ANALYZE_FILE":
        return process_analysis(
            task_data.get("parent_job_id"), 
            task_data.get("repo_path"),
            task_data.get("file_path"),
            task_data.get("cleanup", False)
        )
        
    elif "job_id" in task_data: 
        # Legacy/Fallback compatibility
        return process_discovery(task_data.get("job_id"), task_data.get("repo_path"))
        
    return False

def main():
    while True:
        # Blocking pop, waits until an item is available
        # tuple returned: (queue_name, data)
        item = redis_client.brpop("pqc_tasks", timeout=0)
        
        if item:
            queue_name, data = item
            try:
                task = json.loads(data)
                process_task(task)
            except json.JSONDecodeError:
                print(f"Error decoding task: {data}")
            except Exception as e:
                print(f"Error processing task: {e}")

if __name__ == "__main__":
    main()
