import redis
import os
import json
import time
import sqlite3

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

def update_job_status(job_id, status, progress=None):
    """Update job status in Redis for real-time tracking."""
    data = {"status": status, "last_update": time.time()}
    if progress is not None:
        data["progress"] = progress
    redis_client.hset(f"job_status:{job_id}", mapping=data)
    # Set expiration to 24h to keep Redis clean
    redis_client.expire(f"job_status:{job_id}", 86400)

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
            update_job_status(job_id, "cloning")
            subprocess.run(["git", "clone", "--depth", "1", "--", repo_path, target_path], check=True, timeout=300)
            print(f"[{job_id}] ✅ Cloned to {target_path}")
        except subprocess.CalledProcessError as e:
            update_job_status(job_id, "failed (clone_error)")
            print(f"[{job_id}] ❌ Clone Failed: {e}")
            return False

    else:
        # Local Scan Validation
        target_path_obj = Path(repo_path)
        if not target_path_obj.exists():
            update_job_status(job_id, "failed (invalid_path)")
            print(f"[{job_id}] ❌ Local Path Not Found: {repo_path}")
            return False
        
        # Check if directory
        if not target_path_obj.is_dir():
            update_job_status(job_id, "failed (not_a_directory)")
            print(f"[{job_id}] ❌ Path is not a directory: {repo_path}")
            return False

        print(f"[{job_id}] 💻 Scanning Local Path: {repo_path}")
        update_job_status(job_id, "discovering", progress=5)
        log_to_db(job_id, f"Scanning Local Path: {repo_path}", component="Discovery")

    print(f"[{job_id}] 🔍 Starting Discovery on {target_path}")
    scanner = ArtifactScanner(target_path)
    
    count = 0
    pipe = redis_client.pipeline()
    
    for suspect in scanner.scan():
        # Push sub-task for individual file analysis
        sub_task = {
            "type": "ANALYZE_FILE",
            "parent_job_id": job_id,
            "repo_path": target_path,
            "file_path": suspect.path,
            "suspect_type": suspect.type,
            "cleanup": is_temp # Propagate cleanup flag if needed
        }
        pipe.lpush("pqc_tasks", json.dumps(sub_task))
        count += 1
        
        # Batch push every 100 items
        if count % 100 == 0:
            pipe.execute()
            
    pipe.execute() # Push remaining
    redis_client.hset(f"job_status:{job_id}", mapping={
        "total_files": count,
        "completed_files": 0
    })
    log_to_db(job_id, f"Discovery complete. Identified {count} files for analysis.", component="Discovery")
    update_job_status(job_id, "analyzing", progress=10)
    print(f"[{job_id}] 🚀 Discovered {count} files. Queued for analysis.")
    return True

from scanner.patterns import PatternScanner
import shutil
import hashlib

from scanner.dependencies import DependencyScanner
from scanner.cloudformation import CloudFormationScanner
from scanner.treesitter_scanner import TreeSitterScanner
from scanner.kubernetes import KubernetesScanner

def log_to_db(run_id, message, level="INFO", component="Worker"):
    db_url = os.getenv("DATABASE_URL", "/data/pqc.db").replace("sqlite:///", "")
    try:
        conn = sqlite3.connect(db_url)
        c = conn.cursor()
        c.execute("INSERT INTO scan_logs (run_id, level, component, message) VALUES (?, ?, ?, ?)",
                  (run_id, level, component, message))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Logging Failure: {e}")

def log_to_db(run_id, message, level="INFO", component="Worker"):
    db_path = os.getenv("DATABASE_URL", "/data/pqc.db").replace("sqlite:///", "")
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("INSERT INTO scan_logs (run_id, level, component, message) VALUES (?, ?, ?, ?)",
                  (run_id, level, component, message))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Logging Failure: {e}")

def _increment_progress(parent_job_id):
    redis_client.hincrby(f"job_status:{parent_job_id}", "completed_files", 1)
    # Calculate and update % progress occasionally (every 1, 10, or 100 files depending on scale)
    comp = int(redis_client.hget(f"job_status:{parent_job_id}", "completed_files") or 0)
    total = int(redis_client.hget(f"job_status:{parent_job_id}", "total_files") or 1)
    
    if comp % 1 == 0 or comp == total: # Updated to 1 for more reactive small scans
        prog = 10 + int((comp / total) * 90)
        update_job_status(parent_job_id, "analyzing", progress=prog)
        if comp == total:
            update_job_status(parent_job_id, "completed", progress=100)

def process_analysis(parent_job_id, repo_path, file_path, cleanup=False, task_data=None):
    if task_data is None: task_data = {}
    full_path = Path(repo_path) / file_path
    db_url = os.getenv("DATABASE_URL", "/data/pqc.db").replace("sqlite:///", "")
    
    # Ensuring DB is ready (normally done on startup, but safe here)
    init_db(db_url)

    # --- STEP 1: SCA (Dependency Scan) ---
    if file_path.endswith(("requirements.txt", "package.json", "pom.xml", "go.mod", "Cargo.toml", "pyproject.toml")):
        log_to_db(parent_job_id, f"Manifest detected: {file_path}. Initiating Software Composition Analysis (SCA)...", component="SCA")
        print(f"[{parent_job_id}] 📦 Manifest detected: {file_path}. Running SCA...")
        sca = DependencyScanner(repo_path)
        vulns = sca.scan_file(full_path)
        
        if vulns:
             log_to_db(parent_job_id, f"SCA found {len(vulns)} quantum-vulnerable dependencies in {file_path}.", level="WARNING", component="SCA")
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
        
        _increment_progress(parent_job_id)
        return True 

    # --- STEP 1b: Java/C++ AST Analysis (Tree-sitter) ---
    if file_path.endswith((".java", ".cpp", ".cc", ".cxx", ".hpp", ".h")):
        log_to_db(parent_job_id, f"Java/C++ source detected: {file_path}. Running AST-based crypto analysis...", component="TreeSitter")
        print(f"[{parent_job_id}] 🌳 Java/C++ detected: {file_path}. Running tree-sitter AST scan...")
        ts_scanner = TreeSitterScanner()
        ts_suspects = ts_scanner.scan_file(full_path)
        
        if ts_suspects:
            log_to_db(parent_job_id, f"Tree-sitter found {len(ts_suspects)} crypto patterns in {file_path}.", level="WARNING", component="TreeSitter")
            save_suspects(db_url, parent_job_id, ts_suspects)
            print(f"[{parent_job_id}] 🌳 Tree-sitter found {len(ts_suspects)} crypto issues.")
        
        _increment_progress(parent_job_id)
        return True

    # --- STEP 1c: Kubernetes Manifest Analysis ---
    if file_path.endswith((".yaml", ".yml")):
        # Check if it looks like a K8s manifest before running full scan
        try:
            content = Path(full_path).read_text()
            if "apiVersion:" in content and "kind:" in content:
                log_to_db(parent_job_id, f"Kubernetes manifest detected: {file_path}. Analyzing TLS/crypto configs...", component="K8s")
                print(f"[{parent_job_id}] ☸️ K8s manifest: {file_path}. Running Kubernetes scanner...")
                k8s_scanner = KubernetesScanner(str(Path(full_path).parent))
                k8s_scanner._scan_file(full_path)
                
                if k8s_scanner.suspects:
                    log_to_db(parent_job_id, f"Kubernetes scanner found {len(k8s_scanner.suspects)} crypto-related configs in {file_path}.", level="WARNING", component="K8s")
                    save_suspects(db_url, parent_job_id, k8s_scanner.suspects)
                    print(f"[{parent_job_id}] ☸️ K8s scanner found {len(k8s_scanner.suspects)} findings.")
        except Exception as e:
            print(f"[{parent_job_id}] ⚠️ K8s scan error: {e}")

    # 0. Deduplication (Smart Cache)
    try:
        with open(full_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Check cache
        cached_result = redis_client.get(f"pqc_cache:{file_hash}")
        if cached_result:
            print(f"[{parent_job_id}] ⚡️ Cache Hit for {file_path}. Skipping analysis.")
            _increment_progress(parent_job_id)
            return True
    except Exception as e:
        print(f"[{parent_job_id}] ⚠️ Deduplication failed (hashing error): {e}")

    # 1. Advanced Scanning (Regex/Patterns)
    scanner = PatternScanner(repo_path)
    suspects = scanner.scan_file(full_path)
    
    # If no patterns found AND it wasn't a high-signal artifact from discovery, skip.
    if not suspects and task_data.get("suspect_type") != "artifact":
        # Mark as safe in cache (TTL 24h)
        redis_client.setex(f"pqc_cache:{file_hash}", 86400, "safe")
        _increment_progress(parent_job_id)
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
    
    _increment_progress(parent_job_id)
    return True

from scanner.network import NetworkScanner

def process_network_scan(job_id, host, port=443):
    update_job_status(job_id, "scanning")
    print(f"[{job_id}] 🌐 Starting Network Scan on {host}:{port}")
    scanner = NetworkScanner(host, port)
    items = scanner.scan()
    
    # Save to Inventory
    conn = redis_client  # Hack: reusing redis connection variable name for simplicity? No wait.
    # Need to use save_suspects? No, NetworkScanner returns InventoryItem objects directly.
    # Let's save them manually to DB for now or standardize.
    
    import sqlite3
    db_url = os.getenv("DATABASE_URL", "/data/pqc.db").replace("sqlite:///", "")
    conn = sqlite3.connect(db_url)
    c = conn.cursor()
    
    for item in items:
        c.execute('''
        INSERT OR REPLACE INTO inventory (id, path, line, name, category, algorithm, key_size, is_pqc_vulnerable, description, run_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (item.id, item.path, item.line, item.name, item.category, item.algorithm, item.key_size, item.is_pqc_vulnerable, item.description, job_id))
    
    conn.commit()
    conn.close()
    
    update_job_status(job_id, "completed")
    print(f"[{job_id}] ✅ Network Scan Complete. Found {len(items)} ciphers.")
    return True

def process_task(task_data):
    task_type = task_data.get("type", "UNKNOWN")
    
    if task_type == "SCAN_REPO":
        return process_discovery(task_data.get("job_id"), task_data.get("repo_path"))

    elif task_type == "SCAN_HOST":
        return process_network_scan(
            task_data.get("job_id"), 
            task_data.get("host"),
            task_data.get("port", 443)
        )
        
    elif task_type == "ANALYZE_FILE":
        return process_analysis(
            task_data.get("parent_job_id"), 
            task_data.get("repo_path"),
            task_data.get("file_path"),
            task_data.get("cleanup", False),
            task_data # Pass full task_data to access suspect_type
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
