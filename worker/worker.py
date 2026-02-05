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
    target_path = repo_path
    is_temp = False
    
    # Check if Remote URL
    if repo_path.startswith(("http://", "https://", "git@")):
        print(f"[{job_id}] 🌍 Detected Remote Repo: {repo_path}")
        is_temp = True
        target_path = f"/data/temp/{job_id}"
        
        # Clone strategy: Partial clone for speed
        try:
            subprocess.run(["git", "clone", "--depth", "1", repo_path, target_path], check=True)
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

def process_analysis(parent_job_id, repo_path, file_path, cleanup=False):
    full_path = Path(repo_path) / file_path
    db_url = os.getenv("DATABASE_URL", "/data/pqc.db").replace("sqlite:///", "")
    
    # Ensuring DB is ready (normally done on startup, but safe here)
    init_db(db_url)

    # 1. Advanced Scanning (Regex/Patterns)
    scanner = PatternScanner(repo_path)
    suspects = scanner.scan_file(full_path)
    
    if not suspects:
        return True
        
    print(f"[{parent_job_id}] ⚠️ Found {len(suspects)} patterns in {file_path}. Saving suspects...")
    
    # Save findings to DB
    save_suspects(db_url, parent_job_id, suspects)
    
    # 2. Deep Check (AI)
    gemini_model = os.getenv("GEMINI_MODEL", "gemini-3-pro-preview")
    print(f"[{parent_job_id}] 🧠 Escalating to {gemini_model} for analysis...")
    # ai_result =  gemini_analyst.analyze(full_path, suspects, model=gemini_model)
    
    # Cleanup if this was a remote clone
    if cleanup and os.path.exists(repo_path):
        # Note: In a production fan-out, we'd only cleanup after ALL files are done.
        # But for this MVP, we want to avoid disk bloat.
        # If we delete here, other file analyses for the same repo will fail.
        # CORRECT LOGIC: Cleanup should happen in a separate MONITOR task.
        pass

    return True

def process_task(task_data):
    task_type = task_data.get("type", "UNKNOWN")
    
    if task_type == "SCAN_REPO":
        return process_discovery(task_data.get("job_id"), task_data.get("repo_path"))
        
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
