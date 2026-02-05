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

def process_analysis(parent_job_id, repo_path, file_path):
    full_path = Path(repo_path) / file_path
    
    # 1. Advanced Scanning (Regex/Patterns)
    scanner = PatternScanner(repo_path)
    suspects = scanner.scan_file(full_path)
    
    if not suspects:
        # Optimization: No crypto patterns found? Don't waste AI tokens.
        # print(f"[{parent_job_id}] 💤 No patterns in {file_path}. Skipping AI.")
        return True
        
    print(f"[{parent_job_id}] ⚠️ Found {len(suspects)} patterns in {file_path}. Escalating to AI...")
    
    # 2. Deep Check (AI)
    gemini_model = os.getenv("GEMINI_MODEL", "gemini-3-pro-preview")
    print(f"[{parent_job_id}] 🧠 Escalating to {gemini_model} for analysis...")
    # ai_result =  gemini_analyst.analyze(full_path, suspects, model=gemini_model)
    
    return True

def process_task(task_data):
    task_type = task_data.get("type", "UNKNOWN")
    
    if task_type == "SCAN_REPO":
        return process_discovery(task_data.get("job_id"), task_data.get("repo_path"))
        
    elif task_type == "ANALYZE_FILE":
        return process_analysis(
            task_data.get("parent_job_id"), 
            task_data.get("repo_path"),
            task_data.get("file_path")
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
