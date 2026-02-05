from fastapi import FastAPI, HTTPException
import redis
import os
import json
from pydantic import BaseModel
from typing import List

app = FastAPI(title="LatticeGuard API")

# Redis Connection
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)

class ScanRequest(BaseModel):
    repo_path: str
    scan_type: str = "full"

@app.get("/")
def read_root():
    return {"status": "online", "message": "PQC Assessment API Ready"}

@app.post("/scan")
def trigger_scan(request: ScanRequest):
    return _queue_job(request.repo_path, request.scan_type)

@app.post("/batch/scan")
def trigger_batch_scan(repos: List[str], scan_type: str = "full"):
    """
    Queue multiple repositories at once.
    """
    job_ids = []
    for repo in repos:
        res = _queue_job(repo, scan_type)
        job_ids.append(res["job_id"])
    return {"batch_id": f"batch-{os.urandom(3).hex()}", "jobs": job_ids}

def _queue_job(repo_path: str, scan_type: str):
    job_id = f"job-{os.urandom(4).hex()}"
    task = {
        "type": "SCAN_REPO",
        "job_id": job_id,
        "repo_path": repo_path,
        "scan_type": scan_type,
        "status": "queued"
    }
    try:
        redis_client.lpush("pqc_tasks", json.dumps(task))
        return {"job_id": job_id, "status": "queued"}
    except redis.ConnectionError:
        raise HTTPException(status_code=500, detail="LatticeGuard Message Queue (Redis) is offline.")

@app.get("/reports/summary")
def get_global_summary():
    """
    Aggregate risks across all scanned repositories.
    """
    # In a real impl, this queries the DB.
    # For now, returning schema placeholder.
    return {
        "total_repos_scanned": 120,
        "critical_risks": 45,
        "high_risks": 89,
        "top_vulnerable_repos": [
            {"repo": "auth-service", "critical": 12},
            {"repo": "payment-gateway", "critical": 8}
        ]
    }


@app.get("/health")
def health_check():
    try:
        redis_client.ping()
        return {"redis": "connected"}
    except redis.ConnectionError:
        return {"redis": "disconnected"}
