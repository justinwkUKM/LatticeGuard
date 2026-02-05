from fastapi import FastAPI, HTTPException
import redis
import os
import json
from pydantic import BaseModel

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
    """
    Queue a new scan job.
    """
    job_id = f"job-{os.urandom(4).hex()}"
    task = {
        "type": "SCAN_REPO",
        "job_id": job_id,
        "repo_path": request.repo_path,
        "scan_type": request.scan_type,
        "status": "queued"
    }
    
    # Push to Redis Queue
    try:
        redis_client.lpush("pqc_tasks", json.dumps(task))
        return {"job_id": job_id, "status": "queued"}
    except redis.ConnectionError:
        raise HTTPException(status_code=500, detail="Could not connect to Redis Task Queue")

@app.get("/health")
def health_check():
    try:
        redis_client.ping()
        return {"redis": "connected"}
    except redis.ConnectionError:
        return {"redis": "disconnected"}
