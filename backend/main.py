"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import redis
import os
import json
import sqlite3
import time
from pydantic import BaseModel, field_validator
from typing import List, Optional

app = FastAPI(title="LatticeGuard API")

# Add CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Redis Connection
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)

DATABASE_PATH = os.getenv("DATABASE_URL", "/data/pqc.db").replace("sqlite:///", "")

class ScanRequest(BaseModel):
    repo_path: str
    scan_type: str = "full"

    @field_validator('repo_path')
    def validate_repo_path(cls, v):
        if v.startswith(("http://", "https://", "git@")):
            return v
        if os.getenv("ALLOW_LOCAL_SCAN", "false").lower() != "true":
            raise ValueError("Local file scanning is disabled.")
        return v

class NodeScanRequest(BaseModel):
    host: str
    port: int = 443

class SettingsUpdate(BaseModel):
    gemini_api_key: Optional[str] = None
    gemini_model: Optional[str] = None

class FindingUpdate(BaseModel):
    status: str
    resolution_metadata: Optional[str] = None

@app.get("/")
def read_root():
    return {"status": "online", "message": "PQC Assessment API Ready"}

@app.post("/scan")
def trigger_scan(request: ScanRequest):
    return _queue_job(request.repo_path, request.scan_type)

@app.post("/scan/node")
def trigger_node_scan(request: NodeScanRequest):
    job_id = f"node-{os.urandom(4).hex()}"
    task = {
        "type": "SCAN_HOST",
        "job_id": job_id,
        "host": request.host,
        "port": request.port,
        "status": "queued"
    }
    try:
        # Initialize status in Redis for immediate UI visibility
        status_key = f"job_status:{job_id}"
        redis_client.hset(status_key, mapping={
            "status": "queued",
            "progress": "0",
            "last_update": str(time.time()),
            "host": request.host
        })
        redis_client.expire(status_key, 86400)
        
        redis_client.lpush("pqc_tasks", json.dumps(task))
        return {"job_id": job_id, "status": "queued"}
    except redis.ConnectionError:
        raise HTTPException(status_code=500, detail="LatticeGuard MQ Offline")

@app.get("/scans")
def get_recent_scans():
    """Returns a list of unique run IDs processed."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("SELECT DISTINCT run_id FROM inventory ORDER BY rowid DESC LIMIT 50")
        runs = [row[0] for row in c.fetchall()]
        conn.close()
        return {"scans": runs}
    except Exception as e:
        return {"scans": [], "error": str(e)}

@app.get("/scans/{run_id}")
def get_scan_details(run_id: str):
    """Returns summarized results for a specific scan."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM inventory WHERE run_id = ?", (run_id,))
        total_findings = c.fetchone()[0]
        
        c.execute("SELECT id, path, name, algorithm, is_pqc_vulnerable, status, description FROM inventory WHERE run_id = ?", (run_id,))
        findings = [
            {"id": row[0], "path": row[1], "name": row[2], "algorithm": row[3], "is_pqc": bool(row[4]), "status": row[5], "description": row[6]}
            for row in c.fetchall()
        ]
        
        conn.close()
        return {
            "run_id": run_id,
            "total_findings": total_findings,
            "findings": findings
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scans/{run_id}/status")
def get_job_status(run_id: str):
    """Fetch real-time job status from Redis."""
    status_data = redis_client.hgetall(f"job_status:{run_id}")
    if not status_data:
        # Check if it exists in DB as completed
        return {"status": "unknown"}
    
    return {k.decode(): v.decode() for k, v in status_data.items()}

@app.get("/scans/{run_id}/logs")
def get_scan_logs(run_id: str):
    """Fetch structured logs for a specific scan."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("SELECT level, component, message, timestamp FROM scan_logs WHERE run_id = ? ORDER BY id ASC", (run_id,))
        logs = [
            {"level": row[0], "component": row[1], "message": row[2], "timestamp": row[3]}
            for row in c.fetchall()
        ]
        conn.close()
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/jobs")
def list_active_jobs():
    """List all active/recent jobs tracked in Redis."""
    keys = redis_client.keys("job_status:*")
    jobs = []
    for key in keys:
        run_id = key.decode().split(":")[-1]
        status = redis_client.hgetall(key)
        jobs.append({
            "run_id": run_id,
            "status": {k.decode(): v.decode() for k, v in status.items()}
        })
    return jobs

@app.patch("/inventory/{finding_id}")
def update_finding(finding_id: str, update: FindingUpdate):
    """Update finding status (Remediation)."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute(
            "UPDATE inventory SET status = ?, resolution_metadata = ? WHERE id = ?",
            (update.status, update.resolution_metadata, finding_id)
        )
        conn.commit()
        if c.rowcount == 0:
            raise HTTPException(status_code=404, detail="Finding not found")
        conn.close()
        return {"status": "updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/summary")
def get_global_summary():
    """Aggregate risks across all scanned repositories."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(DISTINCT run_id) FROM inventory")
        total_repos = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM inventory WHERE is_pqc_vulnerable = 1")
        critical_risks = c.fetchone()[0]
        
        conn.close()
        return {
            "total_repos_scanned": total_repos or 0,
            "critical_risks": critical_risks or 0,
            "high_risks": 0, # Placeholder
            "top_vulnerable_repos": []
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/metrics/trends")
def get_metrics_trends():
    """Returns mock trend data for the frontend charts."""
    # In a real app, this would query historical scan statistics
    return [
        {"name": "Feb 1", "risks": 40, "resolved": 5, "scans": 2},
        {"name": "Feb 2", "risks": 30, "resolved": 12, "scans": 5},
        {"name": "Feb 3", "risks": 65, "resolved": 18, "scans": 3},
        {"name": "Feb 4", "risks": 45, "resolved": 25, "scans": 8},
        {"name": "Feb 5", "risks": 90, "resolved": 35, "scans": 4},
        {"name": "Feb 6", "risks": 55, "resolved": 42, "scans": 12},
        {"name": "Feb 7", "risks": 35, "resolved": 50, "scans": 6}
    ]

@app.get("/reports/export/{run_id}")
def export_report(run_id: str, format: str = "json"):
    """Returns all findings for a run in the requested format."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM inventory WHERE run_id = ?", (run_id,))
        columns = [description[0] for description in c.description]
        findings = [dict(zip(columns, row)) for row in c.fetchall()]
        conn.close()
        
        if format == "csv":
            import io, csv
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=columns)
            writer.writeheader()
            writer.writerows(findings)
            return output.getvalue()
            
        return findings
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/pdf/{run_id}")
def export_pdf_report(run_id: str):
    """
    Generate PDF compliance report with NIST/CNSA mapping.
    Returns a downloadable PDF file.
    """
    from fastapi.responses import FileResponse
    from reporting.pdf_generator import PDFReportGenerator
    
    try:
        # Generate PDF
        output_dir = os.path.join(os.path.dirname(DATABASE_PATH), "reports")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{run_id}.pdf")
        
        generator = PDFReportGenerator(DATABASE_PATH)
        pdf_path = generator.generate(run_id, output_path)
        
        return FileResponse(
            pdf_path, 
            media_type="application/pdf",
            filename=f"pqc_report_{run_id}.pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/cbom/{run_id}")
def export_cbom(run_id: str):
    """
    Generate Cryptography Bill of Materials (CBOM) in CycloneDX 1.6 format.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        
        # Get findings
        c.execute("SELECT * FROM inventory WHERE run_id = ?", (run_id,))
        columns = [description[0] for description in c.description]
        findings = [dict(zip(columns, row)) for row in c.fetchall()]
        
        # Get repo path from job status
        target = run_id
        try:
            status_data = redis_client.hgetall(f"job_status:{run_id}")
            if status_data:
                target = status_data.get(b'repo_path', b'').decode() or run_id
        except:
            pass
        
        conn.close()
        
        # Import CBOM generator
        from schemas.cbom import generate_cbom_from_findings
        
        cbom = generate_cbom_from_findings(run_id, target, findings)
        return cbom.to_cyclonedx()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/{run_id}/graph")
def get_blast_radius_graph(run_id: str):
    """
    Generate D3.js-compatible graph data for blast radius visualization.
    Shows how cryptographic assets relate to each other and their risk propagation.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        
        # Get all findings for this run
        c.execute("SELECT * FROM inventory WHERE run_id = ?", (run_id,))
        columns = [description[0] for description in c.description]
        findings = [dict(zip(columns, row)) for row in c.fetchall()]
        conn.close()
        
        nodes = []
        edges = []
        seen_algorithms = {}
        
        # Risk color mapping
        risk_colors = {
            "critical": "#ef4444",  # red-500
            "high": "#f97316",      # orange-500
            "medium": "#eab308",    # yellow-500
            "low": "#22c55e",       # green-500
            "info": "#6b7280"       # gray-500
        }
        
        # Group findings by algorithm family
        for f in findings:
            algo = f.get("algorithm", "Unknown")
            path = f.get("path", "")
            name = f.get("name", "Unknown")
            is_vuln = f.get("is_pqc", False)
            
            # Determine risk level
            algo_upper = algo.upper() if algo else ""
            if "RSA-1024" in algo_upper or "DES" in algo_upper:
                risk = "critical"
            elif "RSA" in algo_upper or "ECDSA" in algo_upper or "ECDHE" in algo_upper:
                risk = "high"
            elif is_vuln:
                risk = "medium"
            else:
                risk = "low"
            
            # Create finding node
            node_id = f.get("id", path)
            nodes.append({
                "id": node_id,
                "label": name[:30],
                "group": "finding",
                "risk": risk,
                "color": risk_colors.get(risk, "#6b7280"),
                "algorithm": algo,
                "path": path,
                "size": 20 if risk == "critical" else 15 if risk == "high" else 10
            })
            
            # Track algorithm for grouping
            if algo and algo not in seen_algorithms:
                algo_node_id = f"algo:{algo}"
                seen_algorithms[algo] = algo_node_id
                
                # Determine algorithm node risk
                algo_risk = "high" if is_vuln else "low"
                if any(tag in algo.upper() for tag in ["KYBER", "DILITHIUM", "ML-KEM", "ML-DSA"]):
                    algo_risk = "low"
                elif "RSA" in algo.upper() or "ECC" in algo.upper() or "ECDSA" in algo.upper():
                    algo_risk = "high"
                
                nodes.append({
                    "id": algo_node_id,
                    "label": algo,
                    "group": "algorithm",
                    "risk": algo_risk,
                    "color": risk_colors.get(algo_risk, "#6b7280"),
                    "size": 30
                })
            
            # Create edge from finding to algorithm
            if algo in seen_algorithms:
                edges.append({
                    "source": node_id,
                    "target": seen_algorithms[algo],
                    "type": "uses"
                })
        
        # Add root node for the scan
        repo_path = run_id
        try:
            status_data = redis_client.hgetall(f"job_status:{run_id}")
            if status_data:
                repo_path = status_data.get(b'repo_path', b'').decode() or run_id
        except:
            pass
        
        nodes.insert(0, {
            "id": "root",
            "label": repo_path.split("/")[-1] if "/" in repo_path else repo_path,
            "group": "root",
            "risk": "info",
            "color": "#3b82f6",  # blue-500
            "size": 40
        })
        
        # Connect algorithm nodes to root
        for algo, algo_node_id in seen_algorithms.items():
            edges.append({
                "source": "root",
                "target": algo_node_id,
                "type": "contains"
            })
        
        # Calculate blast radius summary
        critical_count = sum(1 for n in nodes if n.get("risk") == "critical")
        high_count = sum(1 for n in nodes if n.get("risk") == "high")
        
        return {
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "total_assets": len(findings),
                "algorithm_families": len(seen_algorithms),
                "critical_nodes": critical_count,
                "high_risk_nodes": high_count,
                "blast_radius_score": min(10, (critical_count * 3 + high_count * 2) / max(1, len(findings)) * 10)
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/agility")
def get_algorithm_registry():
    """
    Get algorithm registry for cryptographic agility tracking.
    Returns all unique algorithms found across all scans with their locations.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        
        # Get unique algorithms with counts and locations
        c.execute("""
            SELECT algorithm, COUNT(*) as count, 
                   GROUP_CONCAT(DISTINCT path) as locations,
                   MAX(CASE WHEN is_pqc_vulnerable = 1 THEN 1 ELSE 0 END) as is_vulnerable
            FROM inventory 
            WHERE algorithm IS NOT NULL AND algorithm != ''
            GROUP BY algorithm
            ORDER BY count DESC
        """)

        
        algorithms = []
        for row in c.fetchall():
            algo, count, locations, is_vuln = row
            locations_list = locations.split(",")[:5] if locations else []
            
            # Determine quantum safety
            algo_upper = (algo or "").upper()
            is_quantum_safe = any(tag in algo_upper for tag in ["KYBER", "DILITHIUM", "ML-KEM", "ML-DSA", "AES", "SHA-256", "SHA-384", "SHA-512"])
            
            algorithms.append({
                "algorithm": algo,
                "instance_count": count,
                "sample_locations": locations_list,
                "is_pqc_vulnerable": bool(is_vuln),
                "is_quantum_safe": is_quantum_safe,
                "migration_priority": "critical" if count > 10 and is_vuln else "high" if count > 5 and is_vuln else "medium" if is_vuln else "low"
            })
        
        conn.close()
        
        return {
            "algorithms": algorithms,
            "total_unique": len(algorithms),
            "vulnerable_count": sum(1 for a in algorithms if a["is_pqc_vulnerable"]),
            "quantum_safe_count": sum(1 for a in algorithms if a["is_quantum_safe"])
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/settings")
def get_settings():
    return {
        "gemini_model": os.getenv("GEMINI_MODEL", "gemini-3-flash-preview"),
        "allow_local_scan": os.getenv("ALLOW_LOCAL_SCAN", "false").lower() == "true"
    }

@app.post("/settings")
def update_settings(settings: SettingsUpdate):
    # This is ephemeral as we can't easily update .env in a containerized environment
    # without complex persistence logic, but works for the session.
    if settings.gemini_model:
        os.environ["GEMINI_MODEL"] = settings.gemini_model
    return {"status": "updated"}

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
        # Initialize status in Redis for immediate UI visibility
        status_key = f"job_status:{job_id}"
        redis_client.hset(status_key, mapping={
            "status": "queued",
            "progress": "0",
            "last_update": str(time.time()),
            "repo_path": repo_path
        })
        redis_client.expire(status_key, 86400)

        redis_client.lpush("pqc_tasks", json.dumps(task))
        return {"job_id": job_id, "status": "queued"}
    except redis.ConnectionError:
        raise HTTPException(status_code=500, detail="LatticeGuard MQ Offline")

@app.get("/health")
def health_check():
    try:
        redis_client.ping()
        return {"redis": "connected", "database": "accessible" if os.path.exists(DATABASE_PATH) else "not_found"}
    except redis.ConnectionError:
        return {"redis": "disconnected"}
