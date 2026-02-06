import typer
import os
from dotenv import load_dotenv

load_dotenv()
import json
import time
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

from planner.agent import PlannerAgent
from planner.fingerprint import RepoFingerprinter
from scanner.db import init_db, save_suspects
from scanner.patterns import PatternScanner
from scanner.dependencies import DependencyScanner
from scanner.files import ArtifactScanner
from scanner.ast_scanner import ASTScanner
from scanner.secret_scanner import SecretScanner
from agents.file_analyst import FileAnalystAgent
from agents.graph import GraphAgent
from risk.assessor import RiskAssessor
from schemas.models import ScanBudget

app = typer.Typer()
console = Console()

@app.callback()
def callback():
    """
    PQC Assessment CLI
    """

@app.command()
def scan(
    repo_path: str = typer.Argument(..., help="Path to the repository to scan"),
    run_id: str = typer.Option(None, help="Unique ID for this run. If not provided, one is generated."),
    max_files: int = 1000,
    max_depth: int = 5,
    skip_fast: bool = False,
    skip_deep: bool = False,
):
    """
    Runs a Post-Quantum Cryptography (PQC) assessment on the target repository.
    """
    
    # 0. Setup
    if not run_id:
        run_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    output_dir = Path("output") / run_id
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # DB Setup: Use Central DB from Env or Default
    db_url = os.getenv("DATABASE_URL", "sqlite:///data/pqc.db")
    
    # Handle different DB Schemas
    if db_url.startswith("sqlite"):
        # Extract path from sqlite:///path/to/db or sqlite://path/to/db
        # Remove prefix to get file path
        if db_url.startswith("sqlite:///"):
            db_path = db_url.replace("sqlite:///", "")
        elif db_url.startswith("sqlite://"):
             db_path = db_url.replace("sqlite://", "")
        else:
             db_path = db_url.replace("sqlite:", "")

        # Ensure DB directory exists if it's a file path
        db_file_path = Path(db_path)
        if not db_file_path.parent.exists():
            db_file_path.parent.mkdir(parents=True, exist_ok=True)
            
        init_db(str(db_file_path))
        console.print(f"  Using Local Database: {db_file_path}")
    else:
        # Remote DB (Postgres, MySQL, etc.)
        # init_db would need to handle connection string. 
        # For now, we assume init_db accepts the connection string directly for non-sqlite
        # or we might need to update scanner/db.py to handle sqlalchemy URLs if we move to that.
        # But for this CLI scope, we just pass it through.
        init_db(db_url) 
        console.print(f"  Using Remote Database: {db_url}")
    
    console.print(Panel(f"Starting PQC Scan\nRun ID: {run_id}\nTarget: {repo_path}\nOutput: {output_dir}", title="PQC Assessment"))

    # 1. Phase 1: Strategize
    console.print("[bold blue]Phase 1: Strategize[/bold blue]")
    planner = PlannerAgent()
    budget = ScanBudget(max_files=max_files, max_depth=max_depth)
    plan = planner.generate_plan(repo_path, run_id, budget)
    
    with open(output_dir / "scan_plan.json", "w") as f:
        f.write(plan.model_dump_json(indent=2))
    console.print(f"  Plan generated: {plan.strategy} strategy")

    # 2. Phase 2: Fast Discovery
    if not skip_fast:
        console.print("[bold blue]Phase 2: Fast Deterministic Discovery[/bold blue]")
        suspects = []
        
        # Patterns
        console.print("  Running Pattern Scanner...")
        ps = PatternScanner(repo_path)
        # Actually we need to loop through files for PatternScanner.scan_file if we want to be granular,
        # but main.py currently calls ps.scan(). Let's check ps.scan() implementation again.
        # wait, ps.scan() in main.py 103 seems intended for a full repo walk.
        
        # For Phase 1, I will update the orchestrator loop to walk once and call all scanners.
        
        ast_s = ASTScanner()
        sec_s = SecretScanner()
        
        for dirpath, dirnames, filenames in os.walk(repo_path):
            # Filter in-place
            dirnames[:] = [d for d in dirnames if not d.startswith('.') and d not in {'.venv', 'node_modules', '.git'}]
            
            for f in filenames:
                file_path = Path(dirpath) / f
                
                # Pattern Scan
                suspects.extend(ps.scan_file(file_path))
                
                # AST Scan (Python only)
                if f.endswith(".py"):
                    suspects.extend(ast_s.scan_file(file_path))
                    
                # Secret Scan
                suspects.extend(sec_s.scan_file(file_path))

        # Dependencies
        console.print("  Running Dependency Scanner...")
        ds = DependencyScanner(repo_path)
        suspects.extend(ds.scan())
        
        # Artifacts
        console.print("  Running Artifact Scanner...")
        fs = ArtifactScanner(repo_path)
        suspects.extend(fs.scan())
        
        
        save_suspects(db_path, run_id, suspects)
        console.print(f"  Found {len(suspects)} suspects.")

    # 3. Phase 3: Deep Discovery
    if not skip_deep:
        console.print("[bold blue]Phase 3: Deep Iterative Discovery[/bold blue]")
        console.print("  Running File Analyst Agent (Gemini)...")
        analyst = FileAnalystAgent(db_path)
        analyst.analyze_suspects(run_id)
        
        console.print("  Running Graph Agent...")
        graph = GraphAgent(db_path)
        graph.build_graph(run_id)

    # 4. Phase 4: Risk Assessment
    console.print("[bold blue]Phase 4: Risk Assessment[/bold blue]")
    assessor = RiskAssessor(db_path)
    assessor.assess_risk(run_id, output_dir)
    
    console.print(f"[bold green]Scan Complete![/bold green]")
    console.print(f"Reports available in: {output_dir}")

if __name__ == "__main__":
    app()
