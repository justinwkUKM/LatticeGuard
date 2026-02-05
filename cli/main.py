import typer
import os
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
    db_path = str(output_dir / "pqc.db")
    init_db(db_path)
    
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
        suspects.extend(ps.scan())
        
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
