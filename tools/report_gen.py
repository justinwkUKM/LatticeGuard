from pathlib import Path
from risk.assessor import RiskAssessor
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/report_gen.py <run_id>")
        sys.exit(1)
        
    run_id = sys.argv[1]
    db_path = "data/pqc.db"
    output_dir = Path("output") / run_id
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Regenerating report for {run_id}...")
    assessor = RiskAssessor(db_path)
    assessor.assess_risk(run_id, output_dir)
    print("Done.")

if __name__ == "__main__":
    main()
