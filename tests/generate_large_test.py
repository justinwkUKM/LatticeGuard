import os
from pathlib import Path

# Create a 10MB file with a PQC vulnerability at the end
base_dir = Path(__file__).parent
file_path = base_dir / "samples" / "large_vulnerable_file.sql"

# Ensure directory exists
file_path.parent.mkdir(parents=True, exist_ok=True)
target_size = 10 * 1024 * 1024 # 10MB

with open(file_path, "w") as f:
    f.write("-- Large SQL Dump\n")
    # Write padding
    f.write("A" * (target_size - 100))
    # Add the vulnerability at the end
    f.write("\n\n-- Vulnerable RSA Key\n")
    f.write("-----BEGIN RSA PRIVATE KEY-----\n")
    f.write("MIIEpAIBAAKCAQEA75...\n")
    f.write("-----END RSA PRIVATE KEY-----\n")

print(f"Created {file_path} ({file_path.stat().st_size} bytes)")
