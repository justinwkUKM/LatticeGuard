import os

# Create a 10MB file with a PQC vulnerability at the end
file_path = "/Users/waqas/Documents/PQCAssessment/tests/samples/large_vulnerable_file.sql"
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

print(f"Created {file_path} ({os.path.getsize(file_path)} bytes)")
