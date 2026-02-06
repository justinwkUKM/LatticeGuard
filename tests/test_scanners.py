import pytest
import os
from scanner.dependencies import DependencyScanner
from scanner.history import HistoryScanner
from pathlib import Path
from unittest.mock import MagicMock, patch

def test_dependency_scanner_finding():
    # Setup dummy requirements.txt
    content = "pycrypto==2.6.1\nrequests==2.31.0"
    path = Path("requirements.txt")
    with open(path, "w") as f:
        f.write(content)
        
    scanner = DependencyScanner()
    results = scanner.scan(path)
    
    # Cleanup
    os.remove(path)
    
    assert len(results) >= 1
    assert results[0].name == "Vulnerable Dependency (pycrypto)"
    assert results[0].is_pqc_vulnerable == True

def test_dependency_scanner_safe():
    # Setup safe requirements.txt
    content = "numpy==1.24.0"
    path = Path("requirements.txt")
    with open(path, "w") as f:
        f.write(content)
        
    scanner = DependencyScanner()
    results = scanner.scan(path)
    
    # Cleanup
    os.remove(path)
    
    assert len(results) == 0

@patch("subprocess.Popen")
def test_history_scanner(mock_popen):
    # Mock git log output
    mock_process = MagicMock()
    mock_process.stdout = iter([
        "commit abc1234",
        "Author: Dev <dev@test.com>",
        "+ api_key = 'AKIA1234567890ABCDEF'",
        "commit def5678"
    ])
    mock_popen.return_value = mock_process
    
    scanner = HistoryScanner(".")
    results = scanner.scan()
    
    assert len(results) >= 1
    assert "AKIA" in results[0].path or "AKIA" in results[0].description or "AWS_Key" in results[0].name or "Generic_Secret" in results[0].name
