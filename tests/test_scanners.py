import pytest
import os
from scanner.dependencies import DependencyScanner
from scanner.history import HistoryScanner
from pathlib import Path
from unittest.mock import MagicMock, patch

def test_dependency_scanner_finding(tmp_path):
    # Setup dummy requirements.txt in temp directory
    content = "pycrypto==2.6.1\nrequests==2.31.0"
    path = tmp_path / "requirements.txt"
    path.write_text(content)
        
    scanner = DependencyScanner(str(tmp_path))
    results = scanner.scan()
    
    assert len(results) >= 1
    assert "pycrypto" in results[0].pattern_matched
    assert results[0].confidence == "high"

def test_dependency_scanner_safe(tmp_path):
    # Setup safe requirements.txt in temp directory
    content = "numpy==1.24.0"
    path = tmp_path / "requirements.txt"
    path.write_text(content)
        
    scanner = DependencyScanner(str(tmp_path))
    results = scanner.scan()
    
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
