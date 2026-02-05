import pytest
from worker import process_task

def test_process_task_success(capsys):
    task = {
        "job_id": "job-123",
        "repo_path": "./test-repo"
    }
    result = process_task(task)
    assert result is True
    
    captured = capsys.readouterr()
    assert "[job-123] Processing repo: ./test-repo" in captured.out
    assert "[job-123] Scan complete." in captured.out

def test_process_task_invalid():
    # Missing fields
    task = {"job_id": "job-bad"}
    result = process_task(task)
    assert result is False
