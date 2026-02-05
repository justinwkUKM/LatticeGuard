import requests
import os
import argparse

def scan_org(org_name, api_base="http://localhost:8000"):
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("Error: GITHUB_TOKEN environment variable not set.")
        return

    print(f"📡 Fetching repository list for organization: {org_name}...")
    
    # Simple GitHub API call to list repos
    headers = {"Authorization": f"token {github_token}"}
    url = f"https://api.github.com/orgs/{org_name}/repos?per_page=100"
    
    repos = []
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        repos = [r["html_url"] for r in response.json()]
    else:
        print(f"Failed to fetch repos: {response.text}")
        return

    print(f"🚀 Triggering LatticeGuard Batch Scan for {len(repos)} repositories...")
    
    # Call LatticeGuard Batch API
    batch_url = f"{api_base}/batch/scan"
    res = requests.post(batch_url, json=repos)
    
    if res.status_code == 200:
        print(f"✅ Batch Scan Started! Tracking ID: {res.json()['batch_id']}")
    else:
        print(f"❌ Failed to start batch scan: {res.text}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan an entire GitHub Org")
    parser.add_argument("org", help="Organization name")
    parser.add_argument("--api", default="http://localhost:8000", help="LatticeGuard API Base")
    args = parser.parse_args()
    
    scan_org(args.org, args.api)
