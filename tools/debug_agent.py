import sys
from dotenv import load_dotenv
load_dotenv()
from agents.file_analyst import FileAnalystAgent
from schemas.models import Suspect

# Mock Suspect
s = Suspect(
    path="/Users/waqas/Documents/Development/Python/Rumius-ai/ai-engine-serverless/serverless.yml",
    line=1,
    content_snippet="provider: aws",
    type="infra",
    pattern_matched="yml",
    confidence="low"
)

def main():
    agent = FileAnalystAgent("data/pqc.db")
    print(f"Testing Pro Model on: {s.path}")
    
    # Read file content to simulate real context
    try:
        with open(s.path, "r") as f:
            content = f.read()
    except:
        content = "Mock content for suspected serverless.yml"

    context = f"File: {s.path}\nContent:\n{content[:1000]}..." # Truncate for debug
    
    print("Sending to Pro...")
    # Manually invoke private method for debug
    res = agent._ask_pro_deep_dive(context, "debug_run")
    print("\n--- Result ---")
    print(res)

if __name__ == "__main__":
    main()
