import uvicorn
import os
import sys

if __name__ == "__main__":
    # Add the current directory to sys.path so 'app' can be found
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    
    # Force disable telemetry
    os.environ["OTEL_SDK_DISABLED"] = "true"
    
    print("--- Starting AI Triage Platform Backend ---")
    print("Database Location:", os.path.join(os.getcwd(), "data/vulnerabilities.db"))
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False  # Keep this False for now to ensure background scans finish
    )