# backend/app/main.py
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

# Use explicit absolute imports
from app.api import scans, results, settings as api_settings
from app.core.database import init_db

os.environ["OTEL_SDK_DISABLED"] = "true" # Force disable before any imports
os.environ["SAM_CLI_TELEMETRY"] = "0"    # Just in case

@asynccontextmanager
async def lifespan(app: FastAPI):
    # This runs when the app starts
    init_db()
    yield
    # This runs when the app stops (cleanup if needed)

app = FastAPI(
    title="AI Vulnerability Triage Platform",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers with explicit prefixes
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(results.router, prefix="/api/results", tags=["results"])
app.include_router(api_settings.router, prefix="/api/settings", tags=["settings"])

@app.get("/")
def health_check():
    return {"status": "online", "platform": "AI-Vulnerability-Triage"}