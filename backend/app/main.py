import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api import scans, results, settings as api_settings, auth, users, audit
from app.core.database import init_db

os.environ["OTEL_SDK_DISABLED"] = "true"
os.environ["SAM_CLI_TELEMETRY"] = "0"

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Riskwise Security Platform", lifespan=lifespan)

# Restrict CORS specifically. 
# Since we route through Nginx in production, we only need CORS for local Vite dev servers.
# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://localhost", "https://127.0.0.1"], 
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], 
    allow_headers=["X-Requested-With", "Content-Type", "Authorization"], # Added X-Requested-With
)

@app.middleware("http")
async def enforce_csrf_header(request: Request, call_next):
    # Only enforce on state-changing requests
    if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
        # Exclude login/register since they establish the session
        if not request.url.path.startswith("/api/auth/login") and not request.url.path.startswith("/api/auth/register"):
            # Check for our custom frontend header
            if request.headers.get("X-Requested-With") != "XMLHttpRequest":
                return JSONResponse(
                    status_code=403, 
                    content={"detail": "CSRF Validation Failed: Missing X-Requested-With header."}
                )
    return await call_next(request)

app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(results.router, prefix="/api/results", tags=["results"])
app.include_router(api_settings.router, prefix="/api/settings", tags=["settings"])
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])

@app.get("/")
def health_check():
    return {"status": "online"}