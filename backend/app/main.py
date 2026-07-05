import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api import scans, results, settings as api_settings, auth, users, audit
from app.core.database import init_db, SessionLocal
from app.models.database import Scan, AuditLog

os.environ["OTEL_SDK_DISABLED"] = "true"
ENV = os.getenv("APP_ENV", "development")

if ENV == "production":
    origins = ["https://yourdomain.com"] # Replace with your strict domain
else:
    origins = [
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://localhost",
        "https://127.0.0.1",
        "https://localhost:5173",
        "https://127.0.0.1:5173"
    ]

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize Tables
    init_db()

    # 2. SYSTEM INTEGRITY FIX: Startup Recovery for Interrupted Scans
    # Marks any leftover active statuses as failed to prevent queue deadlock
    db = SessionLocal()
    try:
        interrupted_scans = db.query(Scan).filter(Scan.status.in_(["running", "analyzing"])).all()
        for s in interrupted_scans:
            s.status = "failed"
            s.error_message = "Scan interrupted due to unexpected server restart or power loss."
            db.add(AuditLog(
                user_id=s.owner_id,
                action="SCAN_INTERRUPTED",
                target=s.id,
                details="Automated system recovery completed on startup."
            ))
        db.commit()
        if interrupted_scans:
            print(f"[RECOVERY] Cleaned up {len(interrupted_scans)} stale scans on boot.")
    except Exception as e:
        print(f"[RECOVERY ERROR] Failed to run startup scan recovery: {e}")
    finally:
        db.close()

    yield


app = FastAPI(title="Riskwise Security Platform", lifespan=lifespan)

# Restrict CORS specifically. 
# Since we route through Nginx in production, we only need CORS for local Vite dev servers.
# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, 
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
    return {"status": "online", "platform": "AI-Vulnerability-Multi-Scanner"}
