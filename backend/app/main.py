from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth
from app.api import agents, events, scanner, phishing, breach

# Multi-org system imports
import sys
from pathlib import Path

# In Railway, packages is at /app/packages. Locally it's 5 levels up.
if Path("/app/packages").exists():
    # Railway environment
    sys.path.insert(0, "/app")
else:
    # Local environment
    root_path = Path(__file__).parent.parent.parent.parent.parent
    if str(root_path) not in sys.path:
        sys.path.insert(0, str(root_path))

# Create FastAPI app
app = FastAPI(
    title="CyberSec Suite API",
    version="0.1.0",
    description="Cybersecurity monitoring platform"
)

# CORS configuration - Allow ALL origins for now
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://cybersec-suite-7kezygy9e-kyle-collins-projects.vercel.app",
        "https://cybersec-suite.vercel.app",
        "http://localhost:3000",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include existing routers
app.include_router(auth.router)
app.include_router(agents.router)
app.include_router(events.router)
app.include_router(scanner.router)
app.include_router(phishing.router)
app.include_router(breach.router)

# Configure and include multi-org router
from packages.multi_org.backend.router import router as org_router
from app.database import get_db as app_get_db
from app.auth import get_current_user as app_get_current_user

# Override dependencies at app level
app.dependency_overrides = {
    "get_db": app_get_db,
    "get_current_user": app_get_current_user
}

# Include multi-org router
app.include_router(org_router)

# Health check endpoints
@app.get("/")
def root():
    return {"message": "CyberSec Suite API is running", "status": "healthy"}

@app.get("/health")
def health():
    return {"status": "healthy"}