from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth
from app.api import agents, events, scanner, phishing, breach

# Multi-org system imports
import sys
import os
from pathlib import Path

# Add packages to path - works for both Railway and local
backend_packages = Path(__file__).parent.parent / "packages"
root_packages = Path(__file__).parent.parent.parent.parent.parent / "packages"

if backend_packages.exists():
    # Packages in backend folder (Railway deployment)
    sys.path.insert(0, str(Path(__file__).parent.parent))
    print(f"[DEBUG] Found packages in backend: {backend_packages}")
elif root_packages.exists():
    # Packages in SAAS Scaffolding root (Local development)
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent))
    print(f"[DEBUG] Found packages in root: {root_packages}")
else:
    print("[WARNING] Could not find packages folder!")

# Debug info
print(f"[DEBUG] Current working directory: {os.getcwd()}")
print(f"[DEBUG] sys.path (first 3): {sys.path[:3]}")

# Create FastAPI app
app = FastAPI(
    title="CyberSec Suite API",
    version="0.1.0",
    description="Cybersecurity monitoring platform"
)

# CORS configuration - Allow ALL origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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