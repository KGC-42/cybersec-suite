from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth
from app.api import agents, events, scanner, phishing, breach

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

# Include routers
app.include_router(auth.router)
app.include_router(agents.router)
app.include_router(events.router)
app.include_router(scanner.router)
app.include_router(phishing.router)
app.include_router(breach.router)

# Health check endpoint
@app.get("/")
def root():
    return {"message": "CyberSec Suite API is running", "status": "healthy"}

@app.get("/health")
def health():
    return {"status": "healthy"}