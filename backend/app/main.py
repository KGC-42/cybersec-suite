from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Create FastAPI app
app = FastAPI(
    title="CyberSec Suite API",
    version="0.1.0",
    description="Cybersecurity monitoring platform"
)

# CORS configuration - Allow ALL origins for now
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check endpoint
@app.get("/")
def root():
    return {"message": "CyberSec Suite API is running", "status": "healthy"}

@app.get("/health")
def health():
    return {"status": "healthy"}