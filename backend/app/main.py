from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
import os

from app.api import owners, agents, delegate, verify, audit
from app.db.rds import create_tables

app = FastAPI(
    title="WARDEN",
    description="The trust layer for the agentic web — W3C DID + Verifiable Credentials",
    version="0.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inclure tous les routers
app.include_router(owners.router, tags=["Owners"])
app.include_router(agents.router, tags=["Agents"])
app.include_router(delegate.router, tags=["Delegation"])
app.include_router(verify.router, tags=["Verification"])
app.include_router(audit.router, tags=["Audit"])


@app.get("/health", tags=["System"])
def health():
    return {
        "status": "operational",
        "service": "WARDEN",
        "version": "0.2.0",
        "environment": os.getenv("ENVIRONMENT", "development"),
    }


@app.on_event("startup")
def startup():
    """Crée les tables PostgreSQL au démarrage si elles n'existent pas."""
    try:
        create_tables()
    except Exception as e:
        print(f"Warning: Could not create tables: {e}")


# Handler Lambda
handler = Mangum(app, lifespan="off")