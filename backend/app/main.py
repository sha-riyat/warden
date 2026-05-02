from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
import os

app = FastAPI(
    title="WARDEN",
    description="The trust layer for the agentic web",
    version="0.1.0",
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

@app.get("/health")
def health():
    return {
        "status": "operational",
        "service": "WARDEN",
        "version": "0.1.0",
        "environment": os.getenv("ENVIRONMENT", "development"),
    }

# Handler Lambda — point d'entrée AWS
handler = Mangum(app, lifespan="off")
