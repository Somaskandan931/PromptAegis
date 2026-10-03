"""
FastAPI entry point for Prompt Aegis 2.0
— Security and Governance Gateway for Tool-Using AI Agents.

Run with:  uvicorn app:app --reload --port 8000   (from backend/)
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import config
from api import chat, dashboard, detect, logs
from api import governance as governance_router
from api import experiments as experiments_router
from database.db import init_db

app = FastAPI(
    title="Prompt Aegis 2.0 — AI Agent Security & Governance Platform",
    description=(
        "Security and governance middleware for tool-using AI agents. "
        "Enforces permissions, policies, rate limits, and audit logging "
        "for every tool invocation. Includes prompt injection detection gateway."
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()


# Original prompt-detection routes
app.include_router(detect.router, tags=["detection"])
app.include_router(chat.router, tags=["aegis-chat"])
app.include_router(dashboard.router, tags=["dashboard"])
app.include_router(logs.router, tags=["logs"])

# New governance routes (Prompt Aegis 2.0 PRD)
app.include_router(governance_router.router, tags=["governance"])
app.include_router(experiments_router.router, tags=["experiments"])


@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}


@app.get("/readiness")
def readiness():
    return {"status": "ready", "version": "2.0.0"}

