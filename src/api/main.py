"""SOC Analyst Agent - FastAPI Application."""

import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, generate_latest
from starlette.responses import Response

from src.config import get_settings
from src.api.routes import health as health_routes
from src.api.routes import domain as domain_routes

logger = structlog.get_logger(__name__)
settings = get_settings()

REQUEST_COUNT = Counter("http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"])
REQUEST_LATENCY = Histogram("http_request_duration_seconds", "HTTP request latency", ["method", "endpoint"])

_start_time = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    logger.info("application_starting", app_name=settings.app_name, env=settings.app_env)
    yield
    logger.info("application_shutting_down")


app = FastAPI(
    title="SOC Analyst Agent",
    description="AI-powered SOC Tier 1/2 analyst that triages security alerts, enriches indicators of compromise, correlates events across SIEM data, generates investigation playbooks, and produces incident summary reports for escalation.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.app_env == "development" else ["https://*.example.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_middleware(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = time.time() - start
    REQUEST_COUNT.labels(request.method, request.url.path, response.status_code).inc()
    REQUEST_LATENCY.labels(request.method, request.url.path).observe(duration)
    return response


app.include_router(health_routes.router)
app.include_router(domain_routes.router)


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type="text/plain")
