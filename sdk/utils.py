from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.semconv.resource import ResourceAttributes
from prometheus_client import Counter, Histogram
from prometheus_fastapi_instrumentator import Instrumentator

from sdk.common.exceptions import setup_exception_handlers
from sdk.common.config import settings
# Custom Metrics for ACP Hardening & Hyperscale
CIRCUIT_BREAKER_STATE_TOTAL = Counter(
    "acp_sdk_circuit_breaker_state_total",
    "Total count of circuit breaker state changes",
    ["service_name", "state"],
)

IDEMPOTENCY_HITS_TOTAL = Counter(
    "acp_idempotency_hits_total",
    "Total count of idempotency key hits",
    ["tenant_id", "outcome"],  # outcome: hit, conflict
)

IDEMPOTENCY_EVICTIONS_TOTAL = Counter(
    "acp_idempotency_evictions_total",
    "Total count of idempotency cache evictions due to memory pressure",
)

RATE_LIMIT_EXCEEDED_TOTAL = Counter(
    "acp_rate_limit_exceeded_total",
    "Total count of rate limit rejections",
    # layer: global, ip, tenant, agent, token; tier: enterprise, premium, basic
    ["layer", "tier"],
)

AUDIT_DUPLICATES_DROPPED_TOTAL = Counter(
    "acp_audit_duplicates_dropped_total",
    "Total count of logical audit duplicates dropped at ingestion",
)

# SLO Metrics
SLO_AVAILABILITY_TOTAL = Counter(
    "acp_slo_availability_total",
    "Total requests for availability SLO tracking",
    ["service", "status"],  # status: success, error
)

SLO_LATENCY_SECONDS = Histogram(
    "acp_slo_latency_seconds",
    "Request latency for p99 SLO tracking",
    ["service", "route"],
    buckets=(
        0.005,
        0.01,
        0.025,
        0.05,
        0.075,
        0.1,
        0.25,
        0.5,
        0.75,
        1.0,
        2.5,
        5.0,
        7.5,
        10.0,
    ),
)

SLO_AUDIT_DURABILITY_TOTAL = Counter(
    "acp_slo_audit_durability_total",
    "Audit record lifecycle tracking for durability SLO",
    ["stage"],  # stage: produced, ingested, persisted, dlq
)


_LOGGING_INITIALIZED = False

def setup_logging(service_name: str) -> None:
    """Configures structured JSON logging using structlog."""
    global _LOGGING_INITIALIZED
    
    # P3-1 FIX: Prevent double-registration of structlog in fastAPI uvicorn hot-reload loops
    if _LOGGING_INITIALIZED:
        return
    _LOGGING_INITIALIZED = True


    def add_trace_id(_: Any, __: Any, event_dict: dict[str, Any]) -> dict[str, Any]:
        span = trace.get_current_span()
        if span and span.get_span_context().is_valid:
            event_dict["trace_id"] = format(span.get_span_context().trace_id, "032x")
            event_dict["span_id"] = format(span.get_span_context().span_id, "016x")
        return event_dict

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            add_trace_id,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.INFO,
    )

    structlog.get_logger().info("logging_initialized", service=service_name)


def setup_tracing(app: FastAPI, service_name: str) -> None:
    """Initializes OpenTelemetry tracing across all services with OTLP Export."""
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

    otlp_endpoint = settings.OTLP_ENDPOINT
    if not otlp_endpoint:
        # P2-2 FIX: Skip tracing when no OTLP collector is configured (safe for dev/Docker)
        return

    resource = Resource(
        attributes={
            ResourceAttributes.SERVICE_NAME: service_name,
            "environment": settings.ENVIRONMENT,
        }
    )

    provider = TracerProvider(resource=resource)

    # P2-2 FIX: Use configurable endpoint instead of hardcoded localhost:4317
    exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
    processor = BatchSpanProcessor(exporter)
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)

    # Instrument the FastAPI app automatically
    FastAPIInstrumentor.instrument_app(app)



def setup_app(app: FastAPI, service_name: str) -> None:
    """
    Consolidated setup for all ACP services.
    Includes: logging, tracing, metrics, exception handlers, and CORS.
    """
    # 1. Observability
    setup_logging(service_name)
    setup_tracing(app, service_name)
    Instrumentator().instrument(app).expose(app)

    # 2. Security (CORS)
    # Origins come from ALLOWED_ORIGINS env var (comma-separated).
    # Default covers local dev; set to your domain in production.
    allowed_origins = [o.strip() for o in settings.ALLOWED_ORIGINS.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-Request-ID",
                       "X-Tenant-ID", "X-Agent-ID", "X-ACP-Tool", "X-Timestamp",
                       "X-Internal-Secret", "X-API-Key"],
        expose_headers=["X-Trace-ID", "X-Request-ID", "X-RateLimit-Remaining"],
    )

    # 3. Standard Exception Handlers (traps unhandled and SDK exceptions)
    setup_exception_handlers(app)

    @app.get("/health", tags=["ops"])
    async def health() -> dict[str, str]:
        return {
            "status": "healthy",
            "service": service_name,
            "version": "1.0.0",  # Pull from version.py in prod
        }
