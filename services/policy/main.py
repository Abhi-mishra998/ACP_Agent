import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI

from sdk.utils import setup_app
from services.policy.opa_client import opa_client
from services.policy.router import init_policy_clients, router


@asynccontextmanager
async def lifespan(app: FastAPI):
    ready = await opa_client.wait_for_ready()
    if not ready:
        print("CRITICAL: OPA policy engine not ready. Exiting.")
        sys.exit(1)
    
    # Initialize Registry & Audit clients
    init_policy_clients()
    yield
    # Shutdown: Clean up client
    await opa_client.close()

app = FastAPI(
    title="ACP Policy Service",
    description="OPA-backed authorization engine for agent tool execution",
    version="1.0.0",
    lifespan=lifespan,
)

# Consolidated SDK Setup
setup_app(app, "policy")

app.include_router(router)
