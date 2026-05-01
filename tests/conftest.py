from __future__ import annotations

import socket

import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: requires live stack (skipped when stack is down)")


def _stack_running() -> bool:
    try:
        sock = socket.create_connection(("localhost", 8000), timeout=2)
        sock.close()
        return True
    except OSError:
        return False


@pytest.fixture(autouse=True)
def skip_without_stack(request):
    if request.node.get_closest_marker("integration") and not _stack_running():
        pytest.skip("ACP stack not running — start with: docker compose -f infra/docker-compose.yml up -d")
