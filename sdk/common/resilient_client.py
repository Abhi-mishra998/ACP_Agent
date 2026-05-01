import time
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog
from opentelemetry import trace
from opentelemetry.propagate import inject
from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential_jitter,
)

from sdk.utils import CIRCUIT_BREAKER_STATE_TOTAL

logger = structlog.get_logger(__name__)


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


_N_TEST_REQUESTS = 5  # Number of concurrent successful requests needed to close circuit


class CircuitBreaker:
    """
    Per-host state for circuit breaking logic.
    Hyperscale version: Deterministic HALF-OPEN recovery.
    """

    def __init__(
        self, failure_threshold: int = 5, recovery_timeout: float = 30.0
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.test_success_count = 0
        self.opened_at = 0.0

    def can_execute(self) -> bool:
        now = time.monotonic()
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            if now - self.opened_at > self.recovery_timeout:
                logger.info("circuit_breaker_transition_half_open", state=self.state)
                self.state = CircuitState.HALF_OPEN
                self.test_success_count = 0
                return True
            return False
        if self.state == CircuitState.HALF_OPEN:
            # In hyperscale, we allow a limited number of "probes"
            return self.test_success_count < _N_TEST_REQUESTS
        return True

    def record_success(self, host: str = "unknown") -> None:
        if self.state == CircuitState.HALF_OPEN:
            self.test_success_count += 1
            if self.test_success_count >= _N_TEST_REQUESTS:
                logger.info(
                    "circuit_breaker_recovered", host=host, tests=_N_TEST_REQUESTS
                )
                CIRCUIT_BREAKER_STATE_TOTAL.labels(
                    service_name=host, state="closed"
                ).inc()
                self.state = CircuitState.CLOSED
                self.failure_count = 0
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0

    def record_failure(self, host: str = "unknown") -> None:
        if self.state == CircuitState.HALF_OPEN:
            # Immediate regression to OPEN on any failure during probe
            logger.warning("circuit_breaker_probe_failed", host=host)
            self.state = CircuitState.OPEN
            self.opened_at = time.monotonic()
            self.test_success_count = 0
        else:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                if self.state != CircuitState.OPEN:
                    logger.error(
                        "circuit_breaker_opened",
                        failure_count=self.failure_count,
                        host=host,
                    )
                    CIRCUIT_BREAKER_STATE_TOTAL.labels(
                        service_name=host, state="open"
                    ).inc()
                self.state = CircuitState.OPEN
                self.opened_at = time.monotonic()


class SLABudgetExceeded(httpx.TimeoutException):
    """Raised when the E2E latency budget is exhausted."""



class ResilientClient:
    """
    Enterprise-grade HTTP Client wrapper with built-in:
    - Circuit Breaker (Host-isolated)
    - Exponential Backoff & Jitter retries
    - Precise Retry Classification (Safe retries only)
    - OpenTelemetry Context Propagation
    """

    # Shared circuit state across client instances using the same hosts
    _circuits: dict[str, CircuitBreaker] = {}

    def __init__(self, timeout: float = 5.0, retries: int = 3) -> None:
        self._timeout = httpx.Timeout(timeout, connect=timeout * 0.5)
        self._retries = retries
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    def _get_circuit(self, url: str) -> CircuitBreaker:
        host = urlparse(url).netloc
        if host not in self._circuits:
            self._circuits[host] = CircuitBreaker()
        return self._circuits[host]

    async def close(self) -> None:
        import contextlib

        if self._client and not self._client.is_closed:
            with contextlib.suppress(Exception):
                await self._client.aclose()

    def _get_headers(self, custom_headers: dict[str, str] | None) -> dict[str, str]:
        headers = custom_headers.copy() if custom_headers else {}
        request_id = structlog.contextvars.get_contextvars().get("request_id")
        if request_id and "X-Request-ID" not in headers:
            headers["X-Request-ID"] = request_id
        inject(headers)
        return headers

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute an HTTP request with circuit breaking and retries."""
        host = urlparse(url).netloc
        circuit = self._get_circuit(url)

        if not circuit.can_execute():
            logger.warning("circuit_breaker_active_fail_fast", url=url, host=host)
            raise httpx.ConnectError(f"Circuit breaker is OPEN for {url}")

        # SLO & Header Preparation
        deadline = self._calculate_deadline(headers)
        headers = headers or {}
        headers["X-ACP-Deadline"] = str(deadline)

        final_headers = self._get_headers(headers)
        await self._get_client()

        return await self._execute_request_loop(
            method, url, final_headers, deadline, circuit, host, **kwargs
        )

    def _calculate_deadline(self, headers: dict[str, str] | None) -> float:
        """Determine the E2E latency budget/deadline."""
        if headers:
            deadline_str = headers.get("X-ACP-Deadline")
            if deadline_str:
                return float(deadline_str)

        # Default budget: current time + timeout
        read_timeout = self._timeout.read or 5.0
        return time.time() + float(read_timeout)

    def _is_transient_error(self, e: Exception) -> bool:
        """Categorize exception for retry logic."""
        if isinstance(e, SLABudgetExceeded):
            return False

        # Retry on standard network/connection issues
        if isinstance(e, (httpx.ConnectError, httpx.TimeoutException)):
            return True

        # Retry on specific HTTP status codes (Server Error or Rate Limited)
        if isinstance(e, httpx.HTTPStatusError):
            return e.response.status_code in (429, 502, 503, 504)

        return False

    async def _execute_request_loop(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        deadline: float,
        circuit: CircuitBreaker,
        host: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Handle the retry loop logic for the request."""
        retryer = AsyncRetrying(
            stop=stop_after_attempt(self._retries),
            wait=wait_exponential_jitter(initial=0.1, max=2.5),
            retry=retry_if_exception(self._is_transient_error),
            reraise=True,
        )

        async for attempt in retryer:
            with attempt:
                remaining = deadline - time.time()
                if remaining <= 0:
                    logger.warning(
                        "slo_budget_exhausted_before_retry", url=url, deadline=deadline
                    )
                    raise SLABudgetExceeded(f"Global SLA deadline exceeded for {url}")

                try:
                    read_timeout = self._timeout.read or 5.0
                    attempt_timeout = httpx.Timeout(min(remaining, float(read_timeout)))

                    tracer = trace.get_tracer(__name__)
                    span_name = f"{method} {url}"
                    with tracer.start_as_current_span(span_name):
                        resp = await self._client.request(  # type: ignore
                            method,
                            url,
                            headers=headers,
                            timeout=attempt_timeout,
                            **kwargs,
                        )

                        if resp.status_code in (502, 503, 504):
                            logger.warning(
                                "resilient_client_retry_server_error",
                                url=url,
                                status=resp.status_code,
                                attempt=attempt.retry_state.attempt_number,
                            )
                            resp.raise_for_status()

                        circuit.record_success(host=host)
                        return resp

                except (
                    httpx.ConnectError,
                    httpx.TimeoutException,
                    httpx.HTTPStatusError,
                ) as e:
                    circuit.record_failure(host=host)
                    is_server_error = isinstance(
                        e, httpx.HTTPStatusError
                    ) and e.response.status_code in (502, 503, 504)
                    if is_server_error:
                        raise
                    if not isinstance(e, httpx.HTTPStatusError):
                        raise
                    return e.response

        raise httpx.RequestError(f"Maximum retries reached for {url}")

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)
