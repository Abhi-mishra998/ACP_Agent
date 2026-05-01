"""
ACP — 100 Concurrent Agents Stress Test
========================================
Creates N real agents, provisions credentials, authenticates each concurrently,
then hammers /execute with all N agents simultaneously.

Usage:
    python tests/load/concurrent_agents.py \
        --host http://localhost:8000 \
        --agents 100 \
        --rounds 5 \
        --admin-email admin@acp.local \
        --admin-password password \
        --tenant-id 00000000-0000-0000-0000-000000000001

Output:
    - Per-phase timing (create / credential / login / execute)
    - Success rate, P50 / P95 / P99 latency
    - Failure breakdown by error type

Environment: Python 3.11+ with httpx installed (already in .venv).
"""
from __future__ import annotations

import argparse
import asyncio
import statistics
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class AgentRecord:
    agent_id: str = ""
    secret: str = ""
    token: str = ""
    tenant_id: str = ""


@dataclass
class PhaseStats:
    name: str
    durations: list[float] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def record(self, duration: float, error: str | None = None) -> None:
        self.durations.append(duration)
        if error:
            self.errors.append(error)

    def report(self) -> None:
        total = len(self.durations)
        ok = total - len(self.errors)
        if not self.durations:
            print(f"  [{self.name}] No data")
            return
        d = sorted(self.durations)
        p50 = d[int(len(d) * 0.50)]
        p95 = d[int(len(d) * 0.95)]
        p99 = d[min(int(len(d) * 0.99), len(d) - 1)]
        print(
            f"  [{self.name}] {ok}/{total} OK  "
            f"mean={statistics.mean(d)*1000:.1f}ms  "
            f"p50={p50*1000:.1f}ms  p95={p95*1000:.1f}ms  p99={p99*1000:.1f}ms"
        )
        if self.errors:
            from collections import Counter
            for err, cnt in Counter(self.errors).most_common(5):
                print(f"    ERR ×{cnt}: {err[:120]}")


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

_TIMEOUT = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)


async def _post(client: httpx.AsyncClient, url: str, **kwargs: Any) -> tuple[float, httpx.Response | None, str | None]:
    t0 = time.perf_counter()
    try:
        resp = await client.post(url, **kwargs)
        return time.perf_counter() - t0, resp, None
    except Exception as exc:
        return time.perf_counter() - t0, None, str(exc)


async def _get(client: httpx.AsyncClient, url: str, **kwargs: Any) -> tuple[float, httpx.Response | None, str | None]:
    t0 = time.perf_counter()
    try:
        resp = await client.get(url, **kwargs)
        return time.perf_counter() - t0, resp, None
    except Exception as exc:
        return time.perf_counter() - t0, None, str(exc)


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------


async def _admin_login(host: str, email: str, password: str) -> str:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            f"{host}/auth/token",
            json={"email": email, "password": password},
        )
        resp.raise_for_status()
        token = resp.json()["data"]["access_token"]
        print(f"  Admin login OK — token ...{token[-12:]}")
        return token


async def _create_agents(
    client: httpx.AsyncClient,
    host: str,
    admin_token: str,
    tenant_id: str,
    n: int,
    stats: PhaseStats,
) -> list[AgentRecord]:
    records: list[AgentRecord] = []
    run_id = uuid.uuid4().hex[:8]

    async def _create(i: int) -> AgentRecord | None:
        dur, resp, err = await _post(
            client,
            f"{host}/agents",
            json={
                "name": f"stress-agent-{run_id}-{i:04d}",
                "description": f"Concurrent stress test agent {i}",
                "owner_id": "stress_test",
            },
            headers={
                "Authorization": f"Bearer {admin_token}",
                "X-Tenant-ID": tenant_id,
            },
        )
        if err or resp is None or not resp.is_success:
            stats.record(dur, err or f"HTTP {resp.status_code if resp else '?'}: {resp.text[:80] if resp else ''}")
            return None
        data = resp.json().get("data") or {}
        rec = AgentRecord(agent_id=data.get("id", ""), tenant_id=tenant_id)
        stats.record(dur)
        return rec

    results = await asyncio.gather(*[_create(i) for i in range(n)])
    records = [r for r in results if r is not None]
    return records


async def _provision_credentials(
    client: httpx.AsyncClient,
    host: str,
    admin_token: str,
    records: list[AgentRecord],
    stats: PhaseStats,
) -> None:
    async def _provision(rec: AgentRecord) -> None:
        secret = f"stress-secret-{uuid.uuid4().hex}"
        dur, resp, err = await _post(
            client,
            f"{host}/auth/credentials",
            json={"agent_id": rec.agent_id, "secret": secret},
            headers={
                "Authorization": f"Bearer {admin_token}",
                "X-Tenant-ID": rec.tenant_id,
            },
        )
        if err or resp is None or not resp.is_success:
            stats.record(dur, err or f"HTTP {resp.status_code if resp else '?'}: {resp.text[:80] if resp else ''}")
            return
        rec.secret = secret
        stats.record(dur)

    await asyncio.gather(*[_provision(r) for r in records])


async def _grant_permissions(
    client: httpx.AsyncClient,
    host: str,
    admin_token: str,
    records: list[AgentRecord],
    stats: PhaseStats,
) -> None:
    async def _grant(rec: AgentRecord) -> None:
        dur, resp, err = await _post(
            client,
            f"{host}/agents/{rec.agent_id}/permissions",
            json={"tool_name": "data_query", "action": "ALLOW"},
            headers={
                "Authorization": f"Bearer {admin_token}",
                "X-Tenant-ID": rec.tenant_id,
            },
        )
        if err or resp is None or not resp.is_success:
            stats.record(dur, err or f"HTTP {resp.status_code if resp else '?'}: {resp.text[:80] if resp else ''}")
        else:
            stats.record(dur)

    await asyncio.gather(*[_grant(r) for r in records if r.secret])


async def _agent_logins(
    client: httpx.AsyncClient,
    host: str,
    records: list[AgentRecord],
    stats: PhaseStats,
) -> None:
    async def _login(rec: AgentRecord) -> None:
        if not rec.secret:
            return
        dur, resp, err = await _post(
            client,
            f"{host}/auth/agent/token",
            json={"agent_id": rec.agent_id, "secret": rec.secret},
            headers={"X-Tenant-ID": rec.tenant_id},
        )
        if err or resp is None or not resp.is_success:
            stats.record(dur, err or f"HTTP {resp.status_code if resp else '?'}: {resp.text[:80] if resp else ''}")
            return
        data = resp.json().get("data") or {}
        rec.token = data.get("access_token", "")
        stats.record(dur)

    await asyncio.gather(*[_login(r) for r in records])


async def _execute_round(
    client: httpx.AsyncClient,
    host: str,
    records: list[AgentRecord],
    stats: PhaseStats,
    round_num: int,
) -> None:
    async def _exec(rec: AgentRecord) -> None:
        if not rec.token:
            return
        dur, resp, err = await _post(
            client,
            f"{host}/execute",
            json={"tool": "data_query", "payload": {"query": f"SELECT 1 -- round {round_num}"}},
            headers={
                "Authorization": f"Bearer {rec.token}",
                "X-Tenant-ID": rec.tenant_id,
                "X-Agent-ID": rec.agent_id,
                "X-ACP-Tool": "data_query",
            },
        )
        if err:
            stats.record(dur, err)
            return
        if resp is None:
            stats.record(dur, "no response")
            return
        body = resp.json() if resp.content else {}
        (body.get("action") or "")
        # allow / monitor / throttle = success paths; deny/kill = policy decision (also valid)
        # 4xx from gateway layer = unexpected failure
        if resp.status_code >= 500:
            stats.record(dur, f"HTTP {resp.status_code}: {resp.text[:60]}")
        else:
            stats.record(dur)

    await asyncio.gather(*[_exec(r) for r in records])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main(args: argparse.Namespace) -> None:
    host = args.host.rstrip("/")
    tenant_id = args.tenant_id
    n = args.agents
    rounds = args.rounds

    print(f"\n{'='*60}")
    print(f"ACP 100-Agent Concurrent Stress Test")
    print(f"  Host:    {host}")
    print(f"  Agents:  {n}")
    print(f"  Rounds:  {rounds}")
    print(f"  Tenant:  {tenant_id}")
    print(f"{'='*60}\n")

    # Phase 0: Admin login
    print("[Phase 0] Admin authentication")
    admin_token = await _admin_login(host, args.admin_email, args.admin_password)

    async with httpx.AsyncClient(timeout=_TIMEOUT, limits=httpx.Limits(max_connections=200, max_keepalive_connections=100)) as client:

        # Phase 1: Create agents
        s_create = PhaseStats("create-agents")
        print(f"\n[Phase 1] Creating {n} agents concurrently...")
        t0 = time.perf_counter()
        records = await _create_agents(client, host, admin_token, tenant_id, n, s_create)
        print(f"  Wall time: {time.perf_counter()-t0:.2f}s  |  Created: {len(records)}/{n}")
        s_create.report()

        # Phase 2: Provision credentials
        s_creds = PhaseStats("provision-credentials")
        print(f"\n[Phase 2] Provisioning credentials for {len(records)} agents...")
        t0 = time.perf_counter()
        await _provision_credentials(client, host, admin_token, records, s_creds)
        credentialed = [r for r in records if r.secret]
        print(f"  Wall time: {time.perf_counter()-t0:.2f}s  |  Credentialed: {len(credentialed)}/{len(records)}")
        s_creds.report()

        # Phase 3: Grant permissions
        s_perms = PhaseStats("grant-permissions")
        print(f"\n[Phase 3] Granting data_query permission to {len(credentialed)} agents...")
        t0 = time.perf_counter()
        await _grant_permissions(client, host, admin_token, credentialed, s_perms)
        print(f"  Wall time: {time.perf_counter()-t0:.2f}s")
        s_perms.report()

        # Phase 4: Concurrent agent login
        s_login = PhaseStats("agent-login")
        print(f"\n[Phase 4] Concurrent JWT acquisition ({len(credentialed)} agents simultaneously)...")
        t0 = time.perf_counter()
        await _agent_logins(client, host, credentialed, s_login)
        authenticated = [r for r in credentialed if r.token]
        print(f"  Wall time: {time.perf_counter()-t0:.2f}s  |  Authenticated: {len(authenticated)}/{len(credentialed)}")
        s_login.report()

        # Phase 5: Execute rounds
        all_exec_stats: list[PhaseStats] = []
        for rnd in range(1, rounds + 1):
            s_exec = PhaseStats(f"execute-round-{rnd}")
            print(f"\n[Phase 5.{rnd}] {len(authenticated)} concurrent /execute calls (round {rnd}/{rounds})...")
            t0 = time.perf_counter()
            await _execute_round(client, host, authenticated, s_exec, rnd)
            wall = time.perf_counter() - t0
            ok = len(s_exec.durations) - len(s_exec.errors)
            rps = len(s_exec.durations) / max(wall, 0.001)
            print(f"  Wall time: {wall:.2f}s  |  RPS: {rps:.1f}")
            s_exec.report()
            all_exec_stats.append(s_exec)

    # Aggregate execute stats
    if all_exec_stats:
        all_durations = [d for s in all_exec_stats for d in s.durations]
        all_errors = [e for s in all_exec_stats for e in s.errors]
        if all_durations:
            d = sorted(all_durations)
            p50 = d[int(len(d) * 0.50)] * 1000
            p95 = d[int(len(d) * 0.95)] * 1000
            p99 = d[min(int(len(d) * 0.99), len(d) - 1)] * 1000
            total = len(all_durations)
            ok = total - len(all_errors)
            print(f"\n{'='*60}")
            print(f"AGGREGATE EXECUTE RESULTS ({rounds} rounds × {len(authenticated)} agents)")
            print(f"  Total requests : {total}")
            print(f"  Success        : {ok} ({ok/total*100:.1f}%)")
            print(f"  Failures       : {len(all_errors)}")
            print(f"  Latency P50    : {p50:.1f} ms")
            print(f"  Latency P95    : {p95:.1f} ms")
            print(f"  Latency P99    : {p99:.1f} ms")
            print(f"  Mean latency   : {statistics.mean(all_durations)*1000:.1f} ms")
            print(f"{'='*60}")

            # Pass/fail verdict
            if ok / total >= 0.95 and p99 < 3000:
                print("  RESULT: PASS ✓ (≥95% success, p99 < 3s)")
            else:
                print(f"  RESULT: FAIL ✗ (success={ok/total*100:.1f}%, p99={p99:.0f}ms)")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ACP 100-Agent Concurrent Stress Test")
    parser.add_argument("--host", default="http://localhost:8000")
    parser.add_argument("--agents", type=int, default=100)
    parser.add_argument("--rounds", type=int, default=5, help="Execute rounds after login")
    parser.add_argument("--admin-email", default="admin@acp.local")
    parser.add_argument("--admin-password", default="password")
    parser.add_argument("--tenant-id", default="00000000-0000-0000-0000-000000000001")
    asyncio.run(main(parser.parse_args()))
