import asyncio
import time

import structlog

from sdk import ACPClient, ACPPolicyDeniedError

logger = structlog.get_logger(__name__)

# Target URLs
GATEWAY_URL = "http://localhost:8000"
IDENTITY_URL = "http://localhost:8000"

# Test agent credentials (pre-seeded in dev env or created on the fly)
# For this test, we assume an agent exists or we create one.
AGENT_ID = "6f63ecd4-0f35-41b4-b7c2-0720bbd6072a"
AGENT_SECRET = "agent-secret-123"
# Tenant ID must match the tenant the agent was registered under
TEST_TENANT_ID = "00000000-0000-0000-0000-000000000001"


async def test_high_velocity_and_throttling() -> None:
    """Simulate high velocity and verify throttling."""
    print("\n--- [SCENARIO 1] HIGH VELOCITY & THROTTLING ---")
    client = ACPClient(AGENT_ID, AGENT_SECRET, GATEWAY_URL, IDENTITY_URL)
    await client.authenticate(tenant_id=TEST_TENANT_ID)

    # Send 10 rapid requests
    latencies = []
    for i in range(15):
        start = time.time()
        try:
            await client.execute_tool("read_data", {"query": f"select_{i}"})
            elapsed = time.time() - start
            latencies.append(elapsed)
            print(f"Request {i} | Latency: {elapsed:.2f}s")
        except Exception as e:
            print(f"Request {i} failed: {e}")

    # After some point, we expect latency to jump > 2.0s due to throttling
    throttled = [lat for lat in latencies if lat > 1.5]
    if throttled:
        print(f"✅ Success: Detected {len(throttled)} throttled requests.")
    else:
        print("❌ Failure: Throttling not detected.")


async def test_loop_detection_and_kill() -> None:
    """Simulate a tool loop and verify agent termination (KILL)."""
    print("\n--- [SCENARIO 2] TOOL LOOP DETECTION & KILL-SWITCH ---")
    client = ACPClient(AGENT_ID, AGENT_SECRET, GATEWAY_URL, IDENTITY_URL)
    await client.authenticate(tenant_id=TEST_TENANT_ID)

    # Send repeating tools: A, B, A, B...
    sequence = ["tool_a", "tool_b", "tool_a", "tool_b", "tool_a"]

    for i, tool in enumerate(sequence):
        try:
            print(f"Executing {tool}...")
            await client.execute_tool(tool, {"iteration": i})
        except ACPPolicyDeniedError as e:
            print(f"✅ Success: Blocked by policy/behavior: {e}")
            if "Terminated" in str(e):
                print("✅ Success: Agent was KILLED due to loop detection.")
            return
        except Exception as e:
            print(f"Error during loop: {e}")

    print("❌ Failure: Loop was not detected or killed.")


async def test_unseen_tool_anomaly() -> None:
    """Verify that a tool not in baseline increases risk."""
    print("\n--- [SCENARIO 3] UNSEEN TOOL ANOMALY ---")
    client = ACPClient(AGENT_ID, AGENT_SECRET, GATEWAY_URL, IDENTITY_URL)
    await client.authenticate(tenant_id=TEST_TENANT_ID)

    # 1. Establish baseline
    print("Establishing baseline...")
    for _ in range(5):
        await client.execute_tool("baseline_tool", {})

    # 2. Call extreme tool
    print("Calling unseen tool...")
    try:
        # This should trigger 'unseen_tool_execution' flag
        res = await client.execute_tool("malicious_scanner_3000", {})
        print(f"Response: {res}")
    except Exception as e:
        print(f"Blocked as expected (or failed): {e}")


async def main() -> None:
    # Note: These tests require the ACP services to be running.
    # We run them sequentially to avoid cross-polluting the behavior windows.
    try:
        await test_high_velocity_and_throttling()
        await asyncio.sleep(2)
        await test_loop_detection_and_kill()
        await asyncio.sleep(2)
        await test_unseen_tool_anomaly()
    except Exception as e:
        print(f"Main loop error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
