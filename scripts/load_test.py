import asyncio
import time
import sys
import os
from unittest.mock import patch

# Set dummies for validation
os.environ["INTERNAL_SECRET"] = "supersecret123"
os.environ["JWT_SECRET_KEY"] = "54ea24ad3c70807c102fcdaf5ba389230690ceaf8a7be9ad758cc2eaabcb82ad"
os.environ["DATABASE_URL"] = "postgresql+asyncpg://user:pass@localhost/db"
os.environ["REDIS_URL"] = "redis://localhost:6379/0"
os.environ["INTELLIGENCE_SERVICE_URL"] = "http://localhost:8000"
os.environ["LEARNING_SERVICE_URL"] = "http://localhost:8000"
os.environ["DECISION_SERVICE_URL"] = "http://localhost:8000"
os.environ["INSIGHT_SERVICE_URL"] = "http://localhost:8000"
os.environ["BEHAVIOR_SERVICE_URL"] = "http://localhost:8000"
os.environ["API_SERVICE_URL"] = "http://localhost:8000"
os.environ["REGISTRY_SERVICE_URL"] = "http://localhost:8000"
os.environ["IDENTITY_SERVICE_URL"] = "http://localhost:8000"
os.environ["POLICY_SERVICE_URL"] = "http://localhost:8000"
os.environ["AUDIT_SERVICE_URL"] = "http://localhost:8000"
os.environ["USAGE_SERVICE_URL"] = "http://localhost:8000"
os.environ["FORENSICS_SERVICE_URL"] = "http://localhost:8000"

sys.path.append(os.getcwd())
from tests.harness import harness, TEST_AGENT_ID, TEST_TENANT_ID

async def load_test():
    print("🚀 Running Concurrency & Load Test (100 concurrent requests)")
    
    mock_payload = {
        "sub": str(TEST_AGENT_ID),
        "agent_id": str(TEST_AGENT_ID),
        "tenant_id": str(TEST_TENANT_ID),
        "role": "admin",
        "jti": "mock-jti",
        "exp": 9999999999
    }
    
    # Mock all downstreams to be fast
    with patch("services.gateway.middleware.token_validator.validate", return_value=mock_payload):
        with patch("services.gateway.middleware.service_client.evaluate_decision", return_value={"action": "allow", "risk": 0.0}):
            with patch("services.gateway.middleware.service_client.log_audit_stream", return_value=None):
                
                start_time = time.perf_counter()
                
                tasks = []
                for _ in range(100):
                    tasks.append(harness.gateway.post(
                        "/v1/tools/execute",
                        json={"tool_name": "read_file", "arguments": {}},
                        headers=harness.get_headers(token="mock-token")
                    ))
                
                responses = await asyncio.gather(*tasks)
                
                end_time = time.perf_counter()
                duration = (end_time - start_time) * 1000
                avg_latency = duration / 100
                
                success_count = sum(1 for r in responses if r.status_code == 200)
                error_count = 100 - success_count
                
                print(f"Total Time: {duration:.2f}ms")
                print(f"Avg Latency: {avg_latency:.2f}ms")
                print(f"P99 Latency: {max([r.elapsed.total_seconds() for r in responses])*1000:.2f}ms")
                print(f"Error Rate: {error_count}%")
                
                if error_count == 0 and avg_latency < 50:
                    print("✅ PERFORMANCE PASS")
                else:
                    print("❌ PERFORMANCE FAIL")

if __name__ == "__main__":
    asyncio.run(load_test())
