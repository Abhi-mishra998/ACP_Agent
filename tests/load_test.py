import httpx
from locust import HttpUser, between, task


class ACPUser(HttpUser):
    wait_time = between(0.1, 0.5)

    def on_start(self) -> None:
        # In a real load test, we'd authenticate once per user
        self.tenant_id = "6f63ecd4-0f35-41b4-b7c2-0720bbd6072a"
        self.agent_id = "433a56b4-ae2f-4002-b73c-85510ab3c9e0"
        self.secret = "comp-secret-very-long-123456"

        # Authenticate to get a token
        with httpx.Client() as client:
            resp = client.post(
                "http://localhost:8000/auth/agent/token",
                json={"agent_id": self.agent_id, "secret": self.secret},
                headers={"X-Tenant-ID": self.tenant_id},
            )
            data = resp.json()
            self.token = data.get("data", {}).get("access_token") or data.get("access_token", "")
            if not self.token:
                self.token = None

    @task
    def execute_data_query(self) -> None:
        self.client.post(
            "/execute/data_query",
            json={"query": "SELECT 1"},
            headers={
                "Authorization": f"Bearer {self.token}",
                "X-Tenant-ID": self.tenant_id,
            },
        )
