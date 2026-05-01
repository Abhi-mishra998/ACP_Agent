import time

from fastapi import Header, HTTPException, status


def check_deadline(x_acp_deadline: str | None = Header(None, alias="X-ACP-Deadline")) -> bool:
    """
    Dependency to enforce end-to-end global latency budget (SLA).
    Checks if the current time exceeds the provided deadline.
    """
    if x_acp_deadline:
        try:
            deadline = float(x_acp_deadline)
            remaining = deadline - time.time()
            if remaining <= 0:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Global SLA Deadline Exceeded"
                )
        except (ValueError, TypeError):
            # If deadline is malformed, we proceed but log warning in production
            pass
    return True
