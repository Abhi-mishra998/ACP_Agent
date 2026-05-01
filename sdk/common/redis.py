from __future__ import annotations

import os
from typing import Any

import structlog
from redis.asyncio import Redis
from redis.asyncio.cluster import RedisCluster

logger = structlog.get_logger(__name__)


_POOL_DEFAULTS: dict[str, Any] = {
    "max_connections": 50,
    "socket_timeout": 5.0,
    "socket_connect_timeout": 5.0,
    "retry_on_timeout": True,
    "health_check_interval": 30,  # keep idle connections alive; prevents stale-socket timeouts
}


def get_redis_client(
    url: str, decode_responses: bool = False, **kwargs: Any
) -> Redis | RedisCluster:
    """
    Returns a Redis or RedisCluster client based on the URL and environment.
    Automatic detection of cluster mode if URL scheme is 'redis' but host is a cluster.

    In this ACP setup, we use the REDIS_CLUSTER_ENABLED env var to force cluster mode.
    """
    is_cluster = os.getenv("REDIS_CLUSTER_ENABLED", "false").lower() == "true"
    pool_kwargs = {**_POOL_DEFAULTS, **kwargs}

    if is_cluster:
        logger.info("initializing_redis_cluster", url=url)
        return RedisCluster.from_url(
            url,
            decode_responses=decode_responses,
            skip_full_coverage_check=True,
            **pool_kwargs,
        )
    logger.info("initializing_redis_standalone", url=url)
    return Redis.from_url(url, decode_responses=decode_responses, **pool_kwargs)
