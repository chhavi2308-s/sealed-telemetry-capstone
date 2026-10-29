"""Shared bounded AWS SDK timeouts and standard retry policy."""

from botocore.config import Config

SDK_CONFIG = Config(
    connect_timeout=2, read_timeout=5, retries={"mode": "standard", "total_max_attempts": 3}
)
