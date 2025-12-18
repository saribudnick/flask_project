import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps
from flask import request, g

LOG_FILE = Path("log.attempts")


def get_timestamp():
    return datetime.now(timezone.utc).isoformat()


def generate_group_seed():
    """Generate identifier for auth attempts"""
    return "251891"


def log_auth_attempt(
    username: str,
    result: str,
    latency_ms: float,
    hash_mode: str = "bcrypt",
    protection_flags: list = None
):
    """
    Log authentication attempt in JSON lines format.
    
    Fields:
    - timestamp: ISO 8601 UTC timestamp
    - group_seed: Unique request identifier
    - username: Attempted username
    - hash_mode: Password hashing algorithm used
    - protection_flags: List of security features (e.g., ["totp", "rate_limit"])
    - result: "success", "failure", "blocked", etc.
    - latency_ms: Time taken for auth check in milliseconds
    """
    if protection_flags is None:
        protection_flags = []
    
    entry = {
        "timestamp": get_timestamp(),
        "group_seed": generate_group_seed(),
        "username": username or "unknown",
        "hash_mode": hash_mode,
        "protection_flags": protection_flags,
        "result": result,
        "latency_ms": round(latency_ms, 2)
    }
    
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    
    return entry


def timed_auth(func):
    """Decorator to measure authentication latency"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        g.auth_start_time = time.perf_counter()
        return func(*args, **kwargs)
    return wrapper


def get_latency_ms():
    """Get elapsed time since auth started"""
    start = getattr(g, 'auth_start_time', None)
    if start:
        return (time.perf_counter() - start) * 1000
    return 0.0

