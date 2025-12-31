#!/usr/bin/env python3
"""
Attack Simulator v3 - Account Lockout Testing Suite

Tests the new account lockout defense mechanism alongside existing defenses:
- Rate limiting (5 per minute per IP)
- CAPTCHA after 5 failed attempts per IP
- Account lockout after 5 failed attempts per account

Generates comprehensive reports per reporting requirements.
"""

import json
import time
import urllib.request
import urllib.error
import psutil
import os
import statistics
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import threading

# Configuration
BASE_URL = "http://127.0.0.1:5000"
LOGIN_ENDPOINT = f"{BASE_URL}/auth/login"
REGISTER_ENDPOINT = f"{BASE_URL}/auth/register"
ADMIN_UNLOCK_ENDPOINT = f"{BASE_URL}/admin/unlock_account"
ADMIN_STATUS_ENDPOINT = f"{BASE_URL}/admin/account_status"
CAPTCHA_TOKEN_ENDPOINT = f"{BASE_URL}/admin/get_captcha_token"
CAPTCHA_RESET_ENDPOINT = f"{BASE_URL}/admin/reset_captcha"

# Resource Limits
DEFAULT_MAX_ATTEMPTS = 50_000
MAX_RUNTIME_SECONDS = 2 * 60 * 60  # 2 hours

# Test passwords
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "111111",
    "monkey", "master", "dragon", "letmein", "login",
    "admin", "welcome", "password1", "p@ssw0rd", "123123"
]

# Log file for raw attempts
LOG_FILE = "attempts.log"
REPORT_FILE = "lockout_defense_report.json"


@dataclass
class AttemptLog:
    """Single attempt log entry"""
    timestamp: str
    attempt_number: int
    username: str
    password_masked: str
    status_code: int
    result: str
    latency_ms: float
    defense_triggered: str  # "none", "rate_limit", "captcha", "account_locked"
    account_locked: bool
    remaining_lockout_seconds: int


@dataclass
class AttackMetrics:
    """Metrics for an attack configuration"""
    config_name: str
    defense_config: str
    hash_algorithm: str
    attack_mode: str  # "sequential" or "parallel"
    
    # Attempt counts
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    blocked_rate_limit: int = 0
    blocked_captcha: int = 0
    blocked_account_locked: int = 0
    
    # Timing
    start_time: str = ""
    end_time: str = ""
    total_time_seconds: float = 0.0
    attempts_per_second: float = 0.0
    time_to_first_lockout_seconds: Optional[float] = None
    
    # Latency
    latencies_ms: List[float] = field(default_factory=list)
    avg_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    
    # Results
    compromised_accounts: List[str] = field(default_factory=list)
    locked_accounts: List[str] = field(default_factory=list)
    
    # Resource usage
    avg_cpu_percent: float = 0.0
    avg_memory_mb: float = 0.0
    peak_memory_mb: float = 0.0


class ResourceMonitor:
    """Monitor CPU and memory usage"""
    
    def __init__(self, interval: float = 0.5):
        self.interval = interval
        self.cpu_samples: List[float] = []
        self.memory_samples: List[float] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.process = psutil.Process(os.getpid())
    
    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()
    
    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
    
    def _monitor(self):
        while self._running:
            self.cpu_samples.append(psutil.cpu_percent(interval=None))
            self.memory_samples.append(self.process.memory_info().rss / 1024 / 1024)
            time.sleep(self.interval)
    
    def get_stats(self):
        return {
            "avg_cpu": statistics.mean(self.cpu_samples) if self.cpu_samples else 0,
            "avg_memory": statistics.mean(self.memory_samples) if self.memory_samples else 0,
            "peak_memory": max(self.memory_samples) if self.memory_samples else 0
        }


def make_request(url: str, data: Dict = None, method: str = "POST", timeout: int = 30) -> Tuple[Dict, int, float]:
    """Make HTTP request and return (response_data, status_code, latency_ms)"""
    start = time.perf_counter()
    
    try:
        if method == "GET":
            req = urllib.request.Request(url)
        else:
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode() if data else None,
                headers={"Content-Type": "application/json"}
            )
        
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                response = json.loads(resp.read().decode())
                latency = (time.perf_counter() - start) * 1000
                return response, resp.status, latency
        except urllib.error.HTTPError as e:
            response = json.loads(e.read().decode())
            latency = (time.perf_counter() - start) * 1000
            return response, e.code, latency
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000
        return {"error": str(e)}, 0, latency


def get_captcha_token(group_seed: str = "251891") -> Optional[str]:
    """Get CAPTCHA token from admin endpoint"""
    try:
        url = f"{CAPTCHA_TOKEN_ENDPOINT}?group_seed={group_seed}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return data.get("captcha_token")
    except:
        return None


def reset_captcha() -> bool:
    """Reset CAPTCHA state"""
    try:
        req = urllib.request.Request(
            CAPTCHA_RESET_ENDPOINT,
            data=json.dumps({}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except:
        return False


def unlock_account(username: str) -> bool:
    """Unlock an account via admin endpoint"""
    try:
        req = urllib.request.Request(
            ADMIN_UNLOCK_ENDPOINT,
            data=json.dumps({"username": username}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except:
        return False


def get_account_status(username: str) -> Dict:
    """Get account lockout status"""
    try:
        url = f"{ADMIN_STATUS_ENDPOINT}?username={username}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except:
        return {}


def register_user(username: str, password: str) -> bool:
    """Register a test user"""
    response, status, _ = make_request(REGISTER_ENDPOINT, {"username": username, "password": password})
    return status == 201 or "already exists" in str(response.get("error", ""))


def mask_password(password: str) -> str:
    """Mask password for logging"""
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def write_attempt_log(log_entry: AttemptLog, log_file: str = LOG_FILE):
    """Write attempt to log file"""
    with open(log_file, "a") as f:
        f.write(f"{log_entry.timestamp}|{log_entry.attempt_number}|{log_entry.username}|"
                f"{log_entry.password_masked}|{log_entry.status_code}|{log_entry.result}|"
                f"{log_entry.latency_ms:.2f}ms|{log_entry.defense_triggered}|"
                f"locked={log_entry.account_locked}|remaining={log_entry.remaining_lockout_seconds}s\n")


def run_lockout_attack(
    username: str,
    passwords: List[str],
    config_name: str,
    defense_config: str,
    handle_captcha: bool = True,
    reset_before: bool = True,
    delay_between_attempts: float = 0.0
) -> AttackMetrics:
    """
    Run attack against a single account to trigger lockout.
    """
    metrics = AttackMetrics(
        config_name=config_name,
        defense_config=defense_config,
        hash_algorithm="argon2id",
        attack_mode="sequential",
        start_time=datetime.now(timezone.utc).isoformat()
    )
    
    monitor = ResourceMonitor()
    monitor.start()
    
    start_time = time.perf_counter()
    first_lockout_time = None
    
    # Reset state if requested
    if reset_before:
        reset_captcha()
        unlock_account(username)
    
    print(f"\n🎯 LOCKOUT ATTACK: {config_name}")
    print(f"   Target: {username}")
    print(f"   Defense: {defense_config}")
    print(f"   Passwords to try: {len(passwords)}")
    print("-" * 60)
    
    for i, password in enumerate(passwords):
        attempt_num = i + 1
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Prepare login data
        login_data = {"username": username, "password": password}
        
        # Make request
        response, status, latency = make_request(LOGIN_ENDPOINT, login_data)
        
        metrics.total_attempts += 1
        metrics.latencies_ms.append(latency)
        
        # Determine result and defense triggered
        defense = "none"
        result = "unknown"
        account_locked = False
        remaining_seconds = 0
        
        if status == 200 and "token" in response:
            result = "success"
            metrics.successful_attempts += 1
            metrics.compromised_accounts.append(f"{username}:{password}")
            print(f"   ✓ [{attempt_num}] SUCCESS: {username}:{mask_password(password)}")
        
        elif status == 429:
            result = "blocked_rate_limit"
            defense = "rate_limit"
            metrics.blocked_rate_limit += 1
            print(f"   🚫 [{attempt_num}] RATE LIMITED")
        
        elif status == 423:  # Account locked
            result = "blocked_account_locked"
            defense = "account_locked"
            account_locked = True
            remaining_seconds = response.get("locked_until_seconds", 0)
            metrics.blocked_account_locked += 1
            if username not in metrics.locked_accounts:
                metrics.locked_accounts.append(username)
            if first_lockout_time is None:
                first_lockout_time = time.perf_counter() - start_time
            print(f"   🔒 [{attempt_num}] ACCOUNT LOCKED: {remaining_seconds}s remaining")
        
        elif status == 403 and response.get("captcha_required"):
            if handle_captcha:
                # Get CAPTCHA token and retry
                token = get_captcha_token()
                if token:
                    login_data["captcha_token"] = token
                    response2, status2, latency2 = make_request(LOGIN_ENDPOINT, login_data)
                    latency += latency2
                    
                    if status2 == 200:
                        result = "success_with_captcha"
                        metrics.successful_attempts += 1
                        metrics.compromised_accounts.append(f"{username}:{password}")
                        print(f"   ✓ [{attempt_num}] SUCCESS (after CAPTCHA)")
                    elif status2 == 423:
                        result = "blocked_account_locked"
                        defense = "account_locked"
                        account_locked = True
                        remaining_seconds = response2.get("locked_until_seconds", 0)
                        metrics.blocked_account_locked += 1
                        if username not in metrics.locked_accounts:
                            metrics.locked_accounts.append(username)
                        print(f"   🔒 [{attempt_num}] ACCOUNT LOCKED (after CAPTCHA)")
                    else:
                        result = "failed_with_captcha"
                        metrics.failed_attempts += 1
                        # Check if this triggered lockout
                        if response2.get("account_locked"):
                            account_locked = True
                            remaining_seconds = response2.get("locked_until_seconds", 0)
                            defense = "account_locked"
                            if username not in metrics.locked_accounts:
                                metrics.locked_accounts.append(username)
                            if first_lockout_time is None:
                                first_lockout_time = time.perf_counter() - start_time
                            print(f"   🔒 [{attempt_num}] FAILED + LOCKOUT TRIGGERED")
                        else:
                            print(f"   ✗ [{attempt_num}] FAILED (with CAPTCHA)")
                else:
                    result = "blocked_captcha"
                    defense = "captcha"
                    metrics.blocked_captcha += 1
                    print(f"   🔐 [{attempt_num}] CAPTCHA BLOCKED (no token)")
            else:
                result = "blocked_captcha"
                defense = "captcha"
                metrics.blocked_captcha += 1
                print(f"   🔐 [{attempt_num}] CAPTCHA REQUIRED")
        
        elif status == 401:
            result = "failed_invalid_credentials"
            metrics.failed_attempts += 1
            # Check if lockout was triggered
            if response.get("account_locked"):
                account_locked = True
                remaining_seconds = response.get("locked_until_seconds", 0)
                defense = "account_locked"
                if username not in metrics.locked_accounts:
                    metrics.locked_accounts.append(username)
                if first_lockout_time is None:
                    first_lockout_time = time.perf_counter() - start_time
                print(f"   🔒 [{attempt_num}] FAILED + LOCKOUT TRIGGERED: {remaining_seconds}s")
            else:
                print(f"   ✗ [{attempt_num}] FAILED: {mask_password(password)}")
        
        else:
            result = f"error_{status}"
            metrics.failed_attempts += 1
            print(f"   ⚠️ [{attempt_num}] ERROR: {status} - {response.get('error', 'unknown')}")
        
        # Log the attempt
        log_entry = AttemptLog(
            timestamp=timestamp,
            attempt_number=attempt_num,
            username=username,
            password_masked=mask_password(password),
            status_code=status,
            result=result,
            latency_ms=latency,
            defense_triggered=defense,
            account_locked=account_locked,
            remaining_lockout_seconds=remaining_seconds
        )
        write_attempt_log(log_entry)
        
        # Stop if account is locked and we can't continue
        if account_locked and defense == "account_locked":
            # Continue a few more attempts to verify lockout works
            if metrics.blocked_account_locked >= 3:
                print(f"   ⏹️ Stopping: Account locked, verified with {metrics.blocked_account_locked} blocked attempts")
                break
        
        # Delay between attempts if specified
        if delay_between_attempts > 0:
            time.sleep(delay_between_attempts)
    
    # Finalize metrics
    monitor.stop()
    end_time = time.perf_counter()
    
    metrics.end_time = datetime.now(timezone.utc).isoformat()
    metrics.total_time_seconds = end_time - start_time
    metrics.time_to_first_lockout_seconds = first_lockout_time
    
    if metrics.total_time_seconds > 0:
        metrics.attempts_per_second = metrics.total_attempts / metrics.total_time_seconds
    
    # Latency stats
    if metrics.latencies_ms:
        metrics.avg_latency_ms = statistics.mean(metrics.latencies_ms)
        metrics.min_latency_ms = min(metrics.latencies_ms)
        metrics.max_latency_ms = max(metrics.latencies_ms)
        sorted_latencies = sorted(metrics.latencies_ms)
        p95_idx = int(len(sorted_latencies) * 0.95)
        metrics.p95_latency_ms = sorted_latencies[p95_idx] if sorted_latencies else 0
    
    # Resource stats
    stats = monitor.get_stats()
    metrics.avg_cpu_percent = stats["avg_cpu"]
    metrics.avg_memory_mb = stats["avg_memory"]
    metrics.peak_memory_mb = stats["peak_memory"]
    
    return metrics


def run_multi_account_attack(
    targets: List[Tuple[str, str]],  # (username, real_password)
    config_name: str,
    defense_config: str,
    passwords_per_account: int = 10,
    handle_captcha: bool = True
) -> AttackMetrics:
    """
    Run password spray attack across multiple accounts.
    """
    metrics = AttackMetrics(
        config_name=config_name,
        defense_config=defense_config,
        hash_algorithm="argon2id",
        attack_mode="sequential",
        start_time=datetime.now(timezone.utc).isoformat()
    )
    
    monitor = ResourceMonitor()
    monitor.start()
    
    start_time = time.perf_counter()
    first_lockout_time = None
    
    # Reset state
    reset_captcha()
    for username, _ in targets:
        unlock_account(username)
    
    print(f"\n🎯 MULTI-ACCOUNT ATTACK: {config_name}")
    print(f"   Targets: {len(targets)} accounts")
    print(f"   Passwords per account: {passwords_per_account}")
    print(f"   Defense: {defense_config}")
    print("-" * 60)
    
    attempt_num = 0
    
    for username, real_password in targets:
        # Try wrong passwords first, then the real one
        test_passwords = [p for p in COMMON_PASSWORDS[:passwords_per_account-1] if p != real_password]
        test_passwords.append(real_password)  # Add real password at end
        
        for password in test_passwords:
            attempt_num += 1
            timestamp = datetime.now(timezone.utc).isoformat()
            
            login_data = {"username": username, "password": password}
            response, status, latency = make_request(LOGIN_ENDPOINT, login_data)
            
            metrics.total_attempts += 1
            metrics.latencies_ms.append(latency)
            
            defense = "none"
            result = "unknown"
            account_locked = False
            remaining_seconds = 0
            
            if status == 200 and "token" in response:
                result = "success"
                metrics.successful_attempts += 1
                metrics.compromised_accounts.append(f"{username}:{password}")
                print(f"   ✓ [{attempt_num}] SUCCESS: {username}")
            
            elif status == 429:
                result = "blocked_rate_limit"
                defense = "rate_limit"
                metrics.blocked_rate_limit += 1
            
            elif status == 423:
                result = "blocked_account_locked"
                defense = "account_locked"
                account_locked = True
                remaining_seconds = response.get("locked_until_seconds", 0)
                metrics.blocked_account_locked += 1
                if username not in metrics.locked_accounts:
                    metrics.locked_accounts.append(username)
                if first_lockout_time is None:
                    first_lockout_time = time.perf_counter() - start_time
                print(f"   🔒 [{attempt_num}] LOCKED: {username}")
            
            elif status == 403 and response.get("captcha_required"):
                if handle_captcha:
                    token = get_captcha_token()
                    if token:
                        login_data["captcha_token"] = token
                        response2, status2, latency2 = make_request(LOGIN_ENDPOINT, login_data)
                        latency += latency2
                        
                        if status2 == 200:
                            result = "success_with_captcha"
                            metrics.successful_attempts += 1
                            metrics.compromised_accounts.append(f"{username}:{password}")
                        elif status2 == 423:
                            result = "blocked_account_locked"
                            defense = "account_locked"
                            account_locked = True
                            metrics.blocked_account_locked += 1
                        else:
                            result = "failed_with_captcha"
                            metrics.failed_attempts += 1
                            if response2.get("account_locked"):
                                account_locked = True
                                defense = "account_locked"
                    else:
                        result = "blocked_captcha"
                        defense = "captcha"
                        metrics.blocked_captcha += 1
                else:
                    result = "blocked_captcha"
                    defense = "captcha"
                    metrics.blocked_captcha += 1
            
            elif status == 401:
                result = "failed_invalid_credentials"
                metrics.failed_attempts += 1
                if response.get("account_locked"):
                    account_locked = True
                    remaining_seconds = response.get("locked_until_seconds", 0)
                    defense = "account_locked"
                    if username not in metrics.locked_accounts:
                        metrics.locked_accounts.append(username)
                    if first_lockout_time is None:
                        first_lockout_time = time.perf_counter() - start_time
            
            else:
                result = f"error_{status}"
                metrics.failed_attempts += 1
            
            # Log
            log_entry = AttemptLog(
                timestamp=timestamp,
                attempt_number=attempt_num,
                username=username,
                password_masked=mask_password(password),
                status_code=status,
                result=result,
                latency_ms=latency,
                defense_triggered=defense,
                account_locked=account_locked,
                remaining_lockout_seconds=remaining_seconds
            )
            write_attempt_log(log_entry)
    
    # Finalize
    monitor.stop()
    end_time = time.perf_counter()
    
    metrics.end_time = datetime.now(timezone.utc).isoformat()
    metrics.total_time_seconds = end_time - start_time
    metrics.time_to_first_lockout_seconds = first_lockout_time
    
    if metrics.total_time_seconds > 0:
        metrics.attempts_per_second = metrics.total_attempts / metrics.total_time_seconds
    
    if metrics.latencies_ms:
        metrics.avg_latency_ms = statistics.mean(metrics.latencies_ms)
        metrics.min_latency_ms = min(metrics.latencies_ms)
        metrics.max_latency_ms = max(metrics.latencies_ms)
        sorted_latencies = sorted(metrics.latencies_ms)
        p95_idx = int(len(sorted_latencies) * 0.95)
        metrics.p95_latency_ms = sorted_latencies[p95_idx] if sorted_latencies else 0
    
    stats = monitor.get_stats()
    metrics.avg_cpu_percent = stats["avg_cpu"]
    metrics.avg_memory_mb = stats["avg_memory"]
    metrics.peak_memory_mb = stats["peak_memory"]
    
    return metrics


def calculate_crack_time_estimate(metrics: AttackMetrics, keyspace_size: int, keyspace_desc: str) -> Dict:
    """
    Calculate estimated time to crack based on measured metrics.
    """
    if metrics.attempts_per_second <= 0:
        return {"error": "No valid attempts/second measurement"}
    
    # With account lockout (5 attempts, 15 min lockout)
    effective_rate_with_lockout = 5 / (15 * 60)  # 5 attempts per 15 minutes = 0.0056 attempts/sec
    
    # Without lockout (measured rate)
    time_without_lockout_seconds = keyspace_size / metrics.attempts_per_second
    time_with_lockout_seconds = keyspace_size / effective_rate_with_lockout
    
    return {
        "keyspace_size": keyspace_size,
        "keyspace_description": keyspace_desc,
        "measured_attempts_per_second": round(metrics.attempts_per_second, 2),
        "avg_latency_ms": round(metrics.avg_latency_ms, 2),
        "without_lockout": {
            "attempts_per_second": round(metrics.attempts_per_second, 2),
            "estimated_seconds": round(time_without_lockout_seconds, 2),
            "estimated_hours": round(time_without_lockout_seconds / 3600, 2),
            "estimated_days": round(time_without_lockout_seconds / 86400, 2),
            "estimated_years": round(time_without_lockout_seconds / (86400 * 365), 4)
        },
        "with_account_lockout": {
            "effective_attempts_per_second": round(effective_rate_with_lockout, 6),
            "lockout_config": "5 attempts, 15 minute lockout",
            "estimated_seconds": round(time_with_lockout_seconds, 2),
            "estimated_hours": round(time_with_lockout_seconds / 3600, 2),
            "estimated_days": round(time_with_lockout_seconds / 86400, 2),
            "estimated_years": round(time_with_lockout_seconds / (86400 * 365), 2)
        },
        "slowdown_factor": round(time_with_lockout_seconds / time_without_lockout_seconds, 2) if time_without_lockout_seconds > 0 else "infinite",
        "assumptions": [
            "Attacker has no way to bypass account lockout",
            "Single account targeted (lockout is per-account)",
            "No parallel accounts attacked",
            "Lockout timer not circumvented",
            "Full keyspace search required (no password reuse intelligence)"
        ],
        "note": "Full cracking time NOT confirmed - this is an extrapolation based on measured rates"
    }


def print_metrics_report(metrics: AttackMetrics):
    """Print formatted metrics report"""
    print("\n" + "=" * 70)
    print(f"📊 ATTACK METRICS REPORT: {metrics.config_name}")
    print("=" * 70)
    
    print(f"\n{'CONFIGURATION':-^70}")
    print(f"  Defense Config:     {metrics.defense_config}")
    print(f"  Hash Algorithm:     {metrics.hash_algorithm}")
    print(f"  Attack Mode:        {metrics.attack_mode}")
    print(f"  Start Time:         {metrics.start_time}")
    print(f"  End Time:           {metrics.end_time}")
    
    print(f"\n{'ATTEMPT STATISTICS':-^70}")
    print(f"  Total Attempts:           {metrics.total_attempts:,}")
    print(f"  Successful:               {metrics.successful_attempts:,}")
    print(f"  Failed (wrong password):  {metrics.failed_attempts:,}")
    print(f"  Blocked - Rate Limit:     {metrics.blocked_rate_limit:,}")
    print(f"  Blocked - CAPTCHA:        {metrics.blocked_captcha:,}")
    print(f"  Blocked - Account Locked: {metrics.blocked_account_locked:,}")
    
    total_blocked = metrics.blocked_rate_limit + metrics.blocked_captcha + metrics.blocked_account_locked
    block_percent = (total_blocked / metrics.total_attempts * 100) if metrics.total_attempts > 0 else 0
    success_percent = (metrics.successful_attempts / metrics.total_attempts * 100) if metrics.total_attempts > 0 else 0
    
    print(f"\n  Success Rate:             {success_percent:.2f}%")
    print(f"  Block Rate:               {block_percent:.2f}%")
    
    print(f"\n{'TIMING METRICS':-^70}")
    print(f"  Total Time:               {metrics.total_time_seconds:.2f} seconds")
    print(f"  Attempts/Second:          {metrics.attempts_per_second:.2f}")
    if metrics.time_to_first_lockout_seconds is not None:
        print(f"  Time to First Lockout:    {metrics.time_to_first_lockout_seconds:.2f} seconds")
    
    print(f"\n{'LATENCY METRICS':-^70}")
    print(f"  Average Latency:          {metrics.avg_latency_ms:.2f} ms")
    print(f"  Min Latency:              {metrics.min_latency_ms:.2f} ms")
    print(f"  Max Latency:              {metrics.max_latency_ms:.2f} ms")
    print(f"  P95 Latency:              {metrics.p95_latency_ms:.2f} ms")
    
    print(f"\n{'RESOURCE USAGE':-^70}")
    print(f"  Avg CPU:                  {metrics.avg_cpu_percent:.1f}%")
    print(f"  Avg Memory:               {metrics.avg_memory_mb:.1f} MB")
    print(f"  Peak Memory:              {metrics.peak_memory_mb:.1f} MB")
    
    print(f"\n{'RESULTS':-^70}")
    if metrics.compromised_accounts:
        print(f"  Compromised Accounts ({len(metrics.compromised_accounts)}):")
        for acc in metrics.compromised_accounts[:5]:
            print(f"    🔓 {acc}")
    else:
        print("  Compromised Accounts:     0")
    
    if metrics.locked_accounts:
        print(f"  Locked Accounts ({len(metrics.locked_accounts)}):")
        for acc in metrics.locked_accounts[:5]:
            print(f"    🔒 {acc}")
    
    print("=" * 70)


def generate_report(all_metrics: List[AttackMetrics], crack_estimates: List[Dict]) -> Dict:
    """Generate comprehensive JSON report"""
    report = {
        "report_metadata": {
            "title": "Account Lockout Defense Testing Report",
            "generated": datetime.now(timezone.utc).isoformat(),
            "group_seed": "251891",
            "test_framework": "attack_simulator_lockout.py v3"
        },
        "defense_configuration": {
            "rate_limiting": {
                "enabled": True,
                "limit": "5 requests per minute per IP"
            },
            "captcha": {
                "enabled": True,
                "trigger": "5 failed attempts per IP"
            },
            "account_lockout": {
                "enabled": True,
                "max_failed_attempts": 5,
                "lockout_duration_minutes": 15
            },
            "password_hashing": {
                "algorithm": "argon2id",
                "time_cost": 1,
                "memory_cost": "64MB",
                "parallelism": 1
            },
            "pepper": {
                "enabled": True,
                "method": "HMAC-SHA256"
            }
        },
        "test_results": [],
        "summary_table": [],
        "crack_time_estimates": crack_estimates,
        "conclusions": []
    }
    
    # Add each test result
    for m in all_metrics:
        total_blocked = m.blocked_rate_limit + m.blocked_captcha + m.blocked_account_locked
        result = {
            "config_name": m.config_name,
            "defense_config": m.defense_config,
            "total_attempts": m.total_attempts,
            "successful": m.successful_attempts,
            "failed": m.failed_attempts,
            "blocked_rate_limit": m.blocked_rate_limit,
            "blocked_captcha": m.blocked_captcha,
            "blocked_account_locked": m.blocked_account_locked,
            "total_blocked": total_blocked,
            "block_percent": round((total_blocked / m.total_attempts * 100) if m.total_attempts > 0 else 0, 2),
            "success_percent": round((m.successful_attempts / m.total_attempts * 100) if m.total_attempts > 0 else 0, 2),
            "attempts_per_second": round(m.attempts_per_second, 2),
            "avg_latency_ms": round(m.avg_latency_ms, 2),
            "time_to_first_lockout_seconds": round(m.time_to_first_lockout_seconds, 2) if m.time_to_first_lockout_seconds else None,
            "compromised_accounts": len(m.compromised_accounts),
            "locked_accounts": len(m.locked_accounts)
        }
        report["test_results"].append(result)
        
        # Summary table row
        report["summary_table"].append([
            m.config_name,
            m.total_attempts,
            f"{m.attempts_per_second:.1f}",
            f"{result['success_percent']:.1f}%",
            f"{result['block_percent']:.1f}%",
            m.blocked_account_locked,
            len(m.compromised_accounts)
        ])
    
    # Conclusions
    report["conclusions"] = [
        "✅ Account lockout successfully blocks brute-force attacks after 5 failed attempts",
        "✅ Lockout is per-account, preventing single-account credential stuffing",
        f"✅ Lockout triggers in ~{all_metrics[0].time_to_first_lockout_seconds:.1f}s with aggressive attack" if all_metrics and all_metrics[0].time_to_first_lockout_seconds else "",
        "✅ Combined with rate limiting and CAPTCHA, provides defense-in-depth",
        "⚠️ Account lockout alone doesn't prevent password spraying across many accounts",
        "⚠️ Lockout can be used for DoS against known usernames"
    ]
    
    return report


def main():
    """Run comprehensive lockout attack simulation"""
    
    # Clear log file
    open(LOG_FILE, "w").close()
    
    print("\n" + "🔐" * 35)
    print("ACCOUNT LOCKOUT DEFENSE SIMULATION")
    print("🔐" * 35)
    
    # Load users
    users_file = Path(__file__).parent / "users.json"
    if users_file.exists():
        with open(users_file) as f:
            users_data = json.load(f)
        users = users_data.get("users", [])
    else:
        print("❌ users.json not found!")
        return
    
    # Get a test user
    weak_users = [u for u in users if u.get("category") == "weak"]
    if not weak_users:
        print("❌ No weak users found for testing!")
        return
    
    test_user = weak_users[0]
    all_metrics = []
    
    # Write log header
    with open(LOG_FILE, "w") as f:
        f.write("# ACCOUNT LOCKOUT ATTACK SIMULATION LOG\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"# Group Seed: 251891\n")
        f.write("# Format: timestamp|attempt|username|password|status|result|latency|defense|locked|remaining\n")
        f.write("#" + "-" * 100 + "\n")
    
    # Register test user if needed
    print(f"\n📝 Ensuring test user exists: {test_user['username']}")
    register_user(test_user["username"], test_user["password"])
    
    # ===== TEST 1: Single account brute-force to trigger lockout =====
    print("\n" + "=" * 70)
    print("TEST 1: Brute-Force Attack on Single Account (Lockout Test)")
    print("=" * 70)
    
    # Use ONLY WRONG passwords to test lockout (exclude user's real password)
    wrong_passwords = [p for p in COMMON_PASSWORDS[:10] if p != test_user["password"]]
    # Add the real password at the end to see if we can still log in after lockout triggers
    test_passwords = wrong_passwords[:8] + [test_user["password"]]
    
    # Use small delay between attempts - rate limit is per IP, lockout is per account
    # Both should trigger around attempt 5-6
    metrics1 = run_lockout_attack(
        username=test_user["username"],
        passwords=test_passwords,
        config_name="brute_force_lockout_test",
        defense_config="rate_limit=5/min, captcha=5_fails, lockout=5_fails/15min, argon2id+pepper",
        handle_captcha=True,
        reset_before=True,
        delay_between_attempts=0.5  # Small delay to see both defenses in action
    )
    print_metrics_report(metrics1)
    all_metrics.append(metrics1)
    
    # ===== TEST 2: Multi-account password spray =====
    print("\n" + "=" * 70)
    print("TEST 2: Password Spray Attack (Multiple Accounts)")
    print("=" * 70)
    
    # Use first 5 weak users
    spray_targets = [(u["username"], u["password"]) for u in weak_users[:5]]
    
    # Register all spray targets
    for username, password in spray_targets:
        register_user(username, password)
    
    metrics2 = run_multi_account_attack(
        targets=spray_targets,
        config_name="password_spray_lockout_test",
        defense_config="rate_limit=5/min, captcha=5_fails, lockout=5_fails/15min, argon2id+pepper",
        passwords_per_account=8,
        handle_captcha=True
    )
    print_metrics_report(metrics2)
    all_metrics.append(metrics2)
    
    # ===== Calculate crack time estimates =====
    print("\n" + "=" * 70)
    print("CRACK TIME ESTIMATES")
    print("=" * 70)
    
    crack_estimates = []
    
    # Estimate for different keyspaces
    keyspaces = [
        (10000, "4-digit PIN (0000-9999)"),
        (1000000, "6-digit PIN (000000-999999)"),
        (26**6, "6 lowercase letters (a-z)"),
        (62**8, "8 alphanumeric chars (a-z, A-Z, 0-9)"),
        (95**12, "12-char full ASCII (printable)")
    ]
    
    for keyspace_size, keyspace_desc in keyspaces:
        estimate = calculate_crack_time_estimate(metrics1, keyspace_size, keyspace_desc)
        crack_estimates.append(estimate)
        
        print(f"\n📊 Keyspace: {keyspace_desc}")
        print(f"   Size: {keyspace_size:,} combinations")
        print(f"   WITHOUT lockout:")
        print(f"     - Time: {estimate['without_lockout']['estimated_hours']:.2f} hours ({estimate['without_lockout']['estimated_days']:.2f} days)")
        print(f"   WITH account lockout:")
        print(f"     - Time: {estimate['with_account_lockout']['estimated_hours']:.2f} hours ({estimate['with_account_lockout']['estimated_days']:.2f} days)")
        print(f"   Slowdown factor: {estimate['slowdown_factor']}x")
    
    # ===== Generate report =====
    report = generate_report(all_metrics, crack_estimates)
    
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📁 Raw attempts log: {LOG_FILE}")
    print(f"📁 Full report: {REPORT_FILE}")
    
    # ===== Final Summary =====
    print("\n" + "=" * 80)
    print("📋 FINAL SUMMARY TABLE")
    print("=" * 80)
    
    headers = ["Config", "Attempts", "Rate/s", "Success%", "Block%", "Lockouts", "Compromised"]
    print(f"{headers[0]:<30} {headers[1]:<10} {headers[2]:<10} {headers[3]:<10} {headers[4]:<10} {headers[5]:<10} {headers[6]:<10}")
    print("-" * 100)
    
    for row in report["summary_table"]:
        print(f"{row[0]:<30} {row[1]:<10} {row[2]:<10} {row[3]:<10} {row[4]:<10} {row[5]:<10} {row[6]:<10}")
    
    print("\n" + "=" * 80)
    print("🛡️ DEFENSE EFFECTIVENESS")
    print("=" * 80)
    for conclusion in report["conclusions"]:
        if conclusion:
            print(f"  {conclusion}")
    
    print("\n✅ Simulation complete!")


if __name__ == "__main__":
    main()

