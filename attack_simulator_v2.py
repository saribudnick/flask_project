#!/usr/bin/env python3
"""
Attack Simulator v2 - Enhanced with CAPTCHA/TOTP automation and resource limits

Features:
- Resource limits: 50,000 attempts default, 1,000,000 max, 2 hours max
- CAPTCHA automation via admin endpoint
- TOTP automation with clock drift simulation
- Load users from users.json
- Comprehensive metrics collection
"""

import json
import time
import urllib.request
import urllib.error
import psutil
import os
import statistics
import pyotp
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import threading

# Configuration
BASE_URL = "http://127.0.0.1:5000"
LOGIN_ENDPOINT = f"{BASE_URL}/auth/login"
LOGIN_TOTP_ENDPOINT = f"{BASE_URL}/auth/login_totp"
CAPTCHA_TOKEN_ENDPOINT = f"{BASE_URL}/admin/get_captcha_token"
CAPTCHA_RESET_ENDPOINT = f"{BASE_URL}/admin/reset_captcha"

# Resource Limits
DEFAULT_MAX_ATTEMPTS = 50_000
ABSOLUTE_MAX_ATTEMPTS = 1_000_000
MAX_RUNTIME_SECONDS = 2 * 60 * 60  # 2 hours

# Common password lists
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "111111",
    "monkey", "master", "dragon", "letmein", "login",
    "admin", "welcome", "password1", "p@ssw0rd", "123123",
    "654321", "superman", "qwerty123", "michael", "football"
]


def load_users_json() -> Dict:
    """Load users from users.json file"""
    users_file = Path(__file__).parent / "users.json"
    if users_file.exists():
        with open(users_file) as f:
            return json.load(f)
    return {"users": []}


@dataclass
class AttackConfig:
    """Configuration for attack simulation"""
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    max_runtime_seconds: int = MAX_RUNTIME_SECONDS
    max_workers: int = 1
    delay_between_attempts: float = 0.0
    handle_captcha: bool = True
    handle_totp: bool = True
    totp_clock_drift_seconds: int = 0  # Simulate clock drift


@dataclass
class AttackMetrics:
    """Metrics collected during attack simulation"""
    attack_type: str
    config_name: str
    defense_config: str = ""
    start_time: str = ""
    end_time: str = ""
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    blocked_attempts: int = 0
    captcha_challenges: int = 0
    captcha_bypassed: int = 0
    totp_attempts: int = 0
    total_time_seconds: float = 0.0
    attempts_per_second: float = 0.0
    time_to_first_compromise_seconds: Optional[float] = None
    time_to_first_block_seconds: Optional[float] = None
    time_to_first_captcha_seconds: Optional[float] = None
    success_rate_percent: float = 0.0
    block_rate_percent: float = 0.0
    captcha_rate_percent: float = 0.0
    latencies_ms: List[float] = field(default_factory=list)
    avg_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    cpu_usage_percent: List[float] = field(default_factory=list)
    avg_cpu_percent: float = 0.0
    memory_usage_mb: List[float] = field(default_factory=list)
    avg_memory_mb: float = 0.0
    peak_memory_mb: float = 0.0
    compromised_accounts: List[str] = field(default_factory=list)
    stopped_reason: str = ""  # "completed", "max_attempts", "max_runtime", "error"
    errors: List[str] = field(default_factory=list)


class ResourceMonitor:
    """Monitor CPU and memory usage during attack"""
    
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
            "cpu_samples": self.cpu_samples,
            "memory_samples": self.memory_samples,
            "avg_cpu": statistics.mean(self.cpu_samples) if self.cpu_samples else 0,
            "avg_memory": statistics.mean(self.memory_samples) if self.memory_samples else 0,
            "peak_memory": max(self.memory_samples) if self.memory_samples else 0
        }


class CaptchaHandler:
    """Handle CAPTCHA automation via admin endpoint"""
    
    @staticmethod
    def get_token(group_seed: str) -> Optional[str]:
        """Get a valid CAPTCHA token from admin endpoint"""
        try:
            url = f"{CAPTCHA_TOKEN_ENDPOINT}?group_seed={group_seed}"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                return data.get("captcha_token")
        except Exception as e:
            print(f"      ⚠️ Failed to get CAPTCHA token: {e}")
            return None
    
    @staticmethod
    def reset_captcha() -> bool:
        """Reset CAPTCHA state for current IP"""
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


class TOTPHandler:
    """Handle TOTP automation with clock drift simulation"""
    
    def __init__(self, clock_drift_seconds: int = 0):
        self.clock_drift = clock_drift_seconds
    
    def generate_code(self, secret: str) -> str:
        """Generate TOTP code with optional clock drift"""
        totp = pyotp.TOTP(secret)
        if self.clock_drift:
            # Simulate clock drift by adjusting the time
            adjusted_time = time.time() + self.clock_drift
            return totp.at(adjusted_time)
        return totp.now()
    
    def get_drift_info(self) -> Dict:
        """Get clock drift simulation info"""
        return {
            "injected_deviation_seconds": self.clock_drift,
            "correction_applied": 0,  # Would be set by time-sync mechanism
            "final_error_seconds": self.clock_drift
        }


def make_request(url: str, data: Dict, timeout: int = 30) -> Tuple[Dict, int, float]:
    """Make HTTP request and return (response_data, status_code, latency_ms)"""
    start = time.perf_counter()
    
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode(),
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


def make_login_request(
    username: str, 
    password: str, 
    config: AttackConfig,
    totp_secret: Optional[str] = None,
    totp_handler: Optional[TOTPHandler] = None
) -> Dict:
    """Make a login request with CAPTCHA and TOTP handling"""
    result = {
        "username": username,
        "password": password,
        "success": False,
        "blocked": False,
        "captcha_required": False,
        "captcha_bypassed": False,
        "totp_used": False,
        "latency_ms": 0,
        "error": None
    }
    
    # Prepare login data
    login_data = {"username": username, "password": password}
    endpoint = LOGIN_ENDPOINT
    
    # If TOTP secret provided, use TOTP endpoint
    if totp_secret and totp_handler:
        totp_code = totp_handler.generate_code(totp_secret)
        login_data["totp_code"] = totp_code
        endpoint = LOGIN_TOTP_ENDPOINT
        result["totp_used"] = True
    
    # First attempt
    response, status, latency = make_request(endpoint, login_data)
    result["latency_ms"] = latency
    
    # Handle CAPTCHA if required
    if status == 403 and response.get("captcha_required") and config.handle_captcha:
        result["captcha_required"] = True
        
        # Get CAPTCHA token from admin endpoint
        group_seed = response.get("group_seed", "auto")
        token = CaptchaHandler.get_token(group_seed)
        
        if token:
            # Retry with CAPTCHA token
            login_data["captcha_token"] = token
            response, status, retry_latency = make_request(endpoint, login_data)
            result["latency_ms"] += retry_latency
            result["captcha_bypassed"] = True
    
    # Check result
    if status == 429:
        result["blocked"] = True
        result["error"] = "rate_limit_exceeded"
    elif status == 200 and "token" in response:
        result["success"] = True
    elif response.get("totp_required"):
        # Password correct but TOTP needed
        result["success"] = True  # Credentials found
        result["note"] = "totp_required"
    elif response.get("error"):
        result["error"] = response.get("error")
    
    return result


def run_attack(
    attack_type: str,
    targets: List[Tuple[str, str, Optional[str]]],  # (username, password, totp_secret)
    config: AttackConfig,
    config_name: str,
    defense_config: str = ""
) -> AttackMetrics:
    """
    Run attack simulation with resource limits.
    
    Args:
        attack_type: "brute_force" or "password_spray"
        targets: List of (username, password, totp_secret) tuples
        config: Attack configuration
        config_name: Name for this configuration
        defense_config: Description of server defenses
    """
    metrics = AttackMetrics(
        attack_type=attack_type,
        config_name=config_name,
        defense_config=defense_config,
        start_time=datetime.now(timezone.utc).isoformat()
    )
    
    monitor = ResourceMonitor()
    monitor.start()
    
    start_time = time.perf_counter()
    first_compromise_time = None
    first_block_time = None
    first_captcha_time = None
    
    totp_handler = TOTPHandler(config.totp_clock_drift_seconds)
    
    print(f"\n🎯 {attack_type.upper()} Attack")
    print(f"   Config: {config_name}")
    print(f"   Defense: {defense_config}")
    print(f"   Targets: {len(targets)}, Workers: {config.max_workers}")
    print(f"   Limits: {config.max_attempts:,} attempts, {config.max_runtime_seconds}s runtime")
    print("-" * 60)
    
    stopped_reason = "completed"
    
    for i, (username, password, totp_secret) in enumerate(targets):
        # Check resource limits
        elapsed = time.perf_counter() - start_time
        if metrics.total_attempts >= config.max_attempts:
            stopped_reason = "max_attempts"
            print(f"   ⏹️ Stopped: Max attempts ({config.max_attempts:,}) reached")
            break
        if elapsed >= config.max_runtime_seconds:
            stopped_reason = "max_runtime"
            print(f"   ⏹️ Stopped: Max runtime ({config.max_runtime_seconds}s) reached")
            break
        
        # Make request
        result = make_login_request(
            username, password, config, 
            totp_secret if config.handle_totp else None,
            totp_handler
        )
        
        metrics.total_attempts += 1
        metrics.latencies_ms.append(result["latency_ms"])
        
        if result["totp_used"]:
            metrics.totp_attempts += 1
        
        if result["captcha_required"]:
            metrics.captcha_challenges += 1
            if first_captcha_time is None:
                first_captcha_time = time.perf_counter() - start_time
            if result["captcha_bypassed"]:
                metrics.captcha_bypassed += 1
        
        if result["blocked"]:
            metrics.blocked_attempts += 1
            if first_block_time is None:
                first_block_time = time.perf_counter() - start_time
            print(f"   🚫 BLOCKED: {username}")
        elif result["success"]:
            metrics.successful_attempts += 1
            metrics.compromised_accounts.append(f"{username}:{password}")
            if first_compromise_time is None:
                first_compromise_time = time.perf_counter() - start_time
            note = f" ({result.get('note', '')})" if result.get('note') else ""
            print(f"   ✓ FOUND: {username}{note}")
        else:
            metrics.failed_attempts += 1
        
        if result["error"] and not result["blocked"]:
            metrics.errors.append(result["error"])
        
        if config.delay_between_attempts > 0:
            time.sleep(config.delay_between_attempts)
    
    # Finalize metrics
    monitor.stop()
    end_time = time.perf_counter()
    
    metrics.end_time = datetime.now(timezone.utc).isoformat()
    metrics.total_time_seconds = end_time - start_time
    metrics.time_to_first_compromise_seconds = first_compromise_time
    metrics.time_to_first_block_seconds = first_block_time
    metrics.time_to_first_captcha_seconds = first_captcha_time
    metrics.stopped_reason = stopped_reason
    
    if metrics.total_time_seconds > 0:
        metrics.attempts_per_second = metrics.total_attempts / metrics.total_time_seconds
    if metrics.total_attempts > 0:
        metrics.success_rate_percent = (metrics.successful_attempts / metrics.total_attempts) * 100
        metrics.block_rate_percent = (metrics.blocked_attempts / metrics.total_attempts) * 100
        metrics.captcha_rate_percent = (metrics.captcha_challenges / metrics.total_attempts) * 100
    
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
    metrics.cpu_usage_percent = stats["cpu_samples"]
    metrics.avg_cpu_percent = stats["avg_cpu"]
    metrics.memory_usage_mb = stats["memory_samples"]
    metrics.avg_memory_mb = stats["avg_memory"]
    metrics.peak_memory_mb = stats["peak_memory"]
    
    return metrics


def print_metrics_report(metrics: AttackMetrics):
    """Print a formatted metrics report"""
    print("\n" + "=" * 70)
    print(f"📊 ATTACK METRICS REPORT")
    print("=" * 70)
    print(f"Attack Type:     {metrics.attack_type}")
    print(f"Configuration:   {metrics.config_name}")
    print(f"Defense Config:  {metrics.defense_config}")
    print(f"Start Time:      {metrics.start_time}")
    print(f"End Time:        {metrics.end_time}")
    print(f"Stopped Reason:  {metrics.stopped_reason}")
    print("-" * 70)
    print("ATTEMPT STATISTICS")
    print(f"  Total Attempts:      {metrics.total_attempts:,}")
    print(f"  Successful:          {metrics.successful_attempts:,}")
    print(f"  Failed:              {metrics.failed_attempts:,}")
    print(f"  Blocked (429):       {metrics.blocked_attempts:,}")
    print(f"  CAPTCHA Challenges:  {metrics.captcha_challenges:,}")
    print(f"  CAPTCHA Bypassed:    {metrics.captcha_bypassed:,}")
    print(f"  TOTP Attempts:       {metrics.totp_attempts:,}")
    print(f"  Success Rate:        {metrics.success_rate_percent:.2f}%")
    print(f"  Block Rate:          {metrics.block_rate_percent:.2f}%")
    print(f"  CAPTCHA Rate:        {metrics.captcha_rate_percent:.2f}%")
    print("-" * 70)
    print("TIMING METRICS")
    print(f"  Total Time:          {metrics.total_time_seconds:.2f} seconds")
    print(f"  Attempts/Second:     {metrics.attempts_per_second:.2f}")
    if metrics.time_to_first_compromise_seconds is not None:
        print(f"  Time to Compromise:  {metrics.time_to_first_compromise_seconds:.2f} seconds")
    if metrics.time_to_first_block_seconds is not None:
        print(f"  Time to First Block: {metrics.time_to_first_block_seconds:.2f} seconds")
    if metrics.time_to_first_captcha_seconds is not None:
        print(f"  Time to CAPTCHA:     {metrics.time_to_first_captcha_seconds:.2f} seconds")
    print("-" * 70)
    print("LATENCY METRICS")
    print(f"  Average Latency:     {metrics.avg_latency_ms:.2f} ms")
    print(f"  Min Latency:         {metrics.min_latency_ms:.2f} ms")
    print(f"  Max Latency:         {metrics.max_latency_ms:.2f} ms")
    print(f"  P95 Latency:         {metrics.p95_latency_ms:.2f} ms")
    print("-" * 70)
    print("RESOURCE USAGE")
    print(f"  Avg CPU Usage:       {metrics.avg_cpu_percent:.1f}%")
    print(f"  Avg Memory:          {metrics.avg_memory_mb:.1f} MB")
    print(f"  Peak Memory:         {metrics.peak_memory_mb:.1f} MB")
    print("-" * 70)
    if metrics.compromised_accounts:
        print("COMPROMISED ACCOUNTS")
        for account in metrics.compromised_accounts[:10]:  # Show first 10
            print(f"  🔓 {account}")
        if len(metrics.compromised_accounts) > 10:
            print(f"  ... and {len(metrics.compromised_accounts) - 10} more")
    if metrics.blocked_attempts > 0:
        print(f"🛡️  RATE LIMITING: Blocked {metrics.blocked_attempts:,} attempts ({metrics.block_rate_percent:.1f}%)")
    if metrics.captcha_challenges > 0:
        print(f"🔐 CAPTCHA: Challenged {metrics.captcha_challenges:,} times, bypassed {metrics.captcha_bypassed:,}")
    if metrics.errors:
        print(f"⚠️  ERRORS: {len(metrics.errors)} errors occurred")
    print("=" * 70)


def save_metrics(metrics: AttackMetrics, filename: str = "attack_metrics_v2.json"):
    """Save metrics to JSON file"""
    data = asdict(metrics)
    # Summarize large arrays
    data["latencies_ms"] = f"[{len(metrics.latencies_ms)} samples, avg={metrics.avg_latency_ms:.2f}ms]"
    data["cpu_usage_percent"] = f"[{len(metrics.cpu_usage_percent)} samples, avg={metrics.avg_cpu_percent:.1f}%]"
    data["memory_usage_mb"] = f"[{len(metrics.memory_usage_mb)} samples, avg={metrics.avg_memory_mb:.1f}MB]"
    
    with open(filename, "a") as f:
        f.write(json.dumps(data, indent=2) + "\n---\n")
    
    print(f"\n📁 Metrics saved to {filename}")


def run_full_simulation():
    """Run comprehensive attack simulation suite"""
    
    # Load users from users.json
    users_data = load_users_json()
    users = users_data.get("users", [])
    
    # Prepare target lists
    weak_targets = [(u["username"], u["password"], u.get("secret_totp")) 
                    for u in users if u.get("category") == "weak"]
    all_targets = [(u["username"], u["password"], u.get("secret_totp")) for u in users]
    totp_targets = [(u["username"], u["password"], u.get("secret_totp")) 
                    for u in users if u.get("secret_totp")]
    
    # Generate brute-force targets (one user, many passwords)
    brute_force_targets = [(weak_targets[0][0], pwd, None) for pwd in COMMON_PASSWORDS]
    
    # Password spray targets (all users, common passwords)
    spray_targets = []
    for pwd in COMMON_PASSWORDS[:5]:
        for user in all_targets[:15]:
            spray_targets.append((user[0], pwd, user[2]))
    
    results = []
    
    print("\n" + "🚀" * 35)
    print("ATTACK SIMULATION SUITE v2")
    print("🚀" * 35)
    
    # Reset CAPTCHA before tests
    CaptchaHandler.reset_captcha()
    
    # Test 1: Brute-force with all defenses
    config1 = AttackConfig(max_attempts=50, handle_captcha=True)
    metrics1 = run_attack(
        "brute_force",
        brute_force_targets[:50],
        config1,
        "brute_force_all_defenses",
        "rate_limit=5/min, captcha=5_fails, argon2id"
    )
    print_metrics_report(metrics1)
    results.append(metrics1)
    
    # Reset CAPTCHA
    CaptchaHandler.reset_captcha()
    
    # Test 2: Password spray with defenses
    config2 = AttackConfig(max_attempts=75, handle_captcha=True)
    metrics2 = run_attack(
        "password_spray",
        spray_targets[:75],
        config2,
        "spray_all_defenses",
        "rate_limit=5/min, captcha=5_fails, argon2id"
    )
    print_metrics_report(metrics2)
    results.append(metrics2)
    
    # Save all results
    for m in results:
        save_metrics(m)
    
    # Summary
    print("\n" + "=" * 80)
    print("📋 SIMULATION SUMMARY")
    print("=" * 80)
    headers = ["Config", "Attempts", "Rate/s", "Success%", "Block%", "CAPTCHA%", "Compromised"]
    print(f"{headers[0]:<30} {headers[1]:<10} {headers[2]:<10} {headers[3]:<10} {headers[4]:<10} {headers[5]:<10} {headers[6]:<10}")
    print("-" * 100)
    for m in results:
        print(f"{m.config_name:<30} {m.total_attempts:<10} {m.attempts_per_second:<10.1f} "
              f"{m.success_rate_percent:<10.1f} {m.block_rate_percent:<10.1f} "
              f"{m.captcha_rate_percent:<10.1f} {len(m.compromised_accounts):<10}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--suite":
        run_full_simulation()
    else:
        print("Attack Simulator v2")
        print("=" * 50)
        print("Features:")
        print("  - Resource limits (50K default, 1M max, 2hr max)")
        print("  - CAPTCHA automation via admin endpoint")
        print("  - TOTP automation with clock drift simulation")
        print("  - Load users from users.json")
        print()
        print("Usage:")
        print("  python attack_simulator_v2.py --suite    Run full simulation")

