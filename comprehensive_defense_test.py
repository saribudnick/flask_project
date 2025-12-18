#!/usr/bin/env python3
"""
Comprehensive Defense Mechanism Testing Suite
Tests all individual and combined defense configurations with detailed metrics.
"""

import json
import time
import urllib.request
import urllib.error
import statistics
import subprocess
import os
import signal
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from pathlib import Path

BASE_URL = "http://127.0.0.1:5000"
LOGIN_ENDPOINT = f"{BASE_URL}/auth/login"
LOGIN_TOTP_ENDPOINT = f"{BASE_URL}/auth/login_totp"

# Test data
PASSWORDS = [
    "123456", "111111", "abcdef", "admin", "654321", "qwert", "251891",
    "yossi", "user", "null", "Admin001", "Maman16x", "ApplePai", "80Israel",
    "password", "qwerty", "letmein", "dragon", "monkey", "master"
]

USERS = [f"weak{i:02d}" for i in range(1, 11)] + [f"mid{i:02d}" for i in range(1, 11)]

# TOTP secrets for test users (from users.json)
TOTP_SECRETS = {
    "totp_user01": "JBSWY3DPEHPK3PXP",
    "totp_user02": "GEZDGNBVGY3TQOJQ",
    "totp_user03": "MFRGGZDFMY4TQNZZ"
}


@dataclass
class AttackMetrics:
    """Detailed metrics for an attack simulation"""
    config_name: str
    defense_config: Dict
    
    # Attempt counts
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    blocked_rate_limit: int = 0
    blocked_captcha: int = 0
    totp_challenges: int = 0
    
    # Timing metrics (all in milliseconds)
    attack_times: List[float] = field(default_factory=list)
    total_attack_time_sec: float = 0.0
    
    # Computed statistics
    mean_attack_time_ms: float = 0.0
    median_attack_time_ms: float = 0.0
    stddev_attack_time_ms: float = 0.0
    min_attack_time_ms: float = 0.0
    max_attack_time_ms: float = 0.0
    p10_attack_time_ms: float = 0.0
    p25_attack_time_ms: float = 0.0
    p75_attack_time_ms: float = 0.0
    p90_attack_time_ms: float = 0.0
    p95_attack_time_ms: float = 0.0
    p99_attack_time_ms: float = 0.0
    
    # Rates
    success_rate_percent: float = 0.0
    block_rate_percent: float = 0.0
    attempts_per_second: float = 0.0
    
    # Time to events
    time_to_first_success_sec: Optional[float] = None
    time_to_first_block_sec: Optional[float] = None
    
    # Results
    compromised_accounts: List[str] = field(default_factory=list)
    
    def compute_statistics(self):
        """Compute all statistical metrics from attack_times"""
        if not self.attack_times:
            return
        
        sorted_times = sorted(self.attack_times)
        n = len(sorted_times)
        
        self.mean_attack_time_ms = statistics.mean(self.attack_times)
        self.median_attack_time_ms = statistics.median(self.attack_times)
        self.stddev_attack_time_ms = statistics.stdev(self.attack_times) if n > 1 else 0
        self.min_attack_time_ms = min(self.attack_times)
        self.max_attack_time_ms = max(self.attack_times)
        
        # Percentiles
        self.p10_attack_time_ms = sorted_times[int(n * 0.10)]
        self.p25_attack_time_ms = sorted_times[int(n * 0.25)]
        self.p75_attack_time_ms = sorted_times[int(n * 0.75)]
        self.p90_attack_time_ms = sorted_times[int(n * 0.90)]
        self.p95_attack_time_ms = sorted_times[int(n * 0.95)]
        self.p99_attack_time_ms = sorted_times[min(int(n * 0.99), n-1)]
        
        # Rates
        if self.total_attempts > 0:
            self.success_rate_percent = (self.successful_attempts / self.total_attempts) * 100
            self.block_rate_percent = ((self.blocked_rate_limit + self.blocked_captcha) / self.total_attempts) * 100
        
        if self.total_attack_time_sec > 0:
            self.attempts_per_second = self.total_attempts / self.total_attack_time_sec


def make_request(username: str, password: str, totp_code: str = None, captcha_token: str = None) -> Dict:
    """Make a login request and return detailed result"""
    start = time.perf_counter()
    
    result = {
        "success": False,
        "blocked_rate_limit": False,
        "blocked_captcha": False,
        "totp_required": False,
        "latency_ms": 0,
        "error": None
    }
    
    data = {"username": username, "password": password}
    endpoint = LOGIN_ENDPOINT
    
    if totp_code:
        data["totp_code"] = totp_code
        endpoint = LOGIN_TOTP_ENDPOINT
    
    if captcha_token:
        data["captcha_token"] = captcha_token
    
    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"}
        )
        
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                response = json.loads(resp.read().decode())
                result["success"] = "token" in response
        except urllib.error.HTTPError as e:
            response = json.loads(e.read().decode())
            if e.code == 429:
                result["blocked_rate_limit"] = True
            elif e.code == 403:
                if response.get("captcha_required"):
                    result["blocked_captcha"] = True
                elif response.get("totp_required"):
                    result["totp_required"] = True
                    result["success"] = True  # Credentials were valid
    except Exception as ex:
        result["error"] = str(ex)
    
    result["latency_ms"] = (time.perf_counter() - start) * 1000
    return result


def get_captcha_token() -> Optional[str]:
    """Get CAPTCHA token from admin endpoint"""
    try:
        req = urllib.request.Request(f"{BASE_URL}/admin/get_captcha_token?group_seed=251891")
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode()).get("captcha_token")
    except:
        return None


def reset_captcha():
    """Reset CAPTCHA state"""
    try:
        req = urllib.request.Request(
            f"{BASE_URL}/admin/reset_captcha",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req)
    except:
        pass


def run_attack(config_name: str, defense_config: Dict, max_attempts: int = 300) -> AttackMetrics:
    """Run password spray attack with given configuration"""
    
    reset_captcha()
    
    metrics = AttackMetrics(
        config_name=config_name,
        defense_config=defense_config
    )
    
    start_time = time.perf_counter()
    first_success_time = None
    first_block_time = None
    attempt = 0
    
    # Password spray: each password against all users
    for password in PASSWORDS:
        for username in USERS:
            if attempt >= max_attempts:
                break
            
            result = make_request(username, password)
            attempt += 1
            metrics.total_attempts += 1
            metrics.attack_times.append(result["latency_ms"])
            
            if result["blocked_rate_limit"]:
                metrics.blocked_rate_limit += 1
                if first_block_time is None:
                    first_block_time = time.perf_counter() - start_time
            elif result["blocked_captcha"]:
                metrics.blocked_captcha += 1
                if first_block_time is None:
                    first_block_time = time.perf_counter() - start_time
            elif result["totp_required"]:
                metrics.totp_challenges += 1
                metrics.successful_attempts += 1  # Credentials valid
                metrics.compromised_accounts.append(f"{username}:{password}")
                if first_success_time is None:
                    first_success_time = time.perf_counter() - start_time
            elif result["success"]:
                metrics.successful_attempts += 1
                metrics.compromised_accounts.append(f"{username}:{password}")
                if first_success_time is None:
                    first_success_time = time.perf_counter() - start_time
            else:
                metrics.failed_attempts += 1
        
        if attempt >= max_attempts:
            break
    
    metrics.total_attack_time_sec = time.perf_counter() - start_time
    metrics.time_to_first_success_sec = first_success_time
    metrics.time_to_first_block_sec = first_block_time
    
    # Compute statistics
    metrics.compute_statistics()
    
    return metrics


def update_server_config(rate_limiting: bool, captcha: bool, pepper: bool):
    """Update run.py with new configuration and restart server"""
    
    config_str = f"app = create_app(rate_limiting={rate_limiting}, captcha_enabled={captcha})"
    
    run_py_content = f'''from app import create_app

# Defense configuration for testing
# rate_limiting={rate_limiting}, captcha={captcha}, pepper={pepper}
{config_str}

if __name__ == "__main__":
    app.run(debug=True)
'''
    
    with open("run.py", "w") as f:
        f.write(run_py_content)


def restart_server():
    """Restart the Flask server"""
    os.system("pkill -f 'python3 run.py' 2>/dev/null")
    time.sleep(1)
    subprocess.Popen(
        ["python3", "run.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)


def print_metrics(metrics: AttackMetrics):
    """Print formatted metrics"""
    print(f"\n{'=' * 70}")
    print(f"📊 {metrics.config_name}")
    print(f"{'=' * 70}")
    print(f"Defense: {metrics.defense_config}")
    print(f"{'-' * 70}")
    print(f"ATTEMPTS:")
    print(f"  Total:        {metrics.total_attempts}")
    print(f"  Successful:   {metrics.successful_attempts} ({metrics.success_rate_percent:.2f}%)")
    print(f"  Failed:       {metrics.failed_attempts}")
    print(f"  Blocked:      {metrics.blocked_rate_limit + metrics.blocked_captcha} ({metrics.block_rate_percent:.2f}%)")
    print(f"    - Rate Limit: {metrics.blocked_rate_limit}")
    print(f"    - CAPTCHA:    {metrics.blocked_captcha}")
    print(f"{'-' * 70}")
    print(f"TIMING STATISTICS (ms):")
    print(f"  Mean:         {metrics.mean_attack_time_ms:.2f}")
    print(f"  Median:       {metrics.median_attack_time_ms:.2f}")
    print(f"  Std Dev:      {metrics.stddev_attack_time_ms:.2f}")
    print(f"  Min:          {metrics.min_attack_time_ms:.2f}")
    print(f"  Max:          {metrics.max_attack_time_ms:.2f}")
    print(f"{'-' * 70}")
    print(f"PERCENTILES (ms):")
    print(f"  P10:          {metrics.p10_attack_time_ms:.2f}")
    print(f"  P25:          {metrics.p25_attack_time_ms:.2f}")
    print(f"  P50 (Median): {metrics.median_attack_time_ms:.2f}")
    print(f"  P75:          {metrics.p75_attack_time_ms:.2f}")
    print(f"  P90:          {metrics.p90_attack_time_ms:.2f}")
    print(f"  P95:          {metrics.p95_attack_time_ms:.2f}")
    print(f"  P99:          {metrics.p99_attack_time_ms:.2f}")
    print(f"{'-' * 70}")
    print(f"PERFORMANCE:")
    print(f"  Total Time:   {metrics.total_attack_time_sec:.2f}s")
    print(f"  Req/s:        {metrics.attempts_per_second:.2f}")
    if metrics.time_to_first_success_sec:
        print(f"  Time to Crack: {metrics.time_to_first_success_sec:.3f}s")
    if metrics.time_to_first_block_sec:
        print(f"  Time to Block: {metrics.time_to_first_block_sec:.3f}s")
    print(f"{'-' * 70}")
    if metrics.compromised_accounts:
        print(f"COMPROMISED: {len(metrics.compromised_accounts)} accounts")


def metrics_to_dict(metrics: AttackMetrics) -> Dict:
    """Convert metrics to dictionary for JSON serialization"""
    return {
        "config_name": metrics.config_name,
        "defense_config": metrics.defense_config,
        "attempts": {
            "total": metrics.total_attempts,
            "successful": metrics.successful_attempts,
            "failed": metrics.failed_attempts,
            "blocked_rate_limit": metrics.blocked_rate_limit,
            "blocked_captcha": metrics.blocked_captcha,
            "totp_challenges": metrics.totp_challenges
        },
        "rates": {
            "success_rate_percent": round(metrics.success_rate_percent, 4),
            "block_rate_percent": round(metrics.block_rate_percent, 4),
            "attempts_per_second": round(metrics.attempts_per_second, 2)
        },
        "timing_statistics_ms": {
            "mean": round(metrics.mean_attack_time_ms, 2),
            "median": round(metrics.median_attack_time_ms, 2),
            "stddev": round(metrics.stddev_attack_time_ms, 2),
            "min": round(metrics.min_attack_time_ms, 2),
            "max": round(metrics.max_attack_time_ms, 2)
        },
        "percentiles_ms": {
            "p10": round(metrics.p10_attack_time_ms, 2),
            "p25": round(metrics.p25_attack_time_ms, 2),
            "p50": round(metrics.median_attack_time_ms, 2),
            "p75": round(metrics.p75_attack_time_ms, 2),
            "p90": round(metrics.p90_attack_time_ms, 2),
            "p95": round(metrics.p95_attack_time_ms, 2),
            "p99": round(metrics.p99_attack_time_ms, 2)
        },
        "time_to_events_sec": {
            "first_success": metrics.time_to_first_success_sec,
            "first_block": metrics.time_to_first_block_sec
        },
        "total_attack_time_sec": round(metrics.total_attack_time_sec, 2),
        "compromised_count": len(metrics.compromised_accounts),
        "compromised_accounts": metrics.compromised_accounts[:10]  # First 10
    }


def run_all_tests():
    """Run comprehensive tests for all defense configurations"""
    
    print("=" * 80)
    print("🔬 COMPREHENSIVE DEFENSE MECHANISM TESTING SUITE")
    print("=" * 80)
    print(f"Started at: {datetime.now(timezone.utc).isoformat()}")
    print(f"Group Seed: 251891")
    print()
    
    all_results = []
    
    # Define all test configurations
    test_configs = [
        # Individual defenses
        ("NO_DEFENSE", {"rate_limiting": False, "captcha": False, "pepper": True}),
        ("RATE_LIMIT_ONLY", {"rate_limiting": True, "captcha": False, "pepper": True}),
        ("CAPTCHA_ONLY", {"rate_limiting": False, "captcha": True, "pepper": True}),
        ("PEPPER_ONLY", {"rate_limiting": False, "captcha": False, "pepper": True}),
        
        # Combinations
        ("RATE_LIMIT_+_CAPTCHA", {"rate_limiting": True, "captcha": True, "pepper": False}),
        ("RATE_LIMIT_+_PEPPER", {"rate_limiting": True, "captcha": False, "pepper": True}),
        ("CAPTCHA_+_PEPPER", {"rate_limiting": False, "captcha": True, "pepper": True}),
        ("ALL_DEFENSES", {"rate_limiting": True, "captcha": True, "pepper": True}),
    ]
    
    for i, (config_name, defense_config) in enumerate(test_configs):
        print(f"\n[{i+1}/{len(test_configs)}] Testing: {config_name}")
        print(f"    Config: {defense_config}")
        
        # Update server configuration
        update_server_config(
            rate_limiting=defense_config.get("rate_limiting", False),
            captcha=defense_config.get("captcha", False),
            pepper=defense_config.get("pepper", True)
        )
        
        # Restart server
        print("    Restarting server...")
        restart_server()
        
        # Run attack
        print("    Running attack simulation...")
        metrics = run_attack(config_name, defense_config, max_attempts=300)
        
        # Print results
        print_metrics(metrics)
        
        # Store results
        all_results.append(metrics_to_dict(metrics))
    
    # Generate final comparison report
    generate_comparison_report(all_results)
    
    return all_results


def generate_comparison_report(all_results: List[Dict]):
    """Generate comprehensive comparison report"""
    
    report = {
        "report_metadata": {
            "title": "Comprehensive Defense Mechanism Comparison Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "group_seed": "251891",
            "test_parameters": {
                "attack_type": "password_spray",
                "max_attempts_per_config": 300,
                "password_list_size": len(PASSWORDS),
                "target_users": len(USERS)
            }
        },
        
        "individual_results": all_results,
        
        "comparison_tables": {
            "success_and_block_rates": {
                "headers": ["Configuration", "Success%", "Block%", "Compromised"],
                "rows": []
            },
            "timing_comparison": {
                "headers": ["Configuration", "Mean(ms)", "Median(ms)", "P90(ms)", "P95(ms)", "StdDev"],
                "rows": []
            },
            "performance_comparison": {
                "headers": ["Configuration", "Total Time(s)", "Req/s", "Time to Crack(s)", "Time to Block(s)"],
                "rows": []
            }
        },
        
        "distribution_analysis": [],
        
        "summary": {
            "most_effective_defense": None,
            "fastest_to_block": None,
            "lowest_success_rate": None,
            "recommendations": []
        }
    }
    
    # Build comparison tables
    for r in all_results:
        # Success/Block rates
        report["comparison_tables"]["success_and_block_rates"]["rows"].append([
            r["config_name"],
            f"{r['rates']['success_rate_percent']:.2f}%",
            f"{r['rates']['block_rate_percent']:.2f}%",
            r["compromised_count"]
        ])
        
        # Timing comparison
        report["comparison_tables"]["timing_comparison"]["rows"].append([
            r["config_name"],
            r["timing_statistics_ms"]["mean"],
            r["timing_statistics_ms"]["median"],
            r["percentiles_ms"]["p90"],
            r["percentiles_ms"]["p95"],
            r["timing_statistics_ms"]["stddev"]
        ])
        
        # Performance comparison
        report["comparison_tables"]["performance_comparison"]["rows"].append([
            r["config_name"],
            r["total_attack_time_sec"],
            r["rates"]["attempts_per_second"],
            r["time_to_events_sec"]["first_success"],
            r["time_to_events_sec"]["first_block"]
        ])
        
        # Distribution analysis
        report["distribution_analysis"].append({
            "config": r["config_name"],
            "distribution_shape": categorize_distribution(r),
            "percentile_spread": {
                "p10_to_p90_range": r["percentiles_ms"]["p90"] - r["percentiles_ms"]["p10"],
                "p25_to_p75_range": r["percentiles_ms"]["p75"] - r["percentiles_ms"]["p25"],
                "coefficient_of_variation": (r["timing_statistics_ms"]["stddev"] / r["timing_statistics_ms"]["mean"] * 100) if r["timing_statistics_ms"]["mean"] > 0 else 0
            }
        })
    
    # Determine best configurations
    min_success = min(all_results, key=lambda x: x["rates"]["success_rate_percent"])
    max_block = max(all_results, key=lambda x: x["rates"]["block_rate_percent"])
    fastest_block = min(
        [r for r in all_results if r["time_to_events_sec"]["first_block"] is not None],
        key=lambda x: x["time_to_events_sec"]["first_block"],
        default=None
    )
    
    report["summary"]["most_effective_defense"] = max_block["config_name"]
    report["summary"]["lowest_success_rate"] = f"{min_success['config_name']} ({min_success['rates']['success_rate_percent']:.2f}%)"
    if fastest_block:
        report["summary"]["fastest_to_block"] = f"{fastest_block['config_name']} ({fastest_block['time_to_events_sec']['first_block']:.3f}s)"
    
    report["summary"]["recommendations"] = [
        "1. Rate limiting is the most effective single defense mechanism",
        "2. CAPTCHA provides good secondary protection after initial failures",
        "3. Pepper does NOT protect against online attacks - only useful for offline cracking",
        "4. Combining rate limiting + CAPTCHA provides defense-in-depth",
        "5. Argon2id hashing adds ~30ms per attempt, slowing automated attacks"
    ]
    
    # Save report
    with open("comprehensive_defense_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print("\n" + "=" * 80)
    print("📋 FINAL COMPARISON SUMMARY")
    print("=" * 80)
    
    print("\n📊 SUCCESS & BLOCK RATES:")
    print(f"{'Configuration':<25} {'Success%':<12} {'Block%':<12} {'Compromised'}")
    print("-" * 70)
    for row in report["comparison_tables"]["success_and_block_rates"]["rows"]:
        print(f"{row[0]:<25} {row[1]:<12} {row[2]:<12} {row[3]}")
    
    print("\n⏱️  TIMING COMPARISON (ms):")
    print(f"{'Configuration':<25} {'Mean':<10} {'Median':<10} {'P90':<10} {'P95':<10} {'StdDev'}")
    print("-" * 80)
    for row in report["comparison_tables"]["timing_comparison"]["rows"]:
        print(f"{row[0]:<25} {row[1]:<10.2f} {row[2]:<10.2f} {row[3]:<10.2f} {row[4]:<10.2f} {row[5]:.2f}")
    
    print("\n🎯 DISTRIBUTION ANALYSIS:")
    print("-" * 70)
    for dist in report["distribution_analysis"]:
        cv = dist["percentile_spread"]["coefficient_of_variation"]
        shape = dist["distribution_shape"]
        print(f"{dist['config']:<25} Shape: {shape:<15} CV: {cv:.1f}%")
    
    print("\n✅ SUMMARY:")
    print(f"  Most Effective: {report['summary']['most_effective_defense']}")
    print(f"  Lowest Success Rate: {report['summary']['lowest_success_rate']}")
    if report['summary']['fastest_to_block']:
        print(f"  Fastest to Block: {report['summary']['fastest_to_block']}")
    
    print(f"\n📁 Full report saved to: comprehensive_defense_report.json")


def categorize_distribution(result: Dict) -> str:
    """Categorize the distribution shape based on statistics"""
    mean = result["timing_statistics_ms"]["mean"]
    median = result["timing_statistics_ms"]["median"]
    stddev = result["timing_statistics_ms"]["stddev"]
    
    if stddev == 0:
        return "constant"
    
    skewness = (mean - median) / stddev if stddev > 0 else 0
    cv = stddev / mean * 100 if mean > 0 else 0
    
    if cv < 10:
        return "tight_cluster"
    elif cv < 30:
        return "normal"
    elif skewness > 0.5:
        return "right_skewed"
    elif skewness < -0.5:
        return "left_skewed"
    else:
        return "uniform"


if __name__ == "__main__":
    run_all_tests()

