#!/usr/bin/env python3
"""
Hash Algorithm Attack Comparison Experiment
============================================
Simulates brute-force attacks against SHA-256, bcrypt, and Argon2id
Measures: Success rate, Latency, Attempts/sec, Time to crack

Group Seed: 251891
Authors: Sari & Yam
"""

import time
import hashlib
import bcrypt
import json
import statistics
import random
import string
from datetime import datetime, timezone
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError

def tabulate(data, headers, tablefmt="grid"):
    """Simple tabulate replacement"""
    # Calculate column widths
    all_rows = [headers] + data
    widths = [max(len(str(row[i])) for row in all_rows) for i in range(len(headers))]
    
    # Build table
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    lines = [sep]
    
    # Header
    header_line = "|" + "|".join(f" {str(headers[i]).ljust(widths[i])} " for i in range(len(headers))) + "|"
    lines.append(header_line)
    lines.append(sep)
    
    # Data rows
    for row in data:
        row_line = "|" + "|".join(f" {str(row[i]).ljust(widths[i])} " for i in range(len(row))) + "|"
        lines.append(row_line)
    
    lines.append(sep)
    return "\n".join(lines)

# Configuration
NUM_ATTACK_ATTEMPTS = 500  # Total password guesses per algorithm
BCRYPT_COST = 12
ARGON2_TIME_COST = 1
ARGON2_MEMORY_COST = 65536  # 64 MB

# Test passwords - weak ones that should be cracked
WEAK_PASSWORDS = ["123456", "password", "admin", "qwerty", "111111", "abc123", "letmein", "welcome"]
# The actual password we'll use (position in attack list determines success)
TARGET_PASSWORD = "123456"

# Password list for brute-force (common passwords + random)
def generate_attack_wordlist(target_password: str, size: int, target_position: int = None) -> list:
    """Generate attack wordlist with target at specific position"""
    common_passwords = [
        "password", "123456", "12345678", "qwerty", "abc123", "111111", "admin",
        "letmein", "welcome", "monkey", "dragon", "master", "login", "princess",
        "solo", "passw0rd", "starwars", "654321", "batman", "trustno1", "hello",
        "charlie", "donald", "password1", "qwerty123", "iloveyou", "sunshine",
        "1234567", "123123", "football", "shadow", "aa123456", "password123"
    ]
    
    wordlist = []
    # Add common passwords
    for pwd in common_passwords:
        if pwd != target_password and len(wordlist) < size:
            wordlist.append(pwd)
    
    # Fill with random passwords if needed
    while len(wordlist) < size - 1:
        length = random.randint(4, 10)
        pwd = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
        if pwd != target_password:
            wordlist.append(pwd)
    
    # Insert target at specific position (or random if not specified)
    if target_position is None:
        target_position = random.randint(size // 4, size // 2)
    
    wordlist.insert(min(target_position, len(wordlist)), target_password)
    
    return wordlist[:size], target_position


class SHA256Hasher:
    """SHA-256 hasher (INSECURE - for demonstration only)"""
    
    @staticmethod
    def hash(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def verify(password: str, hash_value: str) -> bool:
        return hashlib.sha256(password.encode()).hexdigest() == hash_value


class BcryptHasher:
    """bcrypt hasher"""
    
    def __init__(self, cost: int = 12):
        self.cost = cost
    
    def hash(self, password: str) -> str:
        salt = bcrypt.gensalt(rounds=self.cost)
        return bcrypt.hashpw(password.encode(), salt).decode()
    
    def verify(self, password: str, hash_value: str) -> bool:
        return bcrypt.checkpw(password.encode(), hash_value.encode())


class Argon2Hasher:
    """Argon2id hasher"""
    
    def __init__(self, time_cost: int = 1, memory_cost: int = 65536):
        self.ph = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=1,
            type=Type.ID
        )
    
    def hash(self, password: str) -> str:
        return self.ph.hash(password)
    
    def verify(self, password: str, hash_value: str) -> bool:
        try:
            self.ph.verify(hash_value, password)
            return True
        except VerifyMismatchError:
            return False


def simulate_attack(hasher, hash_value: str, wordlist: list, algorithm_name: str) -> dict:
    """Simulate brute-force attack and collect metrics"""
    
    print(f"\n🔓 Attacking {algorithm_name}...")
    
    latencies = []
    successful = False
    success_attempt = None
    cracked_password = None
    start_time = time.perf_counter()
    
    for i, password in enumerate(wordlist):
        attempt_start = time.perf_counter()
        
        try:
            if hasher.verify(password, hash_value):
                successful = True
                success_attempt = i + 1
                cracked_password = password
                latencies.append((time.perf_counter() - attempt_start) * 1000)
                break
        except Exception:
            pass
        
        latencies.append((time.perf_counter() - attempt_start) * 1000)
    
    total_time = time.perf_counter() - start_time
    
    result = {
        "algorithm": algorithm_name,
        "total_attempts": len(latencies),
        "successful": successful,
        "success_attempt": success_attempt,
        "cracked_password": cracked_password,
        "success_rate_percent": round((1 / success_attempt * 100) if successful else 0, 4),
        "total_time_seconds": round(total_time, 4),
        "attempts_per_second": round(len(latencies) / total_time, 2),
        "time_to_crack_seconds": round(total_time, 4) if successful else None,
        "latency_stats": {
            "mean_ms": round(statistics.mean(latencies), 4),
            "median_ms": round(statistics.median(latencies), 4),
            "min_ms": round(min(latencies), 4),
            "max_ms": round(max(latencies), 4),
            "stddev_ms": round(statistics.stdev(latencies), 4) if len(latencies) > 1 else 0,
            "p95_ms": round(sorted(latencies)[int(len(latencies) * 0.95)], 4) if latencies else 0,
            "p99_ms": round(sorted(latencies)[int(len(latencies) * 0.99)], 4) if latencies else 0
        }
    }
    
    status = "✅ CRACKED" if successful else "❌ NOT CRACKED"
    print(f"   {status} after {len(latencies)} attempts in {total_time:.2f}s")
    
    return result


def run_comparison_experiment():
    """Run full attack comparison experiment"""
    
    print("=" * 80)
    print("HASH ALGORITHM ATTACK COMPARISON EXPERIMENT")
    print("Group Seed: 251891 | Authors: Sari & Yam")
    print("=" * 80)
    
    # Generate wordlist with target password
    wordlist, target_pos = generate_attack_wordlist(TARGET_PASSWORD, NUM_ATTACK_ATTEMPTS, target_position=50)
    
    print(f"\n📋 Configuration:")
    print(f"   Target password: '{TARGET_PASSWORD}'")
    print(f"   Wordlist size: {len(wordlist)}")
    print(f"   Target position in wordlist: {target_pos}")
    
    # Initialize hashers
    sha256_hasher = SHA256Hasher()
    bcrypt_hasher = BcryptHasher(cost=BCRYPT_COST)
    argon2_hasher = Argon2Hasher(time_cost=ARGON2_TIME_COST, memory_cost=ARGON2_MEMORY_COST)
    
    # Create hashes
    print("\n🔐 Creating password hashes...")
    
    sha256_hash = sha256_hasher.hash(TARGET_PASSWORD)
    print(f"   SHA-256: {sha256_hash[:32]}...")
    
    bcrypt_hash = bcrypt_hasher.hash(TARGET_PASSWORD)
    print(f"   bcrypt:  {bcrypt_hash[:32]}...")
    
    argon2_hash = argon2_hasher.hash(TARGET_PASSWORD)
    print(f"   Argon2:  {argon2_hash[:32]}...")
    
    # Run attacks
    print("\n" + "=" * 80)
    print("ATTACK SIMULATION")
    print("=" * 80)
    
    results = []
    
    # Attack SHA-256
    sha256_result = simulate_attack(sha256_hasher, sha256_hash, wordlist.copy(), "SHA-256 (INSECURE)")
    results.append(sha256_result)
    
    # Attack bcrypt
    bcrypt_result = simulate_attack(bcrypt_hasher, bcrypt_hash, wordlist.copy(), f"bcrypt (cost={BCRYPT_COST})")
    results.append(bcrypt_result)
    
    # Attack Argon2id
    argon2_result = simulate_attack(argon2_hasher, argon2_hash, wordlist.copy(), f"Argon2id (64MB)")
    results.append(argon2_result)
    
    # Calculate comparisons
    sha256_rate = sha256_result["attempts_per_second"]
    bcrypt_rate = bcrypt_result["attempts_per_second"]
    argon2_rate = argon2_result["attempts_per_second"]
    
    comparisons = {
        "sha256_vs_bcrypt_speed_ratio": round(sha256_rate / bcrypt_rate, 0) if bcrypt_rate > 0 else float('inf'),
        "sha256_vs_argon2_speed_ratio": round(sha256_rate / argon2_rate, 0) if argon2_rate > 0 else float('inf'),
        "bcrypt_vs_argon2_speed_ratio": round(bcrypt_rate / argon2_rate, 2) if argon2_rate > 0 else float('inf'),
        "sha256_time_to_crack": sha256_result["time_to_crack_seconds"],
        "bcrypt_time_to_crack": bcrypt_result["time_to_crack_seconds"],
        "argon2_time_to_crack": argon2_result["time_to_crack_seconds"]
    }
    
    # Print results table
    print("\n" + "=" * 80)
    print("📊 RESULTS COMPARISON")
    print("=" * 80)
    
    # Main metrics table
    headers = ["Metric", "SHA-256", "bcrypt", "Argon2id"]
    table_data = [
        ["Total Attempts", sha256_result["total_attempts"], bcrypt_result["total_attempts"], argon2_result["total_attempts"]],
        ["Cracked?", "✅ YES" if sha256_result["successful"] else "❌ NO", 
                     "✅ YES" if bcrypt_result["successful"] else "❌ NO",
                     "✅ YES" if argon2_result["successful"] else "❌ NO"],
        ["Attempts to Crack", sha256_result["success_attempt"] or "N/A", 
                              bcrypt_result["success_attempt"] or "N/A",
                              argon2_result["success_attempt"] or "N/A"],
        ["Time to Crack (s)", f"{sha256_result['time_to_crack_seconds']:.4f}" if sha256_result["successful"] else "N/A",
                              f"{bcrypt_result['time_to_crack_seconds']:.2f}" if bcrypt_result["successful"] else "N/A",
                              f"{argon2_result['time_to_crack_seconds']:.2f}" if argon2_result["successful"] else "N/A"],
        ["Attempts/Second", f"{sha256_rate:,.0f}", f"{bcrypt_rate:.2f}", f"{argon2_rate:.2f}"],
        ["Mean Latency (ms)", f"{sha256_result['latency_stats']['mean_ms']:.4f}", 
                              f"{bcrypt_result['latency_stats']['mean_ms']:.2f}",
                              f"{argon2_result['latency_stats']['mean_ms']:.2f}"],
        ["P95 Latency (ms)", f"{sha256_result['latency_stats']['p95_ms']:.4f}",
                             f"{bcrypt_result['latency_stats']['p95_ms']:.2f}",
                             f"{argon2_result['latency_stats']['p95_ms']:.2f}"],
        ["P99 Latency (ms)", f"{sha256_result['latency_stats']['p99_ms']:.4f}",
                             f"{bcrypt_result['latency_stats']['p99_ms']:.2f}",
                             f"{argon2_result['latency_stats']['p99_ms']:.2f}"],
    ]
    
    print("\n" + tabulate(table_data, headers=headers, tablefmt="grid"))
    
    # Speed comparison
    print("\n🚀 SPEED COMPARISON:")
    print("-" * 60)
    print(f"   SHA-256 is {comparisons['sha256_vs_bcrypt_speed_ratio']:,.0f}x FASTER than bcrypt")
    print(f"   SHA-256 is {comparisons['sha256_vs_argon2_speed_ratio']:,.0f}x FASTER than Argon2id")
    print(f"   bcrypt is {comparisons['bcrypt_vs_argon2_speed_ratio']:.2f}x as fast as Argon2id")
    
    # Time comparison
    print("\n⏱️ TIME TO CRACK COMPARISON:")
    print("-" * 60)
    if sha256_result["successful"] and bcrypt_result["successful"]:
        bcrypt_slowdown = bcrypt_result["time_to_crack_seconds"] / sha256_result["time_to_crack_seconds"]
        print(f"   bcrypt took {bcrypt_slowdown:,.0f}x LONGER than SHA-256")
    if sha256_result["successful"] and argon2_result["successful"]:
        argon2_slowdown = argon2_result["time_to_crack_seconds"] / sha256_result["time_to_crack_seconds"]
        print(f"   Argon2id took {argon2_slowdown:,.0f}x LONGER than SHA-256")
    
    # Latency comparison table
    print("\n📈 LATENCY STATISTICS (ms):")
    print("-" * 60)
    latency_headers = ["Statistic", "SHA-256", "bcrypt", "Argon2id"]
    latency_data = [
        ["Mean", f"{sha256_result['latency_stats']['mean_ms']:.4f}", 
                 f"{bcrypt_result['latency_stats']['mean_ms']:.2f}",
                 f"{argon2_result['latency_stats']['mean_ms']:.2f}"],
        ["Median", f"{sha256_result['latency_stats']['median_ms']:.4f}",
                   f"{bcrypt_result['latency_stats']['median_ms']:.2f}",
                   f"{argon2_result['latency_stats']['median_ms']:.2f}"],
        ["Min", f"{sha256_result['latency_stats']['min_ms']:.4f}",
                f"{bcrypt_result['latency_stats']['min_ms']:.2f}",
                f"{argon2_result['latency_stats']['min_ms']:.2f}"],
        ["Max", f"{sha256_result['latency_stats']['max_ms']:.4f}",
                f"{bcrypt_result['latency_stats']['max_ms']:.2f}",
                f"{argon2_result['latency_stats']['max_ms']:.2f}"],
        ["Std Dev", f"{sha256_result['latency_stats']['stddev_ms']:.4f}",
                    f"{bcrypt_result['latency_stats']['stddev_ms']:.2f}",
                    f"{argon2_result['latency_stats']['stddev_ms']:.2f}"],
        ["P95", f"{sha256_result['latency_stats']['p95_ms']:.4f}",
                f"{bcrypt_result['latency_stats']['p95_ms']:.2f}",
                f"{argon2_result['latency_stats']['p95_ms']:.2f}"],
        ["P99", f"{sha256_result['latency_stats']['p99_ms']:.4f}",
                f"{bcrypt_result['latency_stats']['p99_ms']:.2f}",
                f"{argon2_result['latency_stats']['p99_ms']:.2f}"],
    ]
    print(tabulate(latency_data, headers=latency_headers, tablefmt="grid"))
    
    # Extrapolation
    print("\n" + "=" * 80)
    print("📐 EXTRAPOLATION - Time to Crack Larger Keyspaces")
    print("=" * 80)
    
    keyspaces = [
        ("4-digit PIN", 10**4),
        ("6-digit PIN", 10**6),
        ("8 alphanumeric", 62**8),
        ("10 mixed chars", 95**10),
    ]
    
    extrap_headers = ["Keyspace", "Size", "SHA-256", "bcrypt", "Argon2id"]
    extrap_data = []
    
    for name, size in keyspaces:
        sha_time = size / sha256_rate
        bc_time = size / bcrypt_rate
        ar_time = size / argon2_rate
        
        def format_time(seconds):
            if seconds < 60:
                return f"{seconds:.2f} sec"
            elif seconds < 3600:
                return f"{seconds/60:.1f} min"
            elif seconds < 86400:
                return f"{seconds/3600:.1f} hours"
            elif seconds < 86400 * 365:
                return f"{seconds/86400:.1f} days"
            else:
                return f"{seconds/(86400*365):,.0f} years"
        
        extrap_data.append([
            name,
            f"{size:,}",
            format_time(sha_time),
            format_time(bc_time),
            format_time(ar_time)
        ])
    
    print("\n" + tabulate(extrap_data, headers=extrap_headers, tablefmt="grid"))
    
    # Security conclusions
    print("\n" + "=" * 80)
    print("🎯 SECURITY CONCLUSIONS")
    print("=" * 80)
    
    conclusions = [
        f"SHA-256: CRACKED in {sha256_result['time_to_crack_seconds']:.4f}s - {sha256_rate:,.0f} attempts/sec",
        f"bcrypt:  CRACKED in {bcrypt_result['time_to_crack_seconds']:.2f}s - {bcrypt_rate:.2f} attempts/sec",
        f"Argon2:  CRACKED in {argon2_result['time_to_crack_seconds']:.2f}s - {argon2_rate:.2f} attempts/sec",
        "",
        f"⚠️  SHA-256 is {comparisons['sha256_vs_bcrypt_speed_ratio']:,.0f}x faster to crack than bcrypt",
        f"⚠️  SHA-256 is {comparisons['sha256_vs_argon2_speed_ratio']:,.0f}x faster to crack than Argon2id",
        "",
        "✅ bcrypt provides excellent protection with ~200ms per attempt",
        "✅ Argon2id provides strong protection with 64MB memory requirement",
        "❌ SHA-256 provides NO protection - attackers can try millions/sec"
    ]
    
    for c in conclusions:
        print(f"   {c}")
    
    # Save full report
    report = {
        "metadata": {
            "experiment": "Hash Algorithm Attack Comparison",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "group_seed": "251891",
            "authors": "Sari & Yam",
            "target_password": TARGET_PASSWORD,
            "wordlist_size": len(wordlist),
            "target_position": target_pos
        },
        "configuration": {
            "bcrypt_cost": BCRYPT_COST,
            "argon2_time_cost": ARGON2_TIME_COST,
            "argon2_memory_cost_kb": ARGON2_MEMORY_COST
        },
        "results": {
            "sha256": sha256_result,
            "bcrypt": bcrypt_result,
            "argon2": argon2_result
        },
        "comparisons": comparisons,
        "conclusions": conclusions
    }
    
    report_file = "hash_attack_comparison_report.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📄 Full report saved to: {report_file}")
    print("\n" + "=" * 80)
    print("Experiment completed! | Group Seed: 251891 | Sari & Yam")
    print("=" * 80)
    
    return report


if __name__ == "__main__":
    run_comparison_experiment()

