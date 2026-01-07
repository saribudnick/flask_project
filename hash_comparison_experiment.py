#!/usr/bin/env python3
"""
Hash Algorithm Comparison Experiment
=====================================
Compares SHA-256 (fast), bcrypt (slow), and Argon2id (memory-hard)

Group Seed: 251891
Authors: Sari & Yam
"""

import time
import hashlib
import bcrypt
import json
import statistics
from datetime import datetime
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError

# Test configuration
NUM_ITERATIONS = 100  # Number of hash operations per algorithm
TEST_PASSWORD = "TestPassword123!"
BCRYPT_COST = 12
ARGON2_TIME_COST = 1
ARGON2_MEMORY_COST = 65536  # 64 MB

def measure_sha256(password: str, iterations: int) -> dict:
    """Measure SHA-256 hashing performance"""
    timings = []
    
    for _ in range(iterations):
        start = time.perf_counter()
        # SHA-256 hash (what NOT to use for passwords)
        hash_result = hashlib.sha256(password.encode()).hexdigest()
        end = time.perf_counter()
        timings.append((end - start) * 1000)  # Convert to ms
    
    return {
        "algorithm": "SHA-256",
        "iterations": iterations,
        "timings_ms": timings,
        "sample_hash": hash_result[:32] + "..."
    }

def measure_bcrypt(password: str, iterations: int, cost: int) -> dict:
    """Measure bcrypt hashing performance"""
    timings = []
    
    for _ in range(iterations):
        start = time.perf_counter()
        salt = bcrypt.gensalt(rounds=cost)
        hash_result = bcrypt.hashpw(password.encode(), salt)
        end = time.perf_counter()
        timings.append((end - start) * 1000)
    
    return {
        "algorithm": f"bcrypt (cost={cost})",
        "iterations": iterations,
        "timings_ms": timings,
        "sample_hash": hash_result.decode()[:32] + "..."
    }

def measure_argon2id(password: str, iterations: int, time_cost: int, memory_cost: int) -> dict:
    """Measure Argon2id hashing performance"""
    timings = []
    
    ph = PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=1,
        type=Type.ID
    )
    
    for _ in range(iterations):
        start = time.perf_counter()
        hash_result = ph.hash(password)
        end = time.perf_counter()
        timings.append((end - start) * 1000)
    
    return {
        "algorithm": f"Argon2id (t={time_cost}, m={memory_cost//1024}MB)",
        "iterations": iterations,
        "timings_ms": timings,
        "sample_hash": hash_result[:32] + "..."
    }

def calculate_stats(timings: list) -> dict:
    """Calculate statistics from timing data"""
    return {
        "mean_ms": round(statistics.mean(timings), 4),
        "median_ms": round(statistics.median(timings), 4),
        "min_ms": round(min(timings), 4),
        "max_ms": round(max(timings), 4),
        "stddev_ms": round(statistics.stdev(timings), 4) if len(timings) > 1 else 0,
        "hashes_per_second": round(1000 / statistics.mean(timings), 2)
    }

def calculate_crack_times(hashes_per_second: float) -> dict:
    """Calculate estimated crack times for different password complexities"""
    keyspaces = [
        ("4-digit PIN", 10**4),
        ("6-digit PIN", 10**6),
        ("6 lowercase letters", 26**6),
        ("8 alphanumeric", 62**8),
        ("10 mixed + symbols", 95**10),
        ("12 mixed + symbols", 95**12),
    ]
    
    results = []
    for name, size in keyspaces:
        seconds = size / hashes_per_second
        results.append({
            "keyspace": name,
            "keyspace_size": size,
            "seconds": round(seconds, 2),
            "hours": round(seconds / 3600, 2),
            "days": round(seconds / 86400, 2),
            "years": round(seconds / (86400 * 365), 4)
        })
    
    return results

def run_experiment():
    """Run the full hash comparison experiment"""
    print("=" * 70)
    print("HASH ALGORITHM COMPARISON EXPERIMENT")
    print("Group Seed: 251891 | Authors: Sari & Yam")
    print("=" * 70)
    print(f"\nTest Password: {TEST_PASSWORD}")
    print(f"Iterations per algorithm: {NUM_ITERATIONS}")
    print("\n" + "-" * 70)
    
    results = {
        "metadata": {
            "experiment": "Hash Algorithm Comparison",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "group_seed": "251891",
            "authors": "Sari & Yam",
            "test_password_length": len(TEST_PASSWORD),
            "iterations": NUM_ITERATIONS
        },
        "algorithms": []
    }
    
    # Test SHA-256
    print("\n[1/3] Testing SHA-256 (INSECURE for passwords)...")
    sha256_data = measure_sha256(TEST_PASSWORD, NUM_ITERATIONS)
    sha256_stats = calculate_stats(sha256_data["timings_ms"])
    sha256_cracks = calculate_crack_times(sha256_stats["hashes_per_second"])
    
    print(f"      Mean time: {sha256_stats['mean_ms']:.4f} ms")
    print(f"      Hashes/sec: {sha256_stats['hashes_per_second']:,.0f}")
    
    results["algorithms"].append({
        "name": sha256_data["algorithm"],
        "secure_for_passwords": False,
        "stats": sha256_stats,
        "crack_times": sha256_cracks
    })
    
    # Test bcrypt
    print(f"\n[2/3] Testing bcrypt (cost={BCRYPT_COST})...")
    bcrypt_data = measure_bcrypt(TEST_PASSWORD, NUM_ITERATIONS, BCRYPT_COST)
    bcrypt_stats = calculate_stats(bcrypt_data["timings_ms"])
    bcrypt_cracks = calculate_crack_times(bcrypt_stats["hashes_per_second"])
    
    print(f"      Mean time: {bcrypt_stats['mean_ms']:.2f} ms")
    print(f"      Hashes/sec: {bcrypt_stats['hashes_per_second']:.2f}")
    
    results["algorithms"].append({
        "name": bcrypt_data["algorithm"],
        "secure_for_passwords": True,
        "stats": bcrypt_stats,
        "crack_times": bcrypt_cracks
    })
    
    # Test Argon2id
    print(f"\n[3/3] Testing Argon2id (t={ARGON2_TIME_COST}, m={ARGON2_MEMORY_COST//1024}MB)...")
    argon2_data = measure_argon2id(TEST_PASSWORD, NUM_ITERATIONS, ARGON2_TIME_COST, ARGON2_MEMORY_COST)
    argon2_stats = calculate_stats(argon2_data["timings_ms"])
    argon2_cracks = calculate_crack_times(argon2_stats["hashes_per_second"])
    
    print(f"      Mean time: {argon2_stats['mean_ms']:.2f} ms")
    print(f"      Hashes/sec: {argon2_stats['hashes_per_second']:.2f}")
    
    results["algorithms"].append({
        "name": argon2_data["algorithm"],
        "secure_for_passwords": True,
        "memory_hard": True,
        "stats": argon2_stats,
        "crack_times": argon2_cracks
    })
    
    # Calculate comparisons
    sha256_rate = sha256_stats["hashes_per_second"]
    bcrypt_rate = bcrypt_stats["hashes_per_second"]
    argon2_rate = argon2_stats["hashes_per_second"]
    
    results["comparisons"] = {
        "sha256_vs_bcrypt_slowdown": round(sha256_rate / bcrypt_rate, 0),
        "sha256_vs_argon2_slowdown": round(sha256_rate / argon2_rate, 0),
        "bcrypt_vs_argon2_ratio": round(bcrypt_rate / argon2_rate, 2)
    }
    
    # Print comparison table
    print("\n" + "=" * 70)
    print("RESULTS COMPARISON")
    print("=" * 70)
    
    print("\n📊 PERFORMANCE COMPARISON:")
    print("-" * 70)
    print(f"{'Algorithm':<35} {'Time (ms)':<15} {'Hashes/sec':<15}")
    print("-" * 70)
    print(f"{'SHA-256 (INSECURE)':<35} {sha256_stats['mean_ms']:<15.4f} {sha256_stats['hashes_per_second']:>14,.0f}")
    print(f"{'bcrypt (cost=12)':<35} {bcrypt_stats['mean_ms']:<15.2f} {bcrypt_stats['hashes_per_second']:>14.2f}")
    print(f"{'Argon2id (64MB)':<35} {argon2_stats['mean_ms']:<15.2f} {argon2_stats['hashes_per_second']:>14.2f}")
    print("-" * 70)
    
    print("\n🔐 SLOWDOWN FACTORS:")
    print(f"   SHA-256 → bcrypt:  {results['comparisons']['sha256_vs_bcrypt_slowdown']:,.0f}x slower")
    print(f"   SHA-256 → Argon2id: {results['comparisons']['sha256_vs_argon2_slowdown']:,.0f}x slower")
    print(f"   bcrypt → Argon2id: {results['comparisons']['bcrypt_vs_argon2_ratio']:.2f}x ratio")
    
    # Crack time comparison
    print("\n" + "=" * 70)
    print("⏱️ ESTIMATED CRACK TIMES (Brute Force)")
    print("=" * 70)
    
    print("\n4-digit PIN (10,000 possibilities):")
    print(f"   SHA-256:   {sha256_cracks[0]['seconds']:.4f} seconds")
    print(f"   bcrypt:    {bcrypt_cracks[0]['seconds']:.2f} seconds ({bcrypt_cracks[0]['hours']:.2f} hours)")
    print(f"   Argon2id:  {argon2_cracks[0]['seconds']:.2f} seconds ({argon2_cracks[0]['hours']:.2f} hours)")
    
    print("\n6-digit PIN (1,000,000 possibilities):")
    print(f"   SHA-256:   {sha256_cracks[1]['seconds']:.2f} seconds")
    print(f"   bcrypt:    {bcrypt_cracks[1]['hours']:.2f} hours ({bcrypt_cracks[1]['days']:.2f} days)")
    print(f"   Argon2id:  {argon2_cracks[1]['hours']:.2f} hours ({argon2_cracks[1]['days']:.2f} days)")
    
    print("\n8 alphanumeric chars (218 trillion possibilities):")
    print(f"   SHA-256:   {sha256_cracks[3]['days']:.0f} days ({sha256_cracks[3]['years']:.2f} years)")
    print(f"   bcrypt:    {bcrypt_cracks[3]['years']:,.0f} years")
    print(f"   Argon2id:  {argon2_cracks[3]['years']:,.0f} years")
    
    print("\n12 mixed + symbols (540 sextillion possibilities):")
    print(f"   SHA-256:   {sha256_cracks[5]['years']:,.0f} years")
    print(f"   bcrypt:    {bcrypt_cracks[5]['years']:.2e} years")
    print(f"   Argon2id:  {argon2_cracks[5]['years']:.2e} years")
    
    # Key findings
    print("\n" + "=" * 70)
    print("🎯 KEY FINDINGS")
    print("=" * 70)
    
    findings = [
        f"SHA-256 is {results['comparisons']['sha256_vs_bcrypt_slowdown']:,.0f}x FASTER than bcrypt - NEVER use for passwords!",
        f"SHA-256 is {results['comparisons']['sha256_vs_argon2_slowdown']:,.0f}x FASTER than Argon2id",
        f"bcrypt and Argon2id are comparable in speed (ratio: {results['comparisons']['bcrypt_vs_argon2_ratio']:.2f}x)",
        "Argon2id requires 64MB RAM per hash - resists GPU attacks",
        "bcrypt is CPU-bound only - GPUs can parallelize more easily",
        "For maximum security: Use Argon2id with high memory cost"
    ]
    
    for i, finding in enumerate(findings, 1):
        print(f"   {i}. {finding}")
    
    results["findings"] = findings
    
    # Security recommendations
    print("\n" + "=" * 70)
    print("✅ SECURITY RECOMMENDATIONS")
    print("=" * 70)
    print("""
   ❌ NEVER use SHA-256/SHA-512/MD5 for password hashing
      - Too fast! Attackers can try billions per second on GPUs
      
   ✅ USE bcrypt (cost >= 12) for compatibility
      - Widely supported, battle-tested since 1999
      - Good default choice for most applications
      
   ✅ PREFER Argon2id for maximum security
      - Memory-hard: Requires 64MB+ RAM per hash
      - Defeats GPU/ASIC parallelization attacks
      - Winner of Password Hashing Competition (2015)
      - Recommended by OWASP for new applications
""")
    
    # Save results
    report_file = "hash_comparison_report.json"
    with open(report_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📄 Full report saved to: {report_file}")
    print("\n" + "=" * 70)
    print("Experiment completed! | Group Seed: 251891 | Sari & Yam")
    print("=" * 70)
    
    return results

if __name__ == "__main__":
    run_experiment()

