#!/usr/bin/env python3
"""
TOTP Automation Module with Clock Drift Simulation

Features:
- Generate valid TOTP tokens from secret_totp in users.json
- Simulate clock drift (±t seconds)
- Time synchronization mechanism
- Report deviation, correction, and final error
"""

import time
import pyotp
import json
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:5000"


@dataclass
class ClockDriftResult:
    """Results from clock drift simulation"""
    injected_drift_seconds: float
    correction_applied_seconds: float
    final_error_seconds: float
    attempts_before_correction: int
    totp_valid: bool
    timestamp: str


@dataclass
class TOTPValidationResult:
    """Results from TOTP validation attempt"""
    username: str
    password_valid: bool
    totp_valid: bool
    clock_drift: Optional[ClockDriftResult]
    latency_ms: float
    success: bool
    error: Optional[str]


class TOTPAutomation:
    """
    TOTP automation handler with clock drift simulation.
    
    Usage:
        handler = TOTPAutomation()
        handler.load_users("users.json")
        
        # Normal TOTP generation
        code = handler.generate_totp("totp_user01")
        
        # With clock drift simulation
        result = handler.validate_with_drift("totp_user01", "password", drift_seconds=30)
    """
    
    def __init__(self):
        self.users: Dict[str, dict] = {}
        self.drift_offset: float = 0.0  # Simulated clock drift
        self.correction_history: List[ClockDriftResult] = []
    
    def load_users(self, users_file: str = "users.json"):
        """Load users with TOTP secrets from users.json"""
        path = Path(users_file)
        if not path.exists():
            raise FileNotFoundError(f"users.json not found at {path}")
        
        with open(path) as f:
            data = json.load(f)
        
        for user in data.get("users", []):
            if user.get("secret_totp"):
                self.users[user["username"]] = {
                    "password": user["password"],
                    "secret_totp": user["secret_totp"],
                    "category": user.get("category", "unknown")
                }
        
        print(f"✅ Loaded {len(self.users)} TOTP-enabled users")
        return list(self.users.keys())
    
    def generate_totp(self, username: str, drift_seconds: float = 0) -> Optional[str]:
        """
        Generate TOTP code for a user.
        
        Args:
            username: User to generate code for
            drift_seconds: Clock drift to simulate (positive = future, negative = past)
        
        Returns:
            6-digit TOTP code or None if user not found
        """
        if username not in self.users:
            return None
        
        secret = self.users[username]["secret_totp"]
        totp = pyotp.TOTP(secret)
        
        # Apply drift to current time
        current_time = time.time() + drift_seconds + self.drift_offset
        
        return totp.at(current_time)
    
    def set_drift(self, seconds: float):
        """
        Set simulated clock drift.
        
        Args:
            seconds: Drift amount (positive = future, negative = past)
        """
        self.drift_offset = seconds
        print(f"⏰ Clock drift set to {seconds:+.1f} seconds")
    
    def get_effective_time(self) -> float:
        """Get current time with drift applied"""
        return time.time() + self.drift_offset
    
    def sync_time(self, reference_time: Optional[float] = None) -> float:
        """
        Synchronize clock by resetting drift.
        
        Args:
            reference_time: Server reference time (if available)
        
        Returns:
            Correction applied in seconds
        """
        old_drift = self.drift_offset
        self.drift_offset = 0.0
        print(f"🔄 Clock synchronized. Correction: {-old_drift:+.1f} seconds")
        return -old_drift
    
    def validate_with_drift(
        self,
        username: str,
        password: str,
        drift_seconds: float = 0,
        max_correction_attempts: int = 3
    ) -> TOTPValidationResult:
        """
        Validate TOTP with controlled clock drift simulation.
        
        Implements:
        1. Inject drift of ±t seconds
        2. Attempt validation with drifted clock
        3. If failed, run correction mechanism
        4. Report injected deviation, correction, and final error
        
        Args:
            username: Username to authenticate
            password: User's password
            drift_seconds: Clock drift to inject
            max_correction_attempts: Max attempts before giving up
        
        Returns:
            TOTPValidationResult with full drift report
        """
        start_time = time.perf_counter()
        
        if username not in self.users:
            return TOTPValidationResult(
                username=username,
                password_valid=False,
                totp_valid=False,
                clock_drift=None,
                latency_ms=0,
                success=False,
                error="User not in users.json"
            )
        
        user_data = self.users[username]
        
        # Inject drift
        original_drift = self.drift_offset
        self.drift_offset = drift_seconds
        
        attempts = 0
        correction_applied = 0.0
        totp_valid = False
        
        # Try with drifted clock
        while attempts < max_correction_attempts and not totp_valid:
            attempts += 1
            
            # Generate TOTP with current (drifted) time
            totp_code = self.generate_totp(username)
            
            # Try to validate
            result = self._make_totp_request(
                username, 
                user_data["password"], 
                totp_code
            )
            
            if result.get("success"):
                totp_valid = True
                break
            elif result.get("error") == "invalid TOTP code":
                # TOTP failed - try correction
                # Try adjacent time windows (±30 seconds)
                for window_offset in [30, -30, 60, -60]:
                    adj_code = self.generate_totp(username, window_offset)
                    adj_result = self._make_totp_request(
                        username,
                        user_data["password"],
                        adj_code
                    )
                    if adj_result.get("success"):
                        # Found correct window - apply correction
                        correction_applied = -window_offset
                        self.drift_offset += correction_applied
                        totp_valid = True
                        print(f"🔧 Correction found: {correction_applied:+.0f}s (window offset: {window_offset}s)")
                        break
            else:
                # Password invalid or other error
                break
        
        # Calculate final error
        final_error = self.drift_offset
        
        # Record drift result
        drift_result = ClockDriftResult(
            injected_drift_seconds=drift_seconds,
            correction_applied_seconds=correction_applied,
            final_error_seconds=final_error,
            attempts_before_correction=attempts,
            totp_valid=totp_valid,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        self.correction_history.append(drift_result)
        
        # Restore original drift (for isolation between tests)
        self.drift_offset = original_drift
        
        latency = (time.perf_counter() - start_time) * 1000
        
        return TOTPValidationResult(
            username=username,
            password_valid=True,  # Assume password was valid if we got to TOTP
            totp_valid=totp_valid,
            clock_drift=drift_result,
            latency_ms=latency,
            success=totp_valid,
            error=None if totp_valid else "TOTP validation failed after corrections"
        )
    
    def _make_totp_request(self, username: str, password: str, totp_code: str) -> dict:
        """Make TOTP login request to server"""
        try:
            data = {
                "username": username,
                "password": password,
                "totp_code": totp_code
            }
            
            req = urllib.request.Request(
                f"{BASE_URL}/auth/login_totp",
                data=json.dumps(data).encode(),
                headers={"Content-Type": "application/json"}
            )
            
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return {"success": True, "response": json.loads(resp.read().decode())}
            except urllib.error.HTTPError as e:
                response = json.loads(e.read().decode())
                return {"success": False, "error": response.get("error", "unknown"), "code": e.code}
        except Exception as ex:
            return {"success": False, "error": str(ex)}
    
    def run_drift_simulation(
        self,
        drift_values: List[float] = None
    ) -> Dict:
        """
        Run complete drift simulation across all TOTP users.
        
        Args:
            drift_values: List of drift values to test (seconds)
        
        Returns:
            Simulation report
        """
        if drift_values is None:
            drift_values = [0, 15, 30, -15, -30, 45, -45, 60, -60, 90, -90]
        
        results = {
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "group_seed": "251891",
                "drift_values_tested": drift_values,
                "users_tested": list(self.users.keys())
            },
            "results_by_user": {},
            "summary": {
                "total_tests": 0,
                "successful": 0,
                "failed": 0,
                "correction_needed": 0,
                "avg_correction_seconds": 0.0
            }
        }
        
        corrections = []
        
        for username in self.users:
            results["results_by_user"][username] = []
            
            for drift in drift_values:
                result = self.validate_with_drift(username, "", drift)
                
                test_result = {
                    "drift_seconds": drift,
                    "totp_valid": result.totp_valid,
                    "correction_applied": result.clock_drift.correction_applied_seconds if result.clock_drift else 0,
                    "attempts": result.clock_drift.attempts_before_correction if result.clock_drift else 0,
                    "final_error": result.clock_drift.final_error_seconds if result.clock_drift else drift
                }
                
                results["results_by_user"][username].append(test_result)
                results["summary"]["total_tests"] += 1
                
                if result.totp_valid:
                    results["summary"]["successful"] += 1
                else:
                    results["summary"]["failed"] += 1
                
                if result.clock_drift and result.clock_drift.correction_applied_seconds != 0:
                    results["summary"]["correction_needed"] += 1
                    corrections.append(abs(result.clock_drift.correction_applied_seconds))
        
        if corrections:
            results["summary"]["avg_correction_seconds"] = sum(corrections) / len(corrections)
        
        return results


def demo():
    """Demonstrate TOTP automation with clock drift"""
    print("=" * 70)
    print("🔐 TOTP AUTOMATION WITH CLOCK DRIFT SIMULATION")
    print("=" * 70)
    
    handler = TOTPAutomation()
    
    # Load users
    try:
        users = handler.load_users("users.json")
        print(f"   Users: {users}")
    except FileNotFoundError as e:
        print(f"❌ {e}")
        return
    
    print("\n" + "-" * 70)
    print("📋 TOTP Code Generation (No Drift)")
    print("-" * 70)
    
    for username in handler.users:
        code = handler.generate_totp(username)
        print(f"   {username}: {code}")
    
    print("\n" + "-" * 70)
    print("⏰ CLOCK DRIFT SIMULATION")
    print("-" * 70)
    
    drift_tests = [0, 15, 30, -15, -30, 45, -45]
    
    for username in list(handler.users.keys())[:1]:  # Test with first user
        print(f"\n   Testing: {username}")
        print(f"   {'Drift':>10} | {'Code':>8} | {'Window'}")
        print("   " + "-" * 40)
        
        for drift in drift_tests:
            code = handler.generate_totp(username, drift)
            # Determine which 30-second window this falls in
            effective_time = time.time() + drift
            window = int(effective_time // 30)
            current_window = int(time.time() // 30)
            window_diff = window - current_window
            
            print(f"   {drift:+10}s | {code:>8} | {window_diff:+d} windows")
    
    print("\n" + "-" * 70)
    print("📊 DRIFT TOLERANCE ANALYSIS")
    print("-" * 70)
    
    # pyotp typically allows ±1 window (30 seconds) of tolerance
    print("""
   TOTP Standard (RFC 6238):
   - Time step: 30 seconds
   - Typical server tolerance: ±1 window (±30 seconds)
   
   Drift Analysis:
   - 0-30s drift: Usually valid (same or adjacent window)
   - 30-60s drift: May fail (2 windows difference)
   - 60+s drift: Likely fails (requires correction)
   
   Correction Mechanism:
   - Try adjacent windows (±30s, ±60s)
   - Apply correction to local clock
   - Report deviation and correction applied
    """)
    
    print("=" * 70)
    print("✅ TOTP Automation Module Ready")
    print("=" * 70)


if __name__ == "__main__":
    demo()

