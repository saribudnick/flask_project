from .extensions import db
import bcrypt
import pyotp
import hmac
import hashlib
import os
from datetime import datetime, timedelta
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError

# Argon2id parameters per spec: time=1, memory=64MB, parallelism=1
ARGON2_TIME_COST = 1
ARGON2_MEMORY_COST = 65536  # 64 MB in KB
ARGON2_PARALLELISM = 1

# bcrypt cost per spec
BCRYPT_COST = 12

# Default hash algorithm for new users
DEFAULT_HASH_ALGORITHM = "argon2id"

# Pepper: Secret key from environment variable
# Set via: export APP_PEPPER_KEY="your-secret-pepper-key"
PEPPER = os.environ.get("APP_PEPPER_KEY", "S3cr3tP3pp3rK3y_251891_Pr0t3ct10n!")
PEPPER_ENABLED = bool(PEPPER)

# Account Lockout Configuration
MAX_FAILED_LOGIN_ATTEMPTS = int(os.environ.get("MAX_FAILED_LOGIN_ATTEMPTS", 5))
LOCKOUT_DURATION_MINUTES = int(os.environ.get("LOCKOUT_DURATION_MINUTES", 15))


def apply_pepper(password: str) -> str:
    """Apply pepper to password using HMAC-SHA256"""
    if not PEPPER_ENABLED:
        return password
    # Use HMAC to combine password with pepper
    peppered = hmac.new(
        PEPPER.encode(),
        password.encode(),
        hashlib.sha256
    ).hexdigest()
    return peppered


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    hash_algorithm = db.Column(db.String(20), default="bcrypt")  # 'bcrypt' or 'argon2id'
    totp_secret = db.Column(db.String(32), nullable=True)
    
    # Account lockout fields
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    def _get_argon2_hasher(self):
        """Get Argon2id hasher with spec-compliant parameters"""
        return PasswordHasher(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            type=Type.ID  # Argon2id
        )

    def set_password(self, password: str, algorithm: str = None):
        """Hash password with specified algorithm (default: argon2id)"""
        algorithm = algorithm or DEFAULT_HASH_ALGORITHM
        
        # Apply pepper before hashing
        peppered_password = apply_pepper(password)

        if algorithm == "argon2id":
            ph = self._get_argon2_hasher()
            self.password_hash = ph.hash(peppered_password)
            self.hash_algorithm = "argon2id"
        else:  # bcrypt
            salt = bcrypt.gensalt(rounds=BCRYPT_COST)
            self.password_hash = bcrypt.hashpw(peppered_password.encode(), salt).decode()
            self.hash_algorithm = "bcrypt"

    def check_password(self, password: str) -> bool:
        """Verify password against stored hash"""
        # Apply pepper before verification
        peppered_password = apply_pepper(password)
        
        if self.hash_algorithm == "argon2id":
            try:
                ph = self._get_argon2_hasher()
                ph.verify(self.password_hash, peppered_password)
                return True
            except VerifyMismatchError:
                return False
        else:  # bcrypt
            return bcrypt.checkpw(peppered_password.encode(), self.password_hash.encode())

    def needs_rehash(self) -> bool:
        """Check if password should be migrated to new algorithm"""
        # Migrate if not using the default algorithm
        if self.hash_algorithm != DEFAULT_HASH_ALGORITHM:
            return True

        # For argon2id, also check if parameters changed
        if self.hash_algorithm == "argon2id":
            ph = self._get_argon2_hasher()
            return ph.check_needs_rehash(self.password_hash)

        return False

    def upgrade_password(self, password: str):
        """Migrate password to current default algorithm"""
        self.set_password(password, DEFAULT_HASH_ALGORITHM)

    # TOTP methods
    def generate_totp_secret(self):
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret

    def get_totp_uri(self, app_name="FlaskApp"):
        if not self.totp_secret:
            return None
        return pyotp.TOTP(self.totp_secret).provisioning_uri(
            name=self.username,
            issuer_name=app_name
        )

    def verify_totp(self, code: str) -> bool:
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(code)

    # Account lockout methods
    def is_locked(self) -> bool:
        """Check if the account is currently locked."""
        if self.locked_until is None:
            return False
        if datetime.utcnow() >= self.locked_until:
            # Lockout expired, reset
            self.locked_until = None
            self.failed_login_attempts = 0
            return False
        return True

    def get_lockout_remaining_seconds(self) -> int:
        """Get remaining lockout time in seconds."""
        if not self.is_locked():
            return 0
        remaining = (self.locked_until - datetime.utcnow()).total_seconds()
        return max(0, int(remaining))

    def record_failed_login(self) -> bool:
        """
        Record a failed login attempt.
        Returns True if account is now locked.
        """
        self.failed_login_attempts += 1
        
        if self.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
            self.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            return True
        return False

    def reset_failed_login_attempts(self):
        """Reset failed login attempts on successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None
