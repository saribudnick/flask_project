from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import secrets
from collections import defaultdict
from threading import Lock

db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)


class CaptchaManager:
    """
    Manages CAPTCHA requirements and token validation.
    Triggers CAPTCHA after X failed login attempts per IP.
    """
    
    def __init__(self, failed_threshold: int = 5, token_ttl: int = 300):
        self.failed_threshold = failed_threshold  # Attempts before CAPTCHA required
        self.token_ttl = token_ttl  # Token validity in seconds
        self.failed_attempts = defaultdict(int)  # IP -> failed count
        self.valid_tokens = {}  # token -> (group_seed, expires_at)
        self.lock = Lock()
    
    def record_failed_attempt(self, ip: str) -> bool:
        """Record a failed login attempt. Returns True if CAPTCHA now required."""
        with self.lock:
            self.failed_attempts[ip] += 1
            return self.failed_attempts[ip] >= self.failed_threshold
    
    def record_success(self, ip: str):
        """Reset failed attempts on successful login."""
        with self.lock:
            self.failed_attempts[ip] = 0
    
    def is_captcha_required(self, ip: str) -> bool:
        """Check if CAPTCHA is required for this IP."""
        with self.lock:
            return self.failed_attempts[ip] >= self.failed_threshold
    
    def generate_token(self, group_seed: str) -> str:
        """Generate a CAPTCHA token (admin endpoint for automated testing)."""
        token = secrets.token_urlsafe(32)
        expires_at = time.time() + self.token_ttl
        with self.lock:
            self.valid_tokens[token] = (group_seed, expires_at)
        return token
    
    def validate_token(self, token: str) -> bool:
        """Validate and consume a CAPTCHA token."""
        with self.lock:
            if token not in self.valid_tokens:
                return False
            group_seed, expires_at = self.valid_tokens[token]
            if time.time() > expires_at:
                del self.valid_tokens[token]
                return False
            del self.valid_tokens[token]  # Single use
            return True
    
    def get_failed_count(self, ip: str) -> int:
        """Get current failed attempt count for IP."""
        with self.lock:
            return self.failed_attempts[ip]
    
    def reset_ip(self, ip: str):
        """Reset failed attempts for IP (admin use)."""
        with self.lock:
            self.failed_attempts[ip] = 0
    
    def cleanup_expired_tokens(self):
        """Remove expired tokens."""
        current_time = time.time()
        with self.lock:
            expired = [t for t, (_, exp) in self.valid_tokens.items() if current_time > exp]
            for token in expired:
                del self.valid_tokens[token]


# Global CAPTCHA manager instance
captcha_manager = CaptchaManager(failed_threshold=5, token_ttl=300)
