import time
from flask import Blueprint, request, jsonify, current_app
from .models import User, db, DEFAULT_HASH_ALGORITHM, MAX_FAILED_LOGIN_ATTEMPTS, LOCKOUT_DURATION_MINUTES
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from .auth_logger import log_auth_attempt
from .extensions import limiter, captcha_manager
import secrets

auth_bp = Blueprint("auth", __name__)


def migrate_password_if_needed(user, password):
    """Lazy migration: upgrade password hash on successful login"""
    if user.needs_rehash():
        old_algorithm = user.hash_algorithm
        user.upgrade_password(password)
        db.session.commit()
        return old_algorithm  # Return old algorithm for logging
    return None


def get_protection_flags():
    """Get current protection flags based on config"""
    from .models import PEPPER_ENABLED
    flags = []
    if current_app.config.get("RATE_LIMITING_ENABLED", True):
        flags.append("rate_limited")
    if current_app.config.get("CAPTCHA_ENABLED", True):
        flags.append("captcha_enabled")
    if current_app.config.get("ACCOUNT_LOCKOUT_ENABLED", True):
        flags.append("account_lockout")
    if PEPPER_ENABLED:
        flags.append("pepper")
    return flags


def get_client_ip():
    """Get client IP address"""
    return request.remote_addr or "127.0.0.1"


def check_captcha_required(ip: str, data: dict) -> tuple:
    """
    Check if CAPTCHA is required and validate if provided.
    Returns: (is_blocked, response_dict, http_code)
    """
    if not current_app.config.get("CAPTCHA_ENABLED", True):
        return False, None, None
    
    if captcha_manager.is_captcha_required(ip):
        captcha_token = data.get("captcha_token")
        
        if not captcha_token:
            # Use fixed group_seed
            group_seed = "251891"
            return True, {
                "error": "captcha_required",
                "captcha_required": True,
                "captcha_token": None,
                "group_seed": group_seed,
                "message": f"CAPTCHA required. Get token via: /admin/get_captcha_token?group_seed={group_seed}"
            }, 403
        
        if not captcha_manager.validate_token(captcha_token):
            return True, {
                "error": "invalid_captcha_token",
                "captcha_required": True,
                "message": "Invalid or expired CAPTCHA token"
            }, 403
    
    return False, None, None


# Custom error handler for rate limit exceeded
@auth_bp.errorhandler(429)
def ratelimit_handler(e):
    log_auth_attempt(
        username=request.get_json().get("username") if request.get_json() else "unknown",
        result="blocked_rate_limit",
        latency_ms=0,
        protection_flags=["rate_limited"]
    )
    return jsonify({
        "error": "rate_limit_exceeded",
        "message": str(e.description),
        "retry_after": e.description
    }), 429


# --- REGISTER ---
@auth_bp.route("/register", methods=["POST"])
@limiter.limit("10 per minute")
def register():
    start_time = time.perf_counter()
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    protection_flags = get_protection_flags()
    ip = get_client_ip()

    # Check CAPTCHA
    blocked, response, code = check_captcha_required(ip, data)
    if blocked:
        log_auth_attempt(
            username=username,
            result="blocked_captcha_required",
            latency_ms=(time.perf_counter() - start_time) * 1000,
            protection_flags=protection_flags + ["captcha_blocked"]
        )
        return jsonify(response), code

    if not username or not password:
        latency = (time.perf_counter() - start_time) * 1000
        log_auth_attempt(
            username=username,
            result="failure_missing_fields",
            latency_ms=latency,
            protection_flags=protection_flags
        )
        return jsonify({"error": "username + password required"}), 400

    if User.query.filter_by(username=username).first():
        latency = (time.perf_counter() - start_time) * 1000
        log_auth_attempt(
            username=username,
            result="failure_user_exists",
            latency_ms=latency,
            protection_flags=protection_flags
        )
        return jsonify({"error": "user already exists"}), 409

    user = User(username=username)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    # Reset CAPTCHA on successful registration
    captcha_manager.record_success(ip)

    latency = (time.perf_counter() - start_time) * 1000
    log_auth_attempt(
        username=username,
        result="success_registered",
        latency_ms=latency,
        hash_mode=user.hash_algorithm,
        protection_flags=protection_flags
    )

    return jsonify({"msg": "user created", "hash_algorithm": user.hash_algorithm}), 201


# --- LOGIN ---
@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    start_time = time.perf_counter()
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    protection_flags = get_protection_flags()
    ip = get_client_ip()

    # Check CAPTCHA requirement
    blocked, response, code = check_captcha_required(ip, data)
    if blocked:
        log_auth_attempt(
            username=username,
            result="blocked_captcha_required",
            latency_ms=(time.perf_counter() - start_time) * 1000,
            protection_flags=protection_flags + ["captcha_blocked"]
        )
        return jsonify(response), code

    user = User.query.filter_by(username=username).first()

    # Check account lockout (before password verification to prevent timing attacks)
    if user and user.is_locked():
        remaining = user.get_lockout_remaining_seconds()
        latency = (time.perf_counter() - start_time) * 1000
        log_auth_attempt(
            username=username,
            result="blocked_account_locked",
            latency_ms=latency,
            hash_mode=user.hash_algorithm,
            protection_flags=protection_flags + ["account_locked"]
        )
        return jsonify({
            "error": "account_locked",
            "message": f"Account is locked due to too many failed login attempts. Try again in {remaining} seconds.",
            "locked_until_seconds": remaining
        }), 423

    if not user or not user.check_password(password):
        # Record failed attempt for CAPTCHA tracking
        captcha_now_required = captcha_manager.record_failed_attempt(ip)
        
        # Record failed attempt for account lockout
        account_now_locked = False
        if user:
            account_now_locked = user.record_failed_login()
            db.session.commit()
        
        latency = (time.perf_counter() - start_time) * 1000
        result = "failure_invalid_credentials"
        if account_now_locked:
            result = "failure_account_now_locked"
            protection_flags.append("account_locked")
        elif captcha_now_required:
            result = "failure_invalid_credentials_captcha_triggered"
            protection_flags.append("captcha_triggered")
        
        log_auth_attempt(
            username=username,
            result=result,
            latency_ms=latency,
            hash_mode=user.hash_algorithm if user else "unknown",
            protection_flags=protection_flags
        )
        
        response = {"error": "invalid credentials"}
        if account_now_locked:
            response["account_locked"] = True
            response["message"] = f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes due to {MAX_FAILED_LOGIN_ATTEMPTS} failed attempts."
            response["locked_until_seconds"] = user.get_lockout_remaining_seconds()
        elif captcha_now_required:
            response["captcha_required"] = True
            response["message"] = "Too many failed attempts. CAPTCHA required for next attempt."
        
        return jsonify(response), 401

    # Successful authentication - reset counters
    captcha_manager.record_success(ip)
    user.reset_failed_login_attempts()
    db.session.commit()

    # Lazy migration: upgrade hash if needed
    migrated_from = migrate_password_if_needed(user, password)
    if migrated_from:
        protection_flags.append(f"migrated_from_{migrated_from}")

    # If TOTP is enabled, require /login_totp instead
    if user.totp_secret:
        latency = (time.perf_counter() - start_time) * 1000
        log_auth_attempt(
            username=username,
            result="redirect_totp_required",
            latency_ms=latency,
            hash_mode=user.hash_algorithm,
            protection_flags=protection_flags + ["totp_enabled"]
        )
        return jsonify({"error": "TOTP required", "totp_required": True}), 403

    latency = (time.perf_counter() - start_time) * 1000
    log_auth_attempt(
        username=username,
        result="success",
        latency_ms=latency,
        hash_mode=user.hash_algorithm,
        protection_flags=protection_flags
    )

    token = create_access_token(identity=username)
    return jsonify({"token": token})


# --- LOGIN WITH TOTP ---
@auth_bp.route("/login_totp", methods=["POST"])
@limiter.limit("5 per minute")
def login_totp():
    start_time = time.perf_counter()
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    totp_code = data.get("totp_code")
    protection_flags = get_protection_flags() + ["totp"]
    ip = get_client_ip()

    # Check CAPTCHA requirement
    blocked, response, code = check_captcha_required(ip, data)
    if blocked:
        log_auth_attempt(
            username=username,
            result="blocked_captcha_required",
            latency_ms=(time.perf_counter() - start_time) * 1000,
            protection_flags=protection_flags + ["captcha_blocked"]
        )
        return jsonify(response), code

    if not username or not password or not totp_code:
        latency = (time.perf_counter() - start_time) * 1000
        log_auth_attempt(
            username=username,
            result="failure_missing_fields",
            latency_ms=latency,
            hash_mode="unknown",
            protection_flags=protection_flags
        )
        return jsonify({"error": "username, password, and totp_code required"}), 400

    user = User.query.filter_by(username=username).first()

    # Check account lockout (before password verification to prevent timing attacks)
    if user and user.is_locked():
        remaining = user.get_lockout_remaining_seconds()
        latency = (time.perf_counter() - start_time) * 1000
        log_auth_attempt(
            username=username,
            result="blocked_account_locked",
            latency_ms=latency,
            hash_mode=user.hash_algorithm,
            protection_flags=protection_flags + ["account_locked"]
        )
        return jsonify({
            "error": "account_locked",
            "message": f"Account is locked due to too many failed login attempts. Try again in {remaining} seconds.",
            "locked_until_seconds": remaining
        }), 423

    if not user or not user.check_password(password):
        captcha_now_required = captcha_manager.record_failed_attempt(ip)
        
        # Record failed attempt for account lockout
        account_now_locked = False
        if user:
            account_now_locked = user.record_failed_login()
            db.session.commit()
        
        latency = (time.perf_counter() - start_time) * 1000
        result = "failure_invalid_credentials"
        if account_now_locked:
            result = "failure_account_now_locked"
            protection_flags.append("account_locked")
        
        log_auth_attempt(
            username=username,
            result=result,
            latency_ms=latency,
            hash_mode=user.hash_algorithm if user else "unknown",
            protection_flags=protection_flags
        )
        
        response = {"error": "invalid credentials"}
        if account_now_locked:
            response["account_locked"] = True
            response["message"] = f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes due to {MAX_FAILED_LOGIN_ATTEMPTS} failed attempts."
            response["locked_until_seconds"] = user.get_lockout_remaining_seconds()
        
        return jsonify(response), 401

    if not user.totp_secret:
        latency = (time.perf_counter() - start_time) * 1000
        log_auth_attempt(
            username=username,
            result="failure_totp_not_enabled",
            latency_ms=latency,
            hash_mode=user.hash_algorithm,
            protection_flags=protection_flags
        )
        return jsonify({"error": "TOTP not enabled for this user"}), 400

    if not user.verify_totp(totp_code):
        captcha_now_required = captcha_manager.record_failed_attempt(ip)
        
        # Record failed attempt for account lockout (invalid TOTP counts as failed)
        account_now_locked = user.record_failed_login()
        db.session.commit()
        
        latency = (time.perf_counter() - start_time) * 1000
        result = "failure_invalid_totp"
        if account_now_locked:
            result = "failure_invalid_totp_account_locked"
            protection_flags.append("account_locked")
        
        log_auth_attempt(
            username=username,
            result=result,
            latency_ms=latency,
            hash_mode=user.hash_algorithm,
            protection_flags=protection_flags
        )
        
        response = {"error": "invalid TOTP code"}
        if account_now_locked:
            response["account_locked"] = True
            response["message"] = f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes due to {MAX_FAILED_LOGIN_ATTEMPTS} failed attempts."
            response["locked_until_seconds"] = user.get_lockout_remaining_seconds()
        
        return jsonify(response), 401

    # Successful authentication - reset counters
    captcha_manager.record_success(ip)
    user.reset_failed_login_attempts()
    db.session.commit()

    # Lazy migration: upgrade hash if needed
    migrated_from = migrate_password_if_needed(user, password)
    if migrated_from:
        protection_flags.append(f"migrated_from_{migrated_from}")

    latency = (time.perf_counter() - start_time) * 1000
    log_auth_attempt(
        username=username,
        result="success",
        latency_ms=latency,
        hash_mode=user.hash_algorithm,
        protection_flags=protection_flags
    )

    token = create_access_token(identity=username)
    return jsonify({"token": token})


# --- SETUP TOTP ---
@auth_bp.route("/setup_totp", methods=["POST"])
@jwt_required()
@limiter.limit("3 per minute")
def setup_totp():
    start_time = time.perf_counter()
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    protection_flags = get_protection_flags() + ["jwt"]

    if not user:
        latency = (time.perf_counter() - start_time) * 1000
        log_auth_attempt(
            username=username,
            result="failure_user_not_found",
            latency_ms=latency,
            protection_flags=protection_flags
        )
        return jsonify({"error": "user not found"}), 404

    secret = user.generate_totp_secret()
    uri = user.get_totp_uri()

    db.session.commit()

    latency = (time.perf_counter() - start_time) * 1000
    log_auth_attempt(
        username=username,
        result="success_totp_setup",
        latency_ms=latency,
        hash_mode=user.hash_algorithm,
        protection_flags=protection_flags + ["totp_setup"]
    )

    return jsonify({
        "msg": "TOTP enabled",
        "secret": secret,
        "uri": uri
    })
