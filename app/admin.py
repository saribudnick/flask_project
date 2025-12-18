"""
Admin endpoints for automated testing.
These endpoints are for test automation only and should be disabled in production.
"""

import time
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from .extensions import captcha_manager

admin_bp = Blueprint("admin", __name__)

GROUP_SEED = "251891"  # XOR of group member IDs


@admin_bp.route("/get_captcha_token", methods=["GET"])
def get_captcha_token():
    """
    Generate a valid CAPTCHA token for automated testing.
    
    Query params:
        group_seed: Identifier for the test group/session
    
    Returns:
        {"captcha_token": "...", "expires_in": 300}
    
    Usage:
        GET /admin/get_captcha_token?group_seed=<GROUP_SEED>
    """
    group_seed = request.args.get("group_seed", "default")
    
    token = captcha_manager.generate_token(group_seed)
    
    return jsonify({
        "captcha_token": token,
        "group_seed": group_seed,
        "expires_in": captcha_manager.token_ttl,
        "note": "This endpoint is for automated testing only"
    })


@admin_bp.route("/reset_captcha", methods=["POST"])
def reset_captcha():
    """
    Reset CAPTCHA state for an IP address.
    
    JSON body:
        {"ip": "127.0.0.1"}
    
    Returns:
        {"msg": "reset", "ip": "..."}
    """
    data = request.get_json() or {}
    ip = data.get("ip", request.remote_addr)
    
    captcha_manager.reset_ip(ip)
    
    return jsonify({
        "msg": "captcha reset",
        "ip": ip
    })


@admin_bp.route("/captcha_status", methods=["GET"])
def captcha_status():
    """
    Get CAPTCHA status for current IP.
    
    Returns:
        {
            "ip": "...",
            "failed_attempts": 3,
            "captcha_required": false,
            "threshold": 5
        }
    """
    ip = request.remote_addr
    
    return jsonify({
        "ip": ip,
        "failed_attempts": captcha_manager.get_failed_count(ip),
        "captcha_required": captcha_manager.is_captcha_required(ip),
        "threshold": captcha_manager.failed_threshold
    })


@admin_bp.route("/setup_totp_users", methods=["POST"])
def setup_totp_users():
    """
    Setup TOTP for test users from users.json.
    This endpoint reads users.json and enables TOTP for users with secret_totp defined.
    
    Returns:
        {"setup_count": N, "users": [...]}
    """
    import json
    from pathlib import Path
    from .models import User, db
    
    users_file = Path(__file__).parent.parent / "users.json"
    
    if not users_file.exists():
        return jsonify({"error": "users.json not found"}), 404
    
    with open(users_file) as f:
        data = json.load(f)
    
    setup_users = []
    for user_data in data.get("users", []):
        if user_data.get("secret_totp"):
            username = user_data["username"]
            secret = user_data["secret_totp"]
            
            user = User.query.filter_by(username=username).first()
            if user:
                user.totp_secret = secret
                db.session.commit()
                setup_users.append(username)
    
    return jsonify({
        "msg": "TOTP secrets configured",
        "setup_count": len(setup_users),
        "users": setup_users
    })


@admin_bp.route("/server_time", methods=["GET"])
def server_time():
    """
    Get server time for TOTP synchronization.
    
    Returns:
        {
            "timestamp": "2025-12-12T14:30:00.000000+00:00",
            "unix_time": 1734010200.123456,
            "totp_window": 57800340,
            "group_seed": "251891"
        }
    
    Usage for clock drift calculation:
        client_time = time.time()
        server_time = response["unix_time"]
        drift = client_time - server_time
    """
    current_time = time.time()
    
    return jsonify({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "unix_time": current_time,
        "totp_window": int(current_time // 30),
        "group_seed": GROUP_SEED
    })


@admin_bp.route("/group_info", methods=["GET"])
def group_info():
    """
    Get group information including group_seed.
    
    The group_seed is the XOR of group member IDs.
    
    Returns:
        {
            "group_seed": "251891",
            "description": "XOR of group member IDs",
            "usage": "Include in all logs and CAPTCHA requests"
        }
    """
    return jsonify({
        "group_seed": GROUP_SEED,
        "description": "XOR of group member IDs",
        "usage": "Include in all logs and CAPTCHA requests",
        "endpoints": {
            "captcha_token": f"/admin/get_captcha_token?group_seed={GROUP_SEED}",
            "server_time": "/admin/server_time",
            "captcha_status": "/admin/captcha_status"
        }
    })


@admin_bp.route("/totp_drift_test", methods=["POST"])
def totp_drift_test():
    """
    Test TOTP validation with simulated clock drift.
    
    JSON body:
        {
            "username": "totp_user01",
            "drift_seconds": 30
        }
    
    Returns:
        {
            "expected_code": "123456",
            "server_time": 1734010200.123,
            "simulated_client_time": 1734010230.123,
            "totp_window_server": 57800340,
            "totp_window_client": 57800341,
            "window_difference": 1,
            "note": "TOTP typically valid within ±1 window"
        }
    """
    import pyotp
    import json as json_module
    from pathlib import Path
    
    data = request.get_json() or {}
    username = data.get("username")
    drift_seconds = data.get("drift_seconds", 0)
    
    if not username:
        return jsonify({"error": "username required"}), 400
    
    # Load user's TOTP secret from users.json
    users_file = Path(__file__).parent.parent / "users.json"
    if not users_file.exists():
        return jsonify({"error": "users.json not found"}), 404
    
    with open(users_file) as f:
        users_data = json_module.load(f)
    
    user_secret = None
    for user in users_data.get("users", []):
        if user.get("username") == username and user.get("secret_totp"):
            user_secret = user["secret_totp"]
            break
    
    if not user_secret:
        return jsonify({"error": f"TOTP secret not found for {username}"}), 404
    
    server_time = time.time()
    client_time = server_time + drift_seconds
    
    totp = pyotp.TOTP(user_secret)
    server_code = totp.at(server_time)
    client_code = totp.at(client_time)
    
    server_window = int(server_time // 30)
    client_window = int(client_time // 30)
    
    return jsonify({
        "username": username,
        "group_seed": GROUP_SEED,
        "drift_seconds": drift_seconds,
        "server_time": server_time,
        "simulated_client_time": client_time,
        "server_code": server_code,
        "client_code_with_drift": client_code,
        "codes_match": server_code == client_code,
        "totp_window_server": server_window,
        "totp_window_client": client_window,
        "window_difference": client_window - server_window,
        "validation_expected": abs(client_window - server_window) <= 1,
        "note": "TOTP typically valid within ±1 window (30 seconds)"
    })

