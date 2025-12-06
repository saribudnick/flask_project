from flask import Blueprint, request, jsonify
from .models import User, db
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

auth_bp = Blueprint("auth", __name__)

# --- REGISTER ---
@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "username + password required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "user already exists"}), 409

    user = User(username=username)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return jsonify({"msg": "user created"}), 201


# --- LOGIN ---
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"error": "invalid credentials"}), 401

    # If TOTP is enabled, require /login_totp instead
    if user.totp_secret:
        return jsonify({"error": "TOTP required", "totp_required": True}), 403

    token = create_access_token(identity=username)
    return jsonify({"token": token})


# --- LOGIN WITH TOTP ---
@auth_bp.route("/login_totp", methods=["POST"])
def login_totp():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    totp_code = data.get("totp_code")

    if not username or not password or not totp_code:
        return jsonify({"error": "username, password, and totp_code required"}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"error": "invalid credentials"}), 401

    if not user.totp_secret:
        return jsonify({"error": "TOTP not enabled for this user"}), 400

    if not user.verify_totp(totp_code):
        return jsonify({"error": "invalid TOTP code"}), 401

    token = create_access_token(identity=username)
    return jsonify({"token": token})


# --- SETUP TOTP ---
@auth_bp.route("/setup_totp", methods=["POST"])
@jwt_required()
def setup_totp():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "user not found"}), 404

    secret = user.generate_totp_secret()
    uri = user.get_totp_uri()

    db.session.commit()

    return jsonify({
        "msg": "TOTP enabled",
        "secret": secret,
        "uri": uri  # Use this URI to generate a QR code
    })
