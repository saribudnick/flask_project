from flask import Blueprint, jsonify, render_template

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Serve the login page"""
    return render_template("login.html")


@main_bp.route("/health")
def health():
    return jsonify({"status": "ok"})
