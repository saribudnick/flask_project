from .extensions import db, jwt, migrate, limiter, captcha_manager
from .models import User
from flask import Flask
from .config import Config


def create_app(rate_limiting=True, captcha_enabled=True):
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    app.config.from_object(Config)
    
    # Store security config for auth module
    app.config["RATE_LIMITING_ENABLED"] = rate_limiting
    app.config["CAPTCHA_ENABLED"] = captcha_enabled
    app.config["CAPTCHA_THRESHOLD"] = 5  # Failed attempts before CAPTCHA

    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    
    # Only enable rate limiter if rate_limiting is True
    if rate_limiting:
        limiter.init_app(app)
    else:
        # Disable the limiter completely
        limiter.enabled = False
        limiter.init_app(app)

    from .routes import main_bp
    from .auth import auth_bp
    from .admin import admin_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    return app
