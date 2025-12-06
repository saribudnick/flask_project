from .extensions import db
import bcrypt
import pyotp

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)  # TOTP secret for 2FA

    # הצפנת סיסמה
    def set_password(self, password: str):
        self.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    # בדיקת סיסמה
    def check_password(self, password: str):
        return bcrypt.checkpw(password.encode(), self.password_hash.encode())

    # Generate TOTP secret
    def generate_totp_secret(self):
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret

    # Get TOTP provisioning URI for QR code
    def get_totp_uri(self, app_name="FlaskApp"):
        if not self.totp_secret:
            return None
        return pyotp.TOTP(self.totp_secret).provisioning_uri(
            name=self.username,
            issuer_name=app_name
        )

    # Verify TOTP code
    def verify_totp(self, code: str):
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(code)
