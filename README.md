# Flask Authentication Security Project

## Group Information
- **Group Seed**: `251891`
- **Description**: XOR of group member IDs for traceability and originality

---

## Project Overview

A Flask REST API implementing secure authentication with multiple defense mechanisms against brute-force and password-spraying attacks. The project demonstrates various security layers including modern password hashing, two-factor authentication (TOTP), rate limiting, CAPTCHA simulation, and pepper protection.

---

## Features

### Core Functionality
- ✅ User registration and authentication
- ✅ JWT-based session management
- ✅ Two-Factor Authentication (TOTP)
- ✅ SQLite database with Flask-Migrate support
- ✅ Comprehensive authentication logging

### Defense Mechanisms
| Defense | Status | Description |
|---------|--------|-------------|
| **bcrypt** | ✅ Enabled | Cost factor = 12 |
| **Argon2id** | ✅ Enabled | time=1, memory=64MB, parallelism=1 |
| **Per-user Salt** | ✅ Automatic | Embedded in hash |
| **Pepper** | ✅ Enabled | HMAC-SHA256 server secret |
| **Rate Limiting** | ✅ Configurable | Flask-Limiter (5 attempts/min on login) |
| **CAPTCHA** | ✅ Configurable | After 5 failed attempts per IP |
| **TOTP (2FA)** | ✅ Enabled | pyotp-based time-based OTP |

---

## Installation

### Prerequisites
- Python 3.8+
- pip

### Setup
```bash
# Clone the repository
git clone <repository-url>
cd flask_project

# Create virtual environment (optional)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set environment variable for pepper (recommended)
export APP_PEPPER_KEY="your-secret-pepper-key"

# Initialize database
flask db upgrade

# Run the server
python3 run.py
```

The server runs on `http://127.0.0.1:5000`

---

## API Endpoints

### Authentication Endpoints

| Endpoint | Method | Description | Rate Limit |
|----------|--------|-------------|------------|
| `/auth/register` | POST | Register new user | 10/min |
| `/auth/login` | POST | Login (returns JWT or TOTP requirement) | 5/min |
| `/auth/login_totp` | POST | Login with TOTP code | 5/min |
| `/auth/setup_totp` | POST | Setup TOTP for user (requires JWT) | 3/min |

### Admin Endpoints (Testing Only)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/get_captcha_token` | GET | Get bypass CAPTCHA token |
| `/admin/reset_captcha` | POST | Reset CAPTCHA state for IP |
| `/admin/captcha_status` | GET | Check CAPTCHA status for IP |
| `/admin/setup_totp_users` | POST | Bulk setup TOTP for users |
| `/admin/server_time` | GET | Get server timestamp |
| `/admin/totp_drift_test` | POST | Test TOTP with clock drift |
| `/admin/group_info` | GET | Get group seed information |

### Other Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |

---

## API Usage Examples

### Register User
```bash
curl -X POST http://127.0.0.1:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "SecurePass123!"}'
```

### Login
```bash
curl -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "SecurePass123!"}'
```

### Login with TOTP
```bash
curl -X POST http://127.0.0.1:5000/auth/login_totp \
  -H "Content-Type: application/json" \
  -d '{"username": "totp_user01", "password": "TotpTest123!", "totp_code": "123456"}'
```

### Get CAPTCHA Token (Admin)
```bash
curl "http://127.0.0.1:5000/admin/get_captcha_token?group_seed=251891"
```

---

## Password Hashing Implementation

### Supported Algorithms

#### bcrypt (Default)
- **Cost Factor**: 12 rounds
- **Salt**: Auto-generated 22-character salt per password
- **Format**: `$2b$12$[SALT][HASH]`

#### Argon2id
- **Time Cost**: 1 iteration
- **Memory Cost**: 64 MB (65536 KB)
- **Parallelism**: 1 thread
- **Salt**: Auto-generated 16-byte salt per password
- **Format**: `$argon2id$v=19$m=65536,t=1,p=1$[SALT]$[HASH]`

### Pepper Implementation
- **Algorithm**: HMAC-SHA256
- **Storage**: Environment variable `APP_PEPPER_KEY`
- **Application**: Applied before hashing (server-side secret)

### Password Flow
```
password → HMAC-SHA256(password, PEPPER) → bcrypt/Argon2id(peppered, SALT) → stored_hash
```

### Lazy Migration
Existing users are automatically migrated to Argon2id on next successful login.

---

## TOTP Automation

### Configuration
- `secret_totp` provided in `users.json` for test accounts
- Uses `pyotp` library for token generation

### Clock Drift Simulation
```bash
# Test TOTP with +30 second drift
curl -X POST http://127.0.0.1:5000/admin/totp_drift_test \
  -H "Content-Type: application/json" \
  -d '{"username": "totp_user01", "drift_seconds": 30}'
```

### TOTP Test Users
| Username | Password | TOTP Secret |
|----------|----------|-------------|
| totp_user01 | TotpTest123! | JBSWY3DPEHPK3PXP |
| totp_user02 | TotpSecure456@ | GEZDGNBVGY3TQOJQ |
| totp_user03 | Totp2FA789# | MFRGGZDFMY4TQNZZ |

---

## CAPTCHA Simulation

### Trigger Condition
- CAPTCHA required after **5 failed login attempts** from same IP

### Response When Required
```json
{
  "error": "captcha_required",
  "captcha_required": true,
  "group_seed": "251891",
  "message": "CAPTCHA required. Get token via: /admin/get_captcha_token?group_seed=251891"
}
```

### Bypass for Testing
```bash
# Get valid token
curl "http://127.0.0.1:5000/admin/get_captcha_token?group_seed=251891"

# Use token in login
curl -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "pass", "captcha_token": "<token>"}'
```

---

## Attack Simulation

### Running Attack Simulator
```bash
# Run comprehensive attack simulation
python3 attack_simulator_v2.py
```

### Attack Types
1. **Brute Force**: Sequential password attempts against single user
2. **Password Spray**: Common passwords across multiple users

### Resource Limits
- **Default**: 50,000 attempts per configuration
- **Maximum**: 1,000,000 attempts or 2 hours runtime

### Metrics Collected
- Total attempts
- Successful/failed attempts
- Blocked attempts (rate limiting)
- CAPTCHA challenges & bypasses
- Time to compromise
- Attempts per second
- Average latency
- CPU & memory usage

### Output Files
- `attack_metrics_*.json` - Detailed metrics per run
- `defense_comparison_report.json` - Comparison across configurations
- `comprehensive_defense_report.json` - Full analysis

---

## Authentication Logging

All authentication attempts are logged to `log.attempts` in JSON Lines format.

### Log Fields
| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 timestamp |
| `group_seed` | Group identifier (251891) |
| `username` | Attempted username |
| `hash_mode` | Hashing algorithm used |
| `protection_flags` | Active defenses |
| `result` | success/failure/blocked |
| `latency_ms` | Request processing time |

### Example Log Entry
```json
{
  "timestamp": "2025-12-18T10:30:45.123456",
  "group_seed": "251891",
  "username": "testuser",
  "hash_mode": "argon2id",
  "protection_flags": ["argon2id", "pepper", "rate_limit", "captcha"],
  "result": "success",
  "latency_ms": 245.67
}
```

---

## Test Users

### User Categories

#### Weak Passwords (10 users)
Simple, commonly used passwords (e.g., `123456`, `admin`, `qwert`)

#### Medium Passwords (10 users)
Mixed case with numbers (e.g., `Admin001`, `Summer25`)

#### Strong Passwords (10 users)
Complex with special characters (e.g., `%StrongPass_14%`, `M@nNual-Test&42`)

#### TOTP-Enabled Users (3 users)
Two-factor authentication enabled with known secrets

See `users.json` for complete list with credentials.

---

## Configuration

### Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| `APP_PEPPER_KEY` | Secret pepper for password hashing | Built-in default |
| `SECRET_KEY` | Flask session secret | dev-secret-key |
| `JWT_SECRET_KEY` | JWT signing key | jwt-secret-key |

### Application Configuration (`run.py`)
```python
# Full defenses enabled
app = create_app(rate_limiting=True, captcha_enabled=True)

# Testing mode (no rate limiting)
app = create_app(rate_limiting=False, captcha_enabled=False)
```

---

## Project Structure

```
flask_project/
├── app/
│   ├── __init__.py          # Application factory
│   ├── admin.py             # Admin endpoints
│   ├── auth.py              # Authentication endpoints
│   ├── auth_logger.py       # Logging utility
│   ├── config.py            # Flask configuration
│   ├── extensions.py        # Flask extensions & CAPTCHA manager
│   ├── models.py            # User model & password hashing
│   └── routes.py            # Basic routes
├── instance/
│   └── app.db               # SQLite database
├── migrations/              # Database migrations
├── attack_simulator_v2.py   # Attack simulation script
├── comprehensive_defense_test.py
├── log.attempts             # Authentication logs
├── requirements.txt         # Python dependencies
├── run.py                   # Application entry point
├── totp_automation.py       # TOTP utilities
└── users.json               # Test user accounts
```

---

## Dependencies

```
Flask==3.0.0
Flask-SQLAlchemy==3.1.1
Flask-JWT-Extended==4.6.0
Flask-Migrate==4.0.5
Flask-Limiter==3.5.0
bcrypt==4.1.2
argon2-cffi==23.1.0
pyotp==2.9.0
requests==2.31.0
psutil==5.9.7
```

---

## Security Considerations

### Production Recommendations
1. **Pepper Key**: Store in secure environment variable or secrets manager
2. **JWT Secret**: Use strong, randomly generated key
3. **Rate Limiting**: Enable with appropriate thresholds
4. **HTTPS**: Always use TLS in production
5. **Database**: Use PostgreSQL/MySQL instead of SQLite
6. **CAPTCHA**: Implement real CAPTCHA service (reCAPTCHA, hCaptcha)

### Defense Effectiveness (from attack simulation)
| Configuration | Brute Force | Password Spray |
|--------------|-------------|----------------|
| No defenses | ~850 attempts/sec | High success |
| Rate limiting | ~0.08 attempts/sec | Significantly slowed |
| CAPTCHA | Blocked after 5 fails | Blocked per IP |
| Pepper | No offline cracking | Requires server access |
| Full defenses | Maximum protection | Minimal success |

---

## License

This project is for educational purposes as part of security course 20940.

---

## Group Seed

**`251891`** - Used in all logs, CAPTCHA responses, and `users.json` for traceability.
