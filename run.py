from app import create_app

# Defense configuration for testing
# rate_limiting=True, captcha=True, pepper=True
app = create_app(rate_limiting=True, captcha_enabled=True)

if __name__ == "__main__":
    app.run(debug=True)
