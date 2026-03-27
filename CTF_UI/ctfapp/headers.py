from flask import Flask

def register_security_headers(app: Flask):
    @app.after_request
    def set_security_headers(response):
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["Referrer-Policy"] = "strict-origin-when-cross-origin"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        h["X-Frame-Options"] = "SAMEORIGIN"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        h["X-Download-Options"] = "noopen"
        h["Content-Security-Policy"] = app.config["CONTENT_SECURITY_POLICY"]

        if app.config["ENABLE_HSTS"] and not app.debug:
            h["Strict-Transport-Security"] = app.config["HSTS_VALUE"]

        h.pop("X-XSS-Protection", None)
        return response