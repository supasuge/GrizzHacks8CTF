from __future__ import annotations

import base64
import os
import uuid

from flask import current_app, g, redirect, request


def generate_nonce() -> str:
    return base64.b64encode(os.urandom(18)).decode("utf-8").rstrip("=")


def register_security_hooks(app) -> None:
    @app.before_request
    def before_request_security():
        g.request_id = str(uuid.uuid4())
        g.csp_nonce = generate_nonce()

        should_redirect = (
            app.config.get("FORCE_HTTPS_REDIRECT", False)
            and not app.debug
            and not request.is_secure
        )
        if should_redirect:
            secure_url = request.url.replace("http://", "https://", 1)
            return redirect(secure_url, code=301)

    @app.after_request
    def after_request_security(response):
        request_id = getattr(g, "request_id", "")
        csp_nonce = getattr(g, "csp_nonce", "")

        response.headers.setdefault("X-Request-ID", request_id)

        if not current_app.config.get("SECURE_HEADERS_ENABLED", True):
            return response

        csp_parts = [
            "default-src 'self'",
            f"script-src 'self' 'nonce-{csp_nonce}'",
            "style-src 'self'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "manifest-src 'self'",
        ]

        if not app.debug:
            csp_parts.append("upgrade-insecure-requests")

        response.headers.setdefault("Content-Security-Policy", "; ".join(csp_parts))
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Permissions-Policy",
            "accelerometer=(), autoplay=(), camera=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

        robots_value = getattr(g, "seo", {}).get("robots")
        if robots_value:
            response.headers.setdefault("X-Robots-Tag", robots_value)

        hsts_seconds = int(app.config.get("HSTS_SECONDS", 0))
        if request.is_secure and hsts_seconds > 0:
            response.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={hsts_seconds}; includeSubDomains",
            )

        if request.path.startswith("/login") or request.path.startswith("/register"):
            response.headers.setdefault("Cache-Control", "no-store")

        return response