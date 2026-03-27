#!/usr/bin/env python3
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    return os.getenv(name, default)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


class Config:
    SECRET_KEY = env("SECRET_KEY", "change-me-in-production")
    ADMIN_KEY = env("ADMIN_KEY", "change-me-admin-key").encode()

    SQLALCHEMY_DATABASE_URI = env("DATABASE_URL", "sqlite:///ctfapp.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    REDIS_URL = env("REDIS_URL", "redis://localhost:6379/0")

    APP_ENV = env("APP_ENV", "development")
    PREFERRED_URL_SCHEME = env("PREFERRED_URL_SCHEME", "http")
    SITE_URL = env("SITE_URL", "http://localhost:5000")

    # Session
    SESSION_COOKIE_NAME = "ctfapp_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
    SESSION_COOKIE_SAMESITE = env("SESSION_COOKIE_SAMESITE", "Lax")
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
    REMEMBER_COOKIE_SAMESITE = env("SESSION_COOKIE_SAMESITE", "Lax")

    # CSRF
    WTF_CSRF_TIME_LIMIT = 3600

    # Upload limits
    MAX_CONTENT_LENGTH = env_int("MAX_CONTENT_LENGTH", 32 * 1024 * 1024)

    # Proxy
    TRUST_PROXY = env_bool("TRUST_PROXY", False)
    PROXY_FIX_X_FOR = env_int("PROXY_FIX_X_FOR", 1)
    PROXY_FIX_X_PROTO = env_int("PROXY_FIX_X_PROTO", 1)
    PROXY_FIX_X_HOST = env_int("PROXY_FIX_X_HOST", 0)
    PROXY_FIX_X_PREFIX = env_int("PROXY_FIX_X_PREFIX", 0)

    # Security headers
    SECURE_HEADERS_ENABLED = env_bool("SECURE_HEADERS_ENABLED", True)
    ENABLE_HSTS = env_bool("ENABLE_HSTS", False)
    HSTS_VALUE = f"max-age={env_int('HSTS_SECONDS', 31536000)}; includeSubDomains"
    CONTENT_SECURITY_POLICY = env(
        "CONTENT_SECURITY_POLICY",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';",
    )

    # Rate limiting
    RATELIMIT_STORAGE_URI = env("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True

    # Flag submission rate limit
    FLAG_WRONG_LIMIT = env_int("FLAG_WRONG_LIMIT", 3)
    FLAG_LOCKOUT_SECONDS = env_int("FLAG_LOCKOUT_SECONDS", 30)

    # Email
    MAILTRAP_API_KEY = env("MAILTRAP_API_KEY", "")
    MAIL_SENDER = env("MAIL_SENDER", "no-reply@grizzhacks8ctf.us")

    # Dispatch service
    DISPATCH_INTERNAL_URL = env("DISPATCH_INTERNAL_URL", "http://localhost:5001")
    DISPATCH_ADMIN_TOKEN = env("DISPATCH_ADMIN_TOKEN", "change-me-dispatch-token")

    # Event timing
    EVENT_STARTS_AT = datetime(2025, 3, 28, 12, 0, 0, tzinfo=timezone.utc)
    EVENT_ENDS_AT = datetime(2025, 3, 29, 12, 0, 0, tzinfo=timezone.utc)

    TEMPLATES_AUTO_RELOAD = True


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(48).hex())
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = "https"
    TRUST_PROXY = True
    ENABLE_HSTS = True


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SERVER_NAME = "localhost"


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config():
    env_name = (env("APP_ENV", "development") or "development").lower()
    return CONFIG_MAP.get(env_name, DevelopmentConfig)
