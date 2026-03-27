# GrizzHacks8 CTF Core Platform — Implementation Plan (1 of 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the core CTF web platform — auth, models, HMAC flag engine, anti-cheat, challenge submission, scoreboard, admin dashboard.

**Architecture:** Flask app factory with blueprints (auth, challenges, scoreboard, team, admin, dispatch proxy). Service layer for flag derivation (HMAC-SHA3-256), anti-cheat (flag-share detection via cross-principal scan), and chained-HMAC audit logging. All scoring goes through a `Principal` abstraction that unifies team/solo identities.

**Tech Stack:** Flask 3.x, SQLAlchemy (PostgreSQL), Redis, Flask-Login, Flask-Migrate, Flask-Limiter, Flask-WTF, argon2-cffi, pycryptodome

**Spec:** `docs/superpowers/specs/2026-03-26-ctf-platform-design.md`

---

## File Structure

### Modified
- `pyproject.toml` — add flask-login, flask-migrate, redis, psycopg2-binary, argon2-cffi
- `ctfapp/config.py` — add TRUST_PROXY, CSP, HSTS, REDIS_URL, ADMIN_KEY, and other missing fields
- `ctfapp/extensions.py` — add db, migrate, login_manager, csrf, cache, redis_client
- `ctfapp/__init__.py` — fix syntax error, wire extensions + blueprints
- `ctfapp/security.py` — add missing CSP/HSTS config keys
- `ctfapp/secure_log.py` — implement chained HMAC event logging
- `wsgi.py` — entry point

### Created: Models
- `ctfapp/models/__init__.py` — import all models, export `db`
- `ctfapp/models/user.py` — User, TeamMember
- `ctfapp/models/team.py` — Team
- `ctfapp/models/principal.py` — Principal (scoring identity)
- `ctfapp/models/challenge.py` — Challenge, ChallengeFile
- `ctfapp/models/instance.py` — Instance (dispatch scaffold)
- `ctfapp/models/submission.py` — Submission, Solve, ScoreEvent, TeamFlag

### Created: Services
- `ctfapp/services/__init__.py`
- `ctfapp/services/flag_engine.py` — derive_flag, verify_flag, pre-generate
- `ctfapp/services/anticheat.py` — flag share detection, rate limiting
- `ctfapp/services/auth_service.py` — register, login, password hashing
- `ctfapp/services/event_service.py` — chained HMAC audit log
- `ctfapp/services/mail_service.py` — Mailtrap email

### Created: Blueprints
- `ctfapp/blueprints/__init__.py`
- `ctfapp/blueprints/auth/__init__.py`, `routes.py`, `forms.py`
- `ctfapp/blueprints/challenges/__init__.py`, `routes.py`, `forms.py`
- `ctfapp/blueprints/scoreboard/__init__.py`, `routes.py`
- `ctfapp/blueprints/team/__init__.py`, `routes.py`, `forms.py`
- `ctfapp/blueprints/admin/__init__.py`, `routes.py`, `forms.py`
- `ctfapp/blueprints/dispatch/__init__.py`, `routes.py`

### Created: Templates
- `ctfapp/templates/base.html`
- `ctfapp/templates/error.html`
- `ctfapp/templates/index.html`
- `ctfapp/templates/auth/login.html`, `register.html`
- `ctfapp/templates/challenges/list.html`, `detail.html`
- `ctfapp/templates/scoreboard/index.html`
- `ctfapp/templates/team/create.html`, `manage.html`, `join.html`
- `ctfapp/templates/admin/dashboard.html`, `challenges.html`, `challenge_form.html`, `users.html`, `event_log.html`
- `ctfapp/templates/dispatch/instance.html`

### Created: Tests
- `tests/conftest.py` — test app factory, fixtures
- `tests/test_flag_engine.py`
- `tests/test_anticheat.py`
- `tests/test_auth.py`
- `tests/test_challenges.py`
- `tests/test_scoreboard.py`

### Created: Infrastructure stubs
- `.env.example`
- `start.sh`
- `Dockerfile`

---

## Task 1: Dependencies and pyproject.toml

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Update pyproject.toml with all required dependencies**

```toml
[project]
name = "ctf-ui"
version = "0.1.0"
description = "GrizzHacks8 CTF Platform"
readme = "README.md"
requires-python = ">=3.13"
dependencies = [
    "flask>=3.1",
    "flask-caching>=2.3.1",
    "flask-limiter>=4.1.1",
    "flask-login>=0.6.3",
    "flask-migrate>=4.0.7",
    "flask-sqlalchemy>=3.1.1",
    "flask-wtf>=1.2.2",
    "frontmatter>=3.0.8",
    "pycryptodome>=3.23.0",
    "python-dotenv>=1.2.2",
    "argon2-cffi>=23.1.0",
    "redis>=5.0.0",
    "psycopg2-binary>=2.9.9",
    "email-validator>=2.1.0",
    "gunicorn>=22.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-flask>=1.3.0",
]
```

- [ ] **Step 2: Install dependencies**

Run: `cd /home/supasuge/CTF-THM-HTB/Grizzhacks8-CTF/CTF_UI && uv sync`
Expected: All packages resolve and install

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "feat: add all core platform dependencies"
```

---

## Task 2: Fix config.py

**Files:**
- Modify: `ctfapp/config.py`

- [ ] **Step 1: Replace config.py with complete configuration**

```python
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
```

- [ ] **Step 2: Commit**

```bash
git add ctfapp/config.py
git commit -m "feat: complete config with all platform settings"
```

---

## Task 3: Extensions

**Files:**
- Modify: `ctfapp/extensions.py`

- [ ] **Step 1: Write extensions.py with all shared instances**

```python
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
cache = Cache()
limiter = Limiter(key_func=get_remote_address)
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message_category = "info"

redis_client = None


def init_redis(app):
    """Initialize Redis client from app config. Call during app factory."""
    global redis_client
    import redis

    redis_client = redis.from_url(
        app.config["REDIS_URL"], decode_responses=True
    )
    return redis_client


def get_redis():
    """Get the initialized Redis client."""
    if redis_client is None:
        raise RuntimeError("Redis not initialized. Call init_redis(app) first.")
    return redis_client
```

- [ ] **Step 2: Commit**

```bash
git add ctfapp/extensions.py
git commit -m "feat: wire all extensions (db, redis, limiter, login, cache, csrf)"
```

---

## Task 4: Models

**Files:**
- Create: `ctfapp/models/__init__.py`
- Create: `ctfapp/models/user.py`
- Create: `ctfapp/models/team.py`
- Create: `ctfapp/models/principal.py`
- Create: `ctfapp/models/challenge.py`
- Create: `ctfapp/models/instance.py`
- Create: `ctfapp/models/submission.py`
- Create: `ctfapp/models/event_log.py`

- [ ] **Step 1: Create models/__init__.py**

```python
from ctfapp.extensions import db

from .user import User, TeamMember
from .team import Team
from .principal import Principal
from .challenge import Challenge, ChallengeFile
from .instance import Instance
from .submission import Submission, Solve, ScoreEvent, TeamFlag
from .event_log import EventLog

__all__ = [
    "db",
    "User",
    "TeamMember",
    "Team",
    "Principal",
    "Challenge",
    "ChallengeFile",
    "Instance",
    "Submission",
    "Solve",
    "ScoreEvent",
    "TeamFlag",
    "EventLog",
]
```

- [ ] **Step 2: Create models/user.py**

```python
import uuid
from datetime import datetime, timezone

from flask_login import UserMixin

from ctfapp.extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    state = db.Column(db.String(20), default="active", nullable=False)
    email_verified_at = db.Column(db.DateTime(timezone=True), nullable=True)
    totp_secret = db.Column(db.String(64), nullable=True)  # 2FA scaffold
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    team_memberships = db.relationship(
        "TeamMember", back_populates="user", lazy="select"
    )
    principal = db.relationship(
        "Principal",
        back_populates="user",
        uselist=False,
        foreign_keys="Principal.user_id",
    )

    def __repr__(self):
        return f"<User {self.username}>"


class TeamMember(db.Model):
    __tablename__ = "team_members"
    __table_args__ = (
        db.UniqueConstraint("team_id", "user_id", name="uq_team_user"),
    )

    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    role = db.Column(db.String(20), default="member", nullable=False)  # captain|member
    joined_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    active = db.Column(db.Boolean, default=True, nullable=False)

    team = db.relationship("Team", back_populates="members")
    user = db.relationship("User", back_populates="team_memberships")
```

- [ ] **Step 3: Create models/team.py**

```python
import secrets
import uuid
from datetime import datetime, timezone

from ctfapp.extensions import db


class Team(db.Model):
    __tablename__ = "teams"

    id = db.Column(db.Integer, primary_key=True)
    team_uid = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    name = db.Column(db.String(80), unique=True, nullable=False, index=True)
    join_token = db.Column(
        db.String(16),
        unique=True,
        nullable=False,
        default=lambda: secrets.token_urlsafe(12),
    )
    captain_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False
    )
    max_size = db.Column(db.Integer, default=4, nullable=False)
    state = db.Column(db.String(20), default="active", nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    captain = db.relationship("User", foreign_keys=[captain_user_id])
    members = db.relationship("TeamMember", back_populates="team", lazy="select")
    principal = db.relationship(
        "Principal",
        back_populates="team",
        uselist=False,
        foreign_keys="Principal.team_id",
    )

    @property
    def member_count(self):
        return len([m for m in self.members if m.active])

    @property
    def is_full(self):
        return self.member_count >= self.max_size

    def __repr__(self):
        return f"<Team {self.name}>"
```

- [ ] **Step 4: Create models/principal.py**

```python
import os
import uuid
from datetime import datetime, timezone

from ctfapp.extensions import db


class Principal(db.Model):
    __tablename__ = "principals"

    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(10), nullable=False)  # "team" or "solo"
    public_id = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    team_secret = db.Column(db.LargeBinary(32), nullable=False, default=lambda: os.urandom(32))
    team_id = db.Column(
        db.Integer, db.ForeignKey("teams.id"), nullable=True, unique=True
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True, unique=True
    )
    score_total = db.Column(db.Integer, default=0, nullable=False)
    last_solve_at = db.Column(db.DateTime(timezone=True), nullable=True)
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    team = db.relationship("Team", back_populates="principal", foreign_keys=[team_id])
    user = db.relationship("User", back_populates="principal", foreign_keys=[user_id])
    solves = db.relationship("Solve", back_populates="principal", lazy="dynamic")
    submissions = db.relationship(
        "Submission", back_populates="principal", lazy="dynamic"
    )

    @property
    def display_name(self):
        if self.kind == "team" and self.team:
            return self.team.name
        if self.kind == "solo" and self.user:
            return self.user.username
        return f"Principal-{self.public_id[:8]}"

    def __repr__(self):
        return f"<Principal {self.kind}:{self.display_name}>"
```

- [ ] **Step 5: Create models/challenge.py**

```python
from datetime import datetime, timezone

from ctfapp.extensions import db


class Challenge(db.Model):
    __tablename__ = "challenges"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(120), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    category_slug = db.Column(db.String(40), nullable=False, index=True)
    description_md = db.Column(db.Text, nullable=False, default="")
    points = db.Column(db.Integer, nullable=False)
    # No flag column — flags derived from ADMIN_KEY + principal.team_secret + challenge.id
    flag_type = db.Column(
        db.String(20), default="derived", nullable=False
    )  # derived | dynamic
    is_dynamic = db.Column(db.Boolean, default=False, nullable=False)
    container_image = db.Column(db.String(255), nullable=True)
    container_port = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(20), default="hidden", nullable=False)  # hidden|visible
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    files = db.relationship("ChallengeFile", back_populates="challenge", lazy="select")
    submissions = db.relationship(
        "Submission", back_populates="challenge", lazy="dynamic"
    )

    @property
    def solve_count(self):
        from ctfapp.models.submission import Solve
        return Solve.query.filter_by(challenge_id=self.id).count()

    def __repr__(self):
        return f"<Challenge {self.slug}>"


class ChallengeFile(db.Model):
    __tablename__ = "challenge_files"

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"), nullable=False
    )
    filename = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(512), nullable=False)
    size = db.Column(db.Integer, default=0)
    checksum = db.Column(db.String(64), nullable=True)

    challenge = db.relationship("Challenge", back_populates="files")
```

- [ ] **Step 6: Create models/instance.py**

```python
from datetime import datetime, timezone

from ctfapp.extensions import db


class Instance(db.Model):
    __tablename__ = "instances"

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"), nullable=False
    )
    principal_id = db.Column(
        db.Integer, db.ForeignKey("principals.id", ondelete="CASCADE"), nullable=False
    )
    subdomain = db.Column(db.String(120), unique=True, nullable=False)
    container_id = db.Column(db.String(80), nullable=True)
    flag_override = db.Column(db.String(255), nullable=True)  # for dynamic flag_type
    spawned_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    status = db.Column(db.String(20), default="running", nullable=False)

    challenge = db.relationship("Challenge")
    principal = db.relationship("Principal")

    __table_args__ = (
        db.UniqueConstraint(
            "challenge_id", "principal_id", name="uq_instance_chal_principal"
        ),
    )
```

- [ ] **Step 7: Create models/submission.py**

```python
import hashlib
from datetime import datetime, timezone

from ctfapp.extensions import db


class Submission(db.Model):
    __tablename__ = "submissions"

    id = db.Column(db.Integer, primary_key=True)
    principal_id = db.Column(
        db.Integer, db.ForeignKey("principals.id"), nullable=False, index=True
    )
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id"), nullable=False, index=True
    )
    flag_submitted_hash = db.Column(db.String(64), nullable=False)
    result = db.Column(db.String(10), nullable=False)  # correct | wrong
    ip = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(512), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    principal = db.relationship("Principal", back_populates="submissions")
    challenge = db.relationship("Challenge", back_populates="submissions")

    @staticmethod
    def hash_flag(raw_flag: str) -> str:
        return hashlib.sha256(raw_flag.encode()).hexdigest()


class Solve(db.Model):
    __tablename__ = "solves"
    __table_args__ = (
        db.UniqueConstraint(
            "principal_id", "challenge_id", name="uq_solve_principal_challenge"
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    principal_id = db.Column(
        db.Integer, db.ForeignKey("principals.id"), nullable=False, index=True
    )
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id"), nullable=False, index=True
    )
    points_awarded = db.Column(db.Integer, nullable=False)
    solved_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    principal = db.relationship("Principal", back_populates="solves")
    challenge = db.relationship("Challenge")


class ScoreEvent(db.Model):
    __tablename__ = "score_events"

    id = db.Column(db.Integer, primary_key=True)
    principal_id = db.Column(
        db.Integer, db.ForeignKey("principals.id"), nullable=False, index=True
    )
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id"), nullable=True
    )
    delta = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class TeamFlag(db.Model):
    """Durable mirror of Redis team_flags hash."""

    __tablename__ = "team_flags"
    __table_args__ = (
        db.UniqueConstraint(
            "principal_id", "challenge_id", name="uq_teamflag_principal_challenge"
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    principal_id = db.Column(
        db.Integer, db.ForeignKey("principals.id"), nullable=False, index=True
    )
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id"), nullable=False, index=True
    )
    flag_value = db.Column(db.String(255), nullable=False)
```

- [ ] **Step 8: Create models/event_log.py**

```python
from datetime import datetime, timezone

from ctfapp.extensions import db


class EventLog(db.Model):
    __tablename__ = "event_log"

    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(60), nullable=False, index=True)
    severity = db.Column(
        db.String(10), default="INFO", nullable=False
    )  # INFO|WARNING|CRITICAL
    actor_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True
    )
    principal_id = db.Column(
        db.Integer, db.ForeignKey("principals.id"), nullable=True
    )
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id"), nullable=True
    )
    payload_json = db.Column(db.Text, nullable=True)
    prev_sig = db.Column(db.String(64), nullable=True)
    sig = db.Column(db.String(64), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
```

- [ ] **Step 9: Commit**

```bash
git add ctfapp/models/
git commit -m "feat: add all database models (user, team, principal, challenge, submission, event_log)"
```

---

## Task 5: App factory (__init__.py)

**Files:**
- Modify: `ctfapp/__init__.py`
- Modify: `wsgi.py`
- Modify: `ctfapp/secure_log.py`

- [ ] **Step 1: Write complete __init__.py**

```python
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import get_config
from .errors import register_error_handlers
from .extensions import cache, csrf, db, init_redis, limiter, login_manager, migrate
from .secure_log import init_audit_log


def create_app(config_obj=None):
    if config_obj is None:
        config_obj = get_config()

    app = Flask(__name__)
    app.config.from_object(config_obj)

    # Proxy fix
    if app.config.get("TRUST_PROXY"):
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=app.config.get("PROXY_FIX_X_FOR", 1),
            x_proto=app.config.get("PROXY_FIX_X_PROTO", 1),
            x_host=app.config.get("PROXY_FIX_X_HOST", 0),
            x_prefix=app.config.get("PROXY_FIX_X_PREFIX", 0),
        )

    # Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    cache.init_app(app, config={"CACHE_TYPE": "SimpleCache"})
    limiter.init_app(app)
    login_manager.init_app(app)
    init_redis(app)

    # User loader for flask-login
    from .models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Register security headers
    if app.config.get("SECURE_HEADERS_ENABLED", True):
        from .security import register_security_headers
        register_security_headers(app)

    # Register error handlers
    register_error_handlers(app)

    # Register blueprints
    from .blueprints.auth import auth_bp
    from .blueprints.challenges import challenges_bp
    from .blueprints.scoreboard import scoreboard_bp
    from .blueprints.team import team_bp
    from .blueprints.admin import admin_bp
    from .blueprints.dispatch import dispatch_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(challenges_bp)
    app.register_blueprint(scoreboard_bp)
    app.register_blueprint(team_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(dispatch_bp)

    # Init audit log
    init_audit_log(app)

    return app
```

- [ ] **Step 2: Write wsgi.py**

```python
from ctfapp import create_app

app = create_app()

if __name__ == "__main__":
    app.run()
```

- [ ] **Step 3: Write secure_log.py with chained HMAC**

```python
import hashlib
import hmac
import json
from datetime import datetime, timezone

_last_sig = "0" * 64  # genesis signature


def init_audit_log(app=None):
    """Initialize audit log. Loads last sig from DB if available."""
    global _last_sig
    if app is None:
        return
    with app.app_context():
        from ctfapp.extensions import db
        from ctfapp.models.event_log import EventLog

        last = EventLog.query.order_by(EventLog.id.desc()).first()
        if last:
            _last_sig = last.sig


def write_event(
    event_type: str,
    severity: str = "INFO",
    actor_user_id: int | None = None,
    principal_id: int | None = None,
    challenge_id: int | None = None,
    payload: dict | None = None,
) -> None:
    """Write a tamper-evident event to the event_log."""
    global _last_sig
    from flask import current_app

    from ctfapp.extensions import db
    from ctfapp.models.event_log import EventLog

    payload_str = json.dumps(payload, sort_keys=True, default=str) if payload else None
    now = datetime.now(timezone.utc).isoformat()

    # Build the chain: HMAC(admin_key, prev_sig + type + timestamp + payload)
    admin_key = current_app.config["ADMIN_KEY"]
    message = f"{_last_sig}|{event_type}|{now}|{payload_str or ''}"
    sig = hmac.new(admin_key, message.encode(), hashlib.sha256).hexdigest()

    entry = EventLog(
        type=event_type,
        severity=severity,
        actor_user_id=actor_user_id,
        principal_id=principal_id,
        challenge_id=challenge_id,
        payload_json=payload_str,
        prev_sig=_last_sig,
        sig=sig,
    )
    db.session.add(entry)
    db.session.commit()

    _last_sig = sig
```

- [ ] **Step 4: Commit**

```bash
git add ctfapp/__init__.py wsgi.py ctfapp/secure_log.py
git commit -m "feat: wire app factory, wsgi entry point, chained HMAC audit log"
```

---

## Task 6: Flag Engine Service

**Files:**
- Create: `ctfapp/services/__init__.py`
- Create: `ctfapp/services/flag_engine.py`
- Create: `tests/conftest.py`
- Create: `tests/test_flag_engine.py`

- [ ] **Step 1: Create services/__init__.py**

```python
# Services package
```

- [ ] **Step 2: Write the failing test for flag derivation**

Create `tests/conftest.py`:

```python
import pytest

from ctfapp import create_app
from ctfapp.config import TestingConfig
from ctfapp.extensions import db as _db


@pytest.fixture(scope="session")
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db_session(app):
    with app.app_context():
        _db.session.begin_nested()
        yield _db.session
        _db.session.rollback()
```

Create `tests/test_flag_engine.py`:

```python
import os

from ctfapp.services.flag_engine import derive_flag, verify_flag, generate_flags_for_principal


def test_derive_flag_format():
    admin_key = b"test-admin-key-32-bytes-long!!!!!"
    team_secret = os.urandom(32)
    flag = derive_flag(admin_key, team_secret, challenge_id=1)
    assert flag.startswith("GRIZZ{")
    assert flag.endswith("}")
    assert len(flag) == 6 + 32 + 1  # GRIZZ{ + 32 hex + }


def test_derive_flag_deterministic():
    admin_key = b"test-admin-key-32-bytes-long!!!!!"
    team_secret = b"\x01" * 32
    flag1 = derive_flag(admin_key, team_secret, challenge_id=42)
    flag2 = derive_flag(admin_key, team_secret, challenge_id=42)
    assert flag1 == flag2


def test_derive_flag_unique_per_team():
    admin_key = b"test-admin-key-32-bytes-long!!!!!"
    secret_a = b"\x01" * 32
    secret_b = b"\x02" * 32
    flag_a = derive_flag(admin_key, secret_a, challenge_id=1)
    flag_b = derive_flag(admin_key, secret_b, challenge_id=1)
    assert flag_a != flag_b


def test_derive_flag_unique_per_challenge():
    admin_key = b"test-admin-key-32-bytes-long!!!!!"
    team_secret = b"\x01" * 32
    flag1 = derive_flag(admin_key, team_secret, challenge_id=1)
    flag2 = derive_flag(admin_key, team_secret, challenge_id=2)
    assert flag1 != flag2


def test_verify_flag_correct():
    admin_key = b"test-admin-key-32-bytes-long!!!!!"
    team_secret = b"\x01" * 32
    flag = derive_flag(admin_key, team_secret, challenge_id=5)
    assert verify_flag(flag, admin_key, team_secret, challenge_id=5) is True


def test_verify_flag_wrong():
    admin_key = b"test-admin-key-32-bytes-long!!!!!"
    team_secret = b"\x01" * 32
    assert verify_flag("GRIZZ{wrong}", admin_key, team_secret, challenge_id=5) is False


def test_verify_flag_strips_whitespace():
    admin_key = b"test-admin-key-32-bytes-long!!!!!"
    team_secret = b"\x01" * 32
    flag = derive_flag(admin_key, team_secret, challenge_id=5)
    assert verify_flag(f"  {flag}  \n", admin_key, team_secret, challenge_id=5) is True


def test_generate_flags_for_principal(app, db_session):
    from ctfapp.models import Principal, Challenge, TeamFlag

    # Create test data
    principal = Principal(kind="solo", team_secret=b"\xaa" * 32)
    db_session.add(principal)
    chal1 = Challenge(slug="test-1", title="Test 1", category_slug="crypto", points=100, status="visible")
    chal2 = Challenge(slug="test-2", title="Test 2", category_slug="web", points=200, status="visible")
    chal_hidden = Challenge(slug="test-hidden", title="Hidden", category_slug="misc", points=50, status="hidden")
    db_session.add_all([chal1, chal2, chal_hidden])
    db_session.flush()

    generate_flags_for_principal(principal)

    flags = TeamFlag.query.filter_by(principal_id=principal.id).all()
    # Only visible challenges get flags
    assert len(flags) == 2
    assert all(f.flag_value.startswith("GRIZZ{") for f in flags)
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /home/supasuge/CTF-THM-HTB/Grizzhacks8-CTF/CTF_UI && uv run pytest tests/test_flag_engine.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ctfapp.services.flag_engine'`

- [ ] **Step 4: Implement flag_engine.py**

```python
import hmac
import hashlib

from flask import current_app

from ctfapp.extensions import db, get_redis
from ctfapp.models.submission import TeamFlag


def derive_flag(admin_key: bytes, team_secret: bytes, challenge_id: int) -> str:
    """Derive a per-principal, per-challenge flag using HMAC-SHA3-256."""
    msg = team_secret + challenge_id.to_bytes(4, "big")
    digest = hmac.new(admin_key, msg, hashlib.sha3_256).hexdigest()
    return f"GRIZZ{{{digest[:32]}}}"


def verify_flag(
    submitted: str,
    admin_key: bytes,
    team_secret: bytes,
    challenge_id: int,
) -> bool:
    """Constant-time verify a submitted flag against the derived expected value."""
    expected = derive_flag(admin_key, team_secret, challenge_id)
    return hmac.compare_digest(submitted.strip(), expected)


def generate_flags_for_principal(principal) -> list[TeamFlag]:
    """Pre-generate flags for all visible challenges for a principal.

    Stores in DB (TeamFlag) and Redis (HSET team_flags:<principal_id>).
    """
    from ctfapp.models.challenge import Challenge

    admin_key = current_app.config["ADMIN_KEY"]
    challenges = Challenge.query.filter_by(status="visible").all()
    created = []

    for chal in challenges:
        flag_value = derive_flag(admin_key, principal.team_secret, chal.id)

        existing = TeamFlag.query.filter_by(
            principal_id=principal.id, challenge_id=chal.id
        ).first()
        if existing:
            existing.flag_value = flag_value
        else:
            tf = TeamFlag(
                principal_id=principal.id,
                challenge_id=chal.id,
                flag_value=flag_value,
            )
            db.session.add(tf)
            created.append(tf)

    db.session.flush()

    # Mirror to Redis
    try:
        r = get_redis()
        key = f"team_flags:{principal.id}"
        pipe = r.pipeline()
        for chal in challenges:
            flag_value = derive_flag(admin_key, principal.team_secret, chal.id)
            pipe.hset(key, str(chal.id), flag_value)
        pipe.execute()
    except Exception:
        pass  # Redis optional — DB is source of truth

    return created


def generate_flags_for_challenge(challenge) -> None:
    """When admin adds a new challenge, generate flags for all existing principals."""
    from ctfapp.models.principal import Principal

    admin_key = current_app.config["ADMIN_KEY"]
    principals = Principal.query.filter_by(active=True).all()

    for principal in principals:
        flag_value = derive_flag(admin_key, principal.team_secret, challenge.id)
        existing = TeamFlag.query.filter_by(
            principal_id=principal.id, challenge_id=challenge.id
        ).first()
        if not existing:
            db.session.add(
                TeamFlag(
                    principal_id=principal.id,
                    challenge_id=challenge.id,
                    flag_value=flag_value,
                )
            )

    db.session.flush()

    # Mirror to Redis
    try:
        r = get_redis()
        pipe = r.pipeline()
        for principal in principals:
            flag_value = derive_flag(admin_key, principal.team_secret, challenge.id)
            pipe.hset(f"team_flags:{principal.id}", str(challenge.id), flag_value)
        pipe.execute()
    except Exception:
        pass


def get_flag_for_principal(principal_id: int, challenge_id: int) -> str | None:
    """Lookup flag from Redis (fast) or DB (fallback)."""
    try:
        r = get_redis()
        flag = r.hget(f"team_flags:{principal_id}", str(challenge_id))
        if flag:
            return flag
    except Exception:
        pass

    tf = TeamFlag.query.filter_by(
        principal_id=principal_id, challenge_id=challenge_id
    ).first()
    return tf.flag_value if tf else None
```

- [ ] **Step 5: Run tests**

Run: `cd /home/supasuge/CTF-THM-HTB/Grizzhacks8-CTF/CTF_UI && uv run pytest tests/test_flag_engine.py -v`
Expected: All 8 tests PASS

- [ ] **Step 6: Commit**

```bash
git add ctfapp/services/ tests/
git commit -m "feat: HMAC-SHA3-256 flag engine with per-principal derivation + tests"
```

---

## Task 7: Anti-Cheat Service

**Files:**
- Create: `ctfapp/services/anticheat.py`
- Create: `tests/test_anticheat.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_anticheat.py`:

```python
import os

from ctfapp.services.anticheat import check_flag_sharing, check_rate_limit


def test_check_flag_sharing_detects_share(app, db_session):
    from ctfapp.models import Principal, Challenge, TeamFlag

    admin_key = app.config["ADMIN_KEY"]

    p1 = Principal(kind="solo", team_secret=os.urandom(32))
    p2 = Principal(kind="solo", team_secret=os.urandom(32))
    db_session.add_all([p1, p2])
    chal = Challenge(slug="share-test", title="Share Test", category_slug="crypto", points=100, status="visible")
    db_session.add(chal)
    db_session.flush()

    from ctfapp.services.flag_engine import derive_flag

    tf1 = TeamFlag(principal_id=p1.id, challenge_id=chal.id,
                   flag_value=derive_flag(admin_key, p1.team_secret, chal.id))
    tf2 = TeamFlag(principal_id=p2.id, challenge_id=chal.id,
                   flag_value=derive_flag(admin_key, p2.team_secret, chal.id))
    db_session.add_all([tf1, tf2])
    db_session.flush()

    # p2 submits p1's flag — flag sharing!
    result = check_flag_sharing(p2.id, chal.id, tf1.flag_value)
    assert result is not None
    assert result["shared_from_principal_id"] == p1.id


def test_check_flag_sharing_no_match(app, db_session):
    from ctfapp.models import Principal, Challenge, TeamFlag
    from ctfapp.services.flag_engine import derive_flag

    admin_key = app.config["ADMIN_KEY"]
    p1 = Principal(kind="solo", team_secret=os.urandom(32))
    db_session.add(p1)
    chal = Challenge(slug="noshare-test", title="No Share", category_slug="web", points=200, status="visible")
    db_session.add(chal)
    db_session.flush()
    tf = TeamFlag(principal_id=p1.id, challenge_id=chal.id,
                  flag_value=derive_flag(admin_key, p1.team_secret, chal.id))
    db_session.add(tf)
    db_session.flush()

    result = check_flag_sharing(p1.id, chal.id, "GRIZZ{totally_wrong_flag}")
    assert result is None


def test_rate_limit_allows_first_attempts(app):
    # Without Redis in tests, rate limit falls back to allow
    allowed, remaining, retry_after = check_rate_limit(999, 1)
    assert allowed is True


def test_rate_limit_blocks_after_threshold(app):
    from ctfapp.extensions import get_redis

    try:
        r = get_redis()
    except RuntimeError:
        return  # No Redis in tests, skip

    # Simulate 3 wrong attempts
    for _ in range(3):
        allowed, _, _ = check_rate_limit(888, 1)
    allowed, remaining, retry_after = check_rate_limit(888, 1)
    assert allowed is False
    assert retry_after > 0
```

- [ ] **Step 2: Run to verify failure**

Run: `cd /home/supasuge/CTF-THM-HTB/Grizzhacks8-CTF/CTF_UI && uv run pytest tests/test_anticheat.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement anticheat.py**

```python
import hmac

from flask import current_app

from ctfapp.models.submission import TeamFlag
from ctfapp.secure_log import write_event


def check_flag_sharing(
    submitting_principal_id: int,
    challenge_id: int,
    submitted_flag: str,
) -> dict | None:
    """Check if a wrong flag matches another principal's derived flag.

    Returns dict with sharing details if detected, None otherwise.
    """
    other_flags = (
        TeamFlag.query
        .filter_by(challenge_id=challenge_id)
        .filter(TeamFlag.principal_id != submitting_principal_id)
        .all()
    )

    for tf in other_flags:
        if hmac.compare_digest(submitted_flag.strip(), tf.flag_value):
            write_event(
                event_type="FLAG_SHARE_DETECTED",
                severity="CRITICAL",
                principal_id=submitting_principal_id,
                challenge_id=challenge_id,
                payload={
                    "shared_from_principal_id": tf.principal_id,
                    "submitting_principal_id": submitting_principal_id,
                },
            )
            return {
                "shared_from_principal_id": tf.principal_id,
                "submitting_principal_id": submitting_principal_id,
            }

    return None


def check_rate_limit(
    principal_id: int, challenge_id: int
) -> tuple[bool, int, int]:
    """Check submission rate limit (3 wrong in window = 30s lockout).

    Returns (allowed, remaining_attempts, retry_after_seconds).
    """
    from ctfapp.extensions import get_redis

    limit = current_app.config.get("FLAG_WRONG_LIMIT", 3)
    lockout = current_app.config.get("FLAG_LOCKOUT_SECONDS", 30)

    try:
        r = get_redis()
    except RuntimeError:
        return True, limit, 0  # No Redis → allow (dev mode)

    lockout_key = f"lockout:{principal_id}:{challenge_id}"
    counter_key = f"wrong_count:{principal_id}:{challenge_id}"

    # Check lockout
    ttl = r.ttl(lockout_key)
    if ttl and ttl > 0:
        return False, 0, ttl

    # Check counter
    count = int(r.get(counter_key) or 0)
    if count >= limit:
        r.setex(lockout_key, lockout, "1")
        r.delete(counter_key)
        return False, 0, lockout

    return True, limit - count, 0


def record_wrong_attempt(principal_id: int, challenge_id: int) -> None:
    """Increment wrong-attempt counter in Redis."""
    from ctfapp.extensions import get_redis

    lockout = current_app.config.get("FLAG_LOCKOUT_SECONDS", 30)

    try:
        r = get_redis()
        counter_key = f"wrong_count:{principal_id}:{challenge_id}"
        pipe = r.pipeline()
        pipe.incr(counter_key)
        pipe.expire(counter_key, lockout)
        pipe.execute()
    except RuntimeError:
        pass


def clear_attempts(principal_id: int, challenge_id: int) -> None:
    """Clear wrong-attempt counter (called on correct solve)."""
    from ctfapp.extensions import get_redis

    try:
        r = get_redis()
        r.delete(f"wrong_count:{principal_id}:{challenge_id}")
        r.delete(f"lockout:{principal_id}:{challenge_id}")
    except RuntimeError:
        pass
```

- [ ] **Step 4: Run tests**

Run: `cd /home/supasuge/CTF-THM-HTB/Grizzhacks8-CTF/CTF_UI && uv run pytest tests/test_anticheat.py -v`
Expected: PASS (at least the DB-based tests; Redis tests may skip gracefully)

- [ ] **Step 5: Commit**

```bash
git add ctfapp/services/anticheat.py tests/test_anticheat.py
git commit -m "feat: anti-cheat engine — flag sharing detection + rate limiting"
```

---

## Task 8: Auth Service + Blueprint

**Files:**
- Create: `ctfapp/services/auth_service.py`
- Create: `ctfapp/blueprints/__init__.py`
- Create: `ctfapp/blueprints/auth/__init__.py`
- Create: `ctfapp/blueprints/auth/routes.py`
- Create: `ctfapp/blueprints/auth/forms.py`

- [ ] **Step 1: Create auth_service.py**

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from ctfapp.extensions import db
from ctfapp.models.principal import Principal
from ctfapp.models.user import User
from ctfapp.services.flag_engine import generate_flags_for_principal

ph = PasswordHasher()


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def register_user(
    username: str,
    email: str,
    password: str,
    mode: str = "solo",
) -> User:
    """Register a new user and create their solo principal if mode=solo."""
    user = User(
        username=username,
        email=email.lower().strip(),
        password_hash=hash_password(password),
    )
    db.session.add(user)
    db.session.flush()

    if mode == "solo":
        principal = Principal(kind="solo", user_id=user.id)
        db.session.add(principal)
        db.session.flush()
        generate_flags_for_principal(principal)

    db.session.commit()
    return user
```

- [ ] **Step 2: Create blueprints/__init__.py**

```python
# Blueprints package
```

- [ ] **Step 3: Create auth forms**

Create `ctfapp/blueprints/auth/__init__.py`:

```python
from flask import Blueprint

auth_bp = Blueprint("auth", __name__, url_prefix="/auth", template_folder="templates")

from . import routes  # noqa: E402, F401
```

Create `ctfapp/blueprints/auth/forms.py`:

```python
from flask_wtf import FlaskForm
from wtforms import (
    PasswordField,
    RadioField,
    StringField,
    SubmitField,
)
from wtforms.validators import DataRequired, Email, EqualTo, Length


class RegisterForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=3, max=80)]
    )
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField(
        "Password", validators=[DataRequired(), Length(min=8, max=128)]
    )
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    mode = RadioField(
        "Play Mode",
        choices=[("solo", "Solo"), ("team", "Join/Create Team")],
        default="solo",
    )
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")
```

- [ ] **Step 4: Create auth routes**

Create `ctfapp/blueprints/auth/routes.py`:

```python
from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from ctfapp.extensions import db
from ctfapp.models.user import User
from ctfapp.secure_log import write_event
from ctfapp.services.auth_service import register_user, verify_password

from .forms import LoginForm, RegisterForm


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("challenges.list_challenges"))

    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already taken.", "danger")
            return render_template("auth/register.html", form=form)
        if User.query.filter_by(email=form.email.data.lower().strip()).first():
            flash("Email already registered.", "danger")
            return render_template("auth/register.html", form=form)

        user = register_user(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            mode=form.mode.data,
        )
        write_event("USER_REGISTERED", actor_user_id=user.id, payload={"mode": form.mode.data})
        login_user(user)
        flash("Welcome to GrizzHacks8 CTF!", "success")

        if form.mode.data == "team":
            return redirect(url_for("team.create_or_join"))
        return redirect(url_for("challenges.list_challenges"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("challenges.list_challenges"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and verify_password(user.password_hash, form.password.data):
            login_user(user, remember=True)
            write_event("USER_LOGIN", actor_user_id=user.id)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("challenges.list_challenges"))
        flash("Invalid username or password.", "danger")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    write_event("USER_LOGOUT", actor_user_id=current_user.id)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


# Fix circular import — auth_bp used as decorator target above
from ctfapp.blueprints.auth import auth_bp  # noqa: E402
```

Wait — the routes file uses `auth_bp` as a decorator but it's defined in `__init__.py`. Fix the import order:

Replace `ctfapp/blueprints/auth/routes.py` — the `auth_bp` import should come from the `__init__.py`. Update the routes to use a proper pattern:

```python
from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from ctfapp.extensions import db
from ctfapp.models.user import User
from ctfapp.secure_log import write_event
from ctfapp.services.auth_service import register_user, verify_password

from . import auth_bp
from .forms import LoginForm, RegisterForm


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("challenges.list_challenges"))

    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already taken.", "danger")
            return render_template("auth/register.html", form=form)
        if User.query.filter_by(email=form.email.data.lower().strip()).first():
            flash("Email already registered.", "danger")
            return render_template("auth/register.html", form=form)

        user = register_user(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            mode=form.mode.data,
        )
        write_event("USER_REGISTERED", actor_user_id=user.id, payload={"mode": form.mode.data})
        login_user(user)
        flash("Welcome to GrizzHacks8 CTF!", "success")

        if form.mode.data == "team":
            return redirect(url_for("team.create_or_join"))
        return redirect(url_for("challenges.list_challenges"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("challenges.list_challenges"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and verify_password(user.password_hash, form.password.data):
            login_user(user, remember=True)
            write_event("USER_LOGIN", actor_user_id=user.id)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("challenges.list_challenges"))
        flash("Invalid username or password.", "danger")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    write_event("USER_LOGOUT", actor_user_id=current_user.id)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
```

- [ ] **Step 5: Commit**

```bash
git add ctfapp/services/auth_service.py ctfapp/blueprints/
git commit -m "feat: auth service (argon2 hashing) + auth blueprint (register/login/logout)"
```

---

## Task 9: Team Blueprint

**Files:**
- Create: `ctfapp/blueprints/team/__init__.py`
- Create: `ctfapp/blueprints/team/routes.py`
- Create: `ctfapp/blueprints/team/forms.py`

- [ ] **Step 1: Create team blueprint**

Create `ctfapp/blueprints/team/__init__.py`:

```python
from flask import Blueprint

team_bp = Blueprint("team", __name__, url_prefix="/team", template_folder="templates")

from . import routes  # noqa: E402, F401
```

Create `ctfapp/blueprints/team/forms.py`:

```python
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class CreateTeamForm(FlaskForm):
    name = StringField("Team Name", validators=[DataRequired(), Length(min=2, max=80)])
    submit = SubmitField("Create Team")


class JoinTeamForm(FlaskForm):
    join_token = StringField("Join Token", validators=[DataRequired(), Length(min=8, max=32)])
    submit = SubmitField("Join Team")
```

Create `ctfapp/blueprints/team/routes.py`:

```python
from flask import flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from ctfapp.extensions import db
from ctfapp.models.principal import Principal
from ctfapp.models.team import Team
from ctfapp.models.user import TeamMember
from ctfapp.secure_log import write_event
from ctfapp.services.flag_engine import generate_flags_for_principal

from . import team_bp
from .forms import CreateTeamForm, JoinTeamForm


@team_bp.route("/", methods=["GET"])
@login_required
def create_or_join():
    create_form = CreateTeamForm(prefix="create")
    join_form = JoinTeamForm(prefix="join")
    return render_template(
        "team/create.html", create_form=create_form, join_form=join_form
    )


@team_bp.route("/create", methods=["POST"])
@login_required
def create_team():
    form = CreateTeamForm(prefix="create")
    if form.validate_on_submit():
        if Team.query.filter_by(name=form.name.data).first():
            flash("Team name already taken.", "danger")
            return redirect(url_for("team.create_or_join"))

        team = Team(name=form.name.data, captain_user_id=current_user.id)
        db.session.add(team)
        db.session.flush()

        membership = TeamMember(
            team_id=team.id, user_id=current_user.id, role="captain"
        )
        db.session.add(membership)

        principal = Principal(kind="team", team_id=team.id)
        db.session.add(principal)
        db.session.flush()

        generate_flags_for_principal(principal)
        db.session.commit()

        write_event(
            "TEAM_CREATED",
            actor_user_id=current_user.id,
            principal_id=principal.id,
            payload={"team_name": team.name},
        )
        flash(f"Team '{team.name}' created! Share join token: {team.join_token}", "success")
        return redirect(url_for("team.manage"))

    flash("Invalid team name.", "danger")
    return redirect(url_for("team.create_or_join"))


@team_bp.route("/join", methods=["POST"])
@login_required
def join_team():
    form = JoinTeamForm(prefix="join")
    if form.validate_on_submit():
        team = Team.query.filter_by(join_token=form.join_token.data).first()
        if not team:
            flash("Invalid join token.", "danger")
            return redirect(url_for("team.create_or_join"))
        if team.is_full:
            flash("Team is full.", "danger")
            return redirect(url_for("team.create_or_join"))

        existing = TeamMember.query.filter_by(
            team_id=team.id, user_id=current_user.id
        ).first()
        if existing:
            flash("You're already on this team.", "info")
            return redirect(url_for("team.manage"))

        membership = TeamMember(
            team_id=team.id, user_id=current_user.id, role="member"
        )
        db.session.add(membership)
        db.session.commit()

        write_event(
            "TEAM_JOINED",
            actor_user_id=current_user.id,
            payload={"team_name": team.name},
        )
        flash(f"Joined team '{team.name}'!", "success")
        return redirect(url_for("team.manage"))

    flash("Invalid join token.", "danger")
    return redirect(url_for("team.create_or_join"))


@team_bp.route("/manage")
@login_required
def manage():
    membership = TeamMember.query.filter_by(
        user_id=current_user.id, active=True
    ).first()
    if not membership:
        return redirect(url_for("team.create_or_join"))

    team = membership.team
    members = TeamMember.query.filter_by(team_id=team.id, active=True).all()
    return render_template("team/manage.html", team=team, members=members, membership=membership)
```

- [ ] **Step 2: Commit**

```bash
git add ctfapp/blueprints/team/
git commit -m "feat: team blueprint — create, join via token, manage members"
```

---

## Task 10: Challenges Blueprint

**Files:**
- Create: `ctfapp/blueprints/challenges/__init__.py`
- Create: `ctfapp/blueprints/challenges/routes.py`
- Create: `ctfapp/blueprints/challenges/forms.py`
- Create: `ctfapp/services/event_service.py`

- [ ] **Step 1: Create challenges blueprint**

Create `ctfapp/blueprints/challenges/__init__.py`:

```python
from flask import Blueprint

challenges_bp = Blueprint(
    "challenges", __name__, url_prefix="/challenges", template_folder="templates"
)

from . import routes  # noqa: E402, F401
```

Create `ctfapp/blueprints/challenges/forms.py`:

```python
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class FlagSubmitForm(FlaskForm):
    flag = StringField("Flag", validators=[DataRequired(), Length(max=255)])
    submit = SubmitField("Submit Flag")
```

- [ ] **Step 2: Create event_service.py (helper for getting principal)**

```python
from flask_login import current_user

from ctfapp.models.principal import Principal
from ctfapp.models.user import TeamMember


def get_current_principal() -> Principal | None:
    """Get the scoring principal for the current user.

    Solo users → their solo principal.
    Team users → the team principal.
    """
    if not current_user.is_authenticated:
        return None

    # Check solo principal first
    solo = Principal.query.filter_by(user_id=current_user.id, kind="solo").first()
    if solo:
        return solo

    # Check team membership
    membership = TeamMember.query.filter_by(
        user_id=current_user.id, active=True
    ).first()
    if membership and membership.team and membership.team.principal:
        return membership.team.principal

    return None
```

- [ ] **Step 3: Create challenges routes**

Create `ctfapp/blueprints/challenges/routes.py`:

```python
import hmac

from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ctfapp.extensions import db
from ctfapp.models.challenge import Challenge
from ctfapp.models.submission import Solve, ScoreEvent, Submission
from ctfapp.secure_log import write_event
from ctfapp.services.anticheat import (
    check_flag_sharing,
    check_rate_limit,
    clear_attempts,
    record_wrong_attempt,
)
from ctfapp.services.event_service import get_current_principal
from ctfapp.services.flag_engine import get_flag_for_principal

from . import challenges_bp
from .forms import FlagSubmitForm


@challenges_bp.route("/")
@login_required
def list_challenges():
    principal = get_current_principal()
    challenges = Challenge.query.filter_by(status="visible").order_by(
        Challenge.category_slug, Challenge.points
    ).all()

    # Get solved challenge IDs for current principal
    solved_ids = set()
    if principal:
        solved_ids = {
            s.challenge_id
            for s in Solve.query.filter_by(principal_id=principal.id).all()
        }

    # Group by category
    categories = {}
    for chal in challenges:
        categories.setdefault(chal.category_slug, []).append(chal)

    return render_template(
        "challenges/list.html",
        categories=categories,
        solved_ids=solved_ids,
        principal=principal,
    )


@challenges_bp.route("/<slug>", methods=["GET", "POST"])
@login_required
def detail(slug):
    challenge = Challenge.query.filter_by(slug=slug, status="visible").first_or_404()
    principal = get_current_principal()
    if not principal:
        flash("You must be on a team or playing solo to submit flags.", "warning")
        return redirect(url_for("team.create_or_join"))

    already_solved = Solve.query.filter_by(
        principal_id=principal.id, challenge_id=challenge.id
    ).first()

    form = FlagSubmitForm()

    if form.validate_on_submit() and not already_solved:
        submitted_flag = form.flag.data.strip()

        # Rate limit check
        allowed, remaining, retry_after = check_rate_limit(principal.id, challenge.id)
        if not allowed:
            flash(f"Too many wrong attempts. Try again in {retry_after}s.", "danger")
            return render_template(
                "challenges/detail.html",
                challenge=challenge,
                form=form,
                solved=already_solved,
                retry_after=retry_after,
            )

        expected = get_flag_for_principal(principal.id, challenge.id)

        if expected and hmac.compare_digest(submitted_flag, expected):
            # CORRECT
            submission = Submission(
                principal_id=principal.id,
                challenge_id=challenge.id,
                flag_submitted_hash=Submission.hash_flag(submitted_flag),
                result="correct",
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:512],
            )
            solve = Solve(
                principal_id=principal.id,
                challenge_id=challenge.id,
                points_awarded=challenge.points,
            )
            score_event = ScoreEvent(
                principal_id=principal.id,
                challenge_id=challenge.id,
                delta=challenge.points,
                reason="challenge_solve",
            )
            principal.score_total += challenge.points
            principal.last_solve_at = solve.solved_at

            db.session.add_all([submission, solve, score_event])
            db.session.commit()

            clear_attempts(principal.id, challenge.id)
            write_event(
                "CHALLENGE_SOLVED",
                actor_user_id=current_user.id,
                principal_id=principal.id,
                challenge_id=challenge.id,
                payload={"points": challenge.points},
            )
            flash(f"Correct! +{challenge.points} points!", "success")
            return redirect(url_for("challenges.detail", slug=slug))
        else:
            # WRONG
            submission = Submission(
                principal_id=principal.id,
                challenge_id=challenge.id,
                flag_submitted_hash=Submission.hash_flag(submitted_flag),
                result="wrong",
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:512],
            )
            db.session.add(submission)
            db.session.commit()

            record_wrong_attempt(principal.id, challenge.id)

            # Check for flag sharing
            sharing = check_flag_sharing(principal.id, challenge.id, submitted_flag)
            if sharing:
                flash("Incorrect flag.", "danger")
                # Don't reveal sharing detection to the submitter
            else:
                flash("Incorrect flag.", "danger")

    # Get user's flag to display (so they know what to look for in the challenge)
    user_flag = get_flag_for_principal(principal.id, challenge.id)

    return render_template(
        "challenges/detail.html",
        challenge=challenge,
        form=form,
        solved=already_solved,
        retry_after=0,
    )
```

- [ ] **Step 4: Commit**

```bash
git add ctfapp/blueprints/challenges/ ctfapp/services/event_service.py
git commit -m "feat: challenges blueprint — list by category, submit flag with anti-cheat"
```

---

## Task 11: Scoreboard Blueprint

**Files:**
- Create: `ctfapp/blueprints/scoreboard/__init__.py`
- Create: `ctfapp/blueprints/scoreboard/routes.py`

- [ ] **Step 1: Create scoreboard blueprint**

Create `ctfapp/blueprints/scoreboard/__init__.py`:

```python
from flask import Blueprint

scoreboard_bp = Blueprint(
    "scoreboard", __name__, url_prefix="/scoreboard", template_folder="templates"
)

from . import routes  # noqa: E402, F401
```

Create `ctfapp/blueprints/scoreboard/routes.py`:

```python
from flask import render_template, request

from ctfapp.models.principal import Principal

from . import scoreboard_bp


@scoreboard_bp.route("/")
def index():
    filter_kind = request.args.get("filter", "all")  # all | team | solo

    query = Principal.query.filter_by(active=True)
    if filter_kind in ("team", "solo"):
        query = query.filter_by(kind=filter_kind)

    principals = query.order_by(
        Principal.score_total.desc(),
        Principal.last_solve_at.asc(),  # tiebreaker: earlier solve wins
    ).all()

    return render_template(
        "scoreboard/index.html",
        principals=principals,
        filter_kind=filter_kind,
    )
```

- [ ] **Step 2: Commit**

```bash
git add ctfapp/blueprints/scoreboard/
git commit -m "feat: scoreboard blueprint — ranked leaderboard with team/solo filter"
```

---

## Task 12: Admin Blueprint

**Files:**
- Create: `ctfapp/blueprints/admin/__init__.py`
- Create: `ctfapp/blueprints/admin/routes.py`
- Create: `ctfapp/blueprints/admin/forms.py`

- [ ] **Step 1: Create admin blueprint**

Create `ctfapp/blueprints/admin/__init__.py`:

```python
from functools import wraps

from flask import Blueprint, abort, flash, redirect, url_for
from flask_login import current_user

admin_bp = Blueprint("admin", __name__, url_prefix="/admin", template_folder="templates")


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


from . import routes  # noqa: E402, F401
```

Create `ctfapp/blueprints/admin/forms.py`:

```python
from flask_wtf import FlaskForm
from wtforms import BooleanField, IntegerField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, NumberRange, Optional


class ChallengeForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(max=200)])
    slug = StringField("Slug", validators=[DataRequired(), Length(max=120)])
    category_slug = SelectField(
        "Category",
        choices=[
            ("crypto", "Crypto"),
            ("web", "Web"),
            ("misc", "Misc"),
            ("pwn", "Pwn"),
            ("osint", "OSINT"),
        ],
        validators=[DataRequired()],
    )
    description_md = TextAreaField("Description (Markdown)", validators=[DataRequired()])
    points = IntegerField("Points", validators=[DataRequired(), NumberRange(min=1)])
    is_dynamic = BooleanField("Dynamic (requires container)")
    container_image = StringField("Container Image", validators=[Optional(), Length(max=255)])
    container_port = IntegerField("Container Port", validators=[Optional()])
    status = SelectField(
        "Status",
        choices=[("hidden", "Hidden"), ("visible", "Visible")],
        default="hidden",
    )
    submit = SubmitField("Save Challenge")


class ManualScoreForm(FlaskForm):
    principal_id = IntegerField("Principal ID", validators=[DataRequired()])
    delta = IntegerField("Points (+/-)", validators=[DataRequired()])
    reason = StringField("Reason", validators=[DataRequired(), Length(max=255)])
    submit = SubmitField("Apply")
```

Create `ctfapp/blueprints/admin/routes.py`:

```python
from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user

from ctfapp.extensions import db
from ctfapp.models.challenge import Challenge
from ctfapp.models.event_log import EventLog
from ctfapp.models.principal import Principal
from ctfapp.models.submission import ScoreEvent, Solve, Submission
from ctfapp.models.team import Team
from ctfapp.models.user import User
from ctfapp.secure_log import write_event
from ctfapp.services.flag_engine import generate_flags_for_challenge

from . import admin_bp, admin_required
from .forms import ChallengeForm, ManualScoreForm


@admin_bp.route("/")
@admin_required
def dashboard():
    stats = {
        "users": User.query.count(),
        "teams": Team.query.count(),
        "challenges": Challenge.query.count(),
        "submissions": Submission.query.count(),
        "solves": Solve.query.count(),
    }
    recent_events = EventLog.query.order_by(EventLog.id.desc()).limit(20).all()
    return render_template("admin/dashboard.html", stats=stats, recent_events=recent_events)


@admin_bp.route("/challenges")
@admin_required
def challenges():
    all_challenges = Challenge.query.order_by(
        Challenge.category_slug, Challenge.points
    ).all()
    return render_template("admin/challenges.html", challenges=all_challenges)


@admin_bp.route("/challenges/new", methods=["GET", "POST"])
@admin_required
def create_challenge():
    form = ChallengeForm()
    if form.validate_on_submit():
        if Challenge.query.filter_by(slug=form.slug.data).first():
            flash("Challenge slug already exists.", "danger")
            return render_template("admin/challenge_form.html", form=form, editing=False)

        chal = Challenge(
            slug=form.slug.data,
            title=form.title.data,
            category_slug=form.category_slug.data,
            description_md=form.description_md.data,
            points=form.points.data,
            is_dynamic=form.is_dynamic.data,
            container_image=form.container_image.data or None,
            container_port=form.container_port.data or None,
            status=form.status.data,
        )
        db.session.add(chal)
        db.session.flush()

        if chal.status == "visible":
            generate_flags_for_challenge(chal)

        db.session.commit()
        write_event(
            "CHALLENGE_CREATED",
            actor_user_id=current_user.id,
            challenge_id=chal.id,
            payload={"title": chal.title, "points": chal.points},
        )
        flash(f"Challenge '{chal.title}' created.", "success")
        return redirect(url_for("admin.challenges"))

    return render_template("admin/challenge_form.html", form=form, editing=False)


@admin_bp.route("/challenges/<int:chal_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_challenge(chal_id):
    chal = Challenge.query.get_or_404(chal_id)
    form = ChallengeForm(obj=chal)

    if form.validate_on_submit():
        was_hidden = chal.status == "hidden"
        form.populate_obj(chal)
        chal.container_image = chal.container_image or None
        chal.container_port = chal.container_port or None

        # If newly made visible, generate flags for all principals
        if was_hidden and chal.status == "visible":
            generate_flags_for_challenge(chal)

        db.session.commit()
        write_event(
            "CHALLENGE_UPDATED",
            actor_user_id=current_user.id,
            challenge_id=chal.id,
        )
        flash(f"Challenge '{chal.title}' updated.", "success")
        return redirect(url_for("admin.challenges"))

    return render_template("admin/challenge_form.html", form=form, editing=True, chal=chal)


@admin_bp.route("/challenges/<int:chal_id>/toggle", methods=["POST"])
@admin_required
def toggle_challenge(chal_id):
    chal = Challenge.query.get_or_404(chal_id)
    was_hidden = chal.status == "hidden"
    chal.status = "visible" if chal.status == "hidden" else "hidden"

    if was_hidden and chal.status == "visible":
        generate_flags_for_challenge(chal)

    db.session.commit()
    write_event(
        "CHALLENGE_TOGGLED",
        actor_user_id=current_user.id,
        challenge_id=chal.id,
        payload={"new_status": chal.status},
    )
    flash(f"Challenge '{chal.title}' is now {chal.status}.", "info")
    return redirect(url_for("admin.challenges"))


@admin_bp.route("/users")
@admin_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=all_users)


@admin_bp.route("/users/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Cannot change your own admin status.", "danger")
    else:
        user.is_admin = not user.is_admin
        db.session.commit()
        write_event(
            "ADMIN_TOGGLED",
            actor_user_id=current_user.id,
            payload={"target_user_id": user.id, "is_admin": user.is_admin},
        )
        flash(f"Admin status for {user.username}: {user.is_admin}", "info")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/ban", methods=["POST"])
@admin_required
def ban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.state = "banned" if user.state == "active" else "active"
    db.session.commit()
    write_event(
        "USER_BAN_TOGGLED",
        actor_user_id=current_user.id,
        payload={"target_user_id": user.id, "state": user.state},
    )
    flash(f"User {user.username} state: {user.state}", "info")
    return redirect(url_for("admin.users"))


@admin_bp.route("/scoreboard/adjust", methods=["POST"])
@admin_required
def adjust_score():
    form = ManualScoreForm()
    if form.validate_on_submit():
        principal = Principal.query.get_or_404(form.principal_id.data)
        event = ScoreEvent(
            principal_id=principal.id,
            delta=form.delta.data,
            reason=f"admin:{form.reason.data}",
        )
        principal.score_total += form.delta.data
        db.session.add(event)
        db.session.commit()
        write_event(
            "MANUAL_SCORE_ADJUST",
            severity="WARNING",
            actor_user_id=current_user.id,
            principal_id=principal.id,
            payload={"delta": form.delta.data, "reason": form.reason.data},
        )
        flash(f"Score adjusted: {form.delta.data:+d} for {principal.display_name}", "info")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/scoreboard/freeze", methods=["POST"])
@admin_required
def freeze_scoreboard():
    # Set event_ends_at to now (freezes scoreboard display)
    from flask import current_app
    from datetime import datetime, timezone

    # Store freeze state in cache
    from ctfapp.extensions import cache
    is_frozen = cache.get("scoreboard_frozen") or False
    cache.set("scoreboard_frozen", not is_frozen, timeout=0)
    state = "frozen" if not is_frozen else "unfrozen"
    write_event("SCOREBOARD_FREEZE_TOGGLED", severity="WARNING",
                actor_user_id=current_user.id, payload={"state": state})
    flash(f"Scoreboard {state}.", "info")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/events")
@admin_required
def event_log():
    page = request.args.get("page", 1, type=int)
    severity = request.args.get("severity", "all")
    query = EventLog.query
    if severity != "all":
        query = query.filter_by(severity=severity)
    events = query.order_by(EventLog.id.desc()).paginate(page=page, per_page=50)
    return render_template("admin/event_log.html", events=events, severity=severity)
```

- [ ] **Step 2: Commit**

```bash
git add ctfapp/blueprints/admin/
git commit -m "feat: admin blueprint — challenge CRUD, user mgmt, score adjust, event log"
```

---

## Task 13: Dispatch Proxy Blueprint (stub)

**Files:**
- Create: `ctfapp/blueprints/dispatch/__init__.py`
- Create: `ctfapp/blueprints/dispatch/routes.py`

- [ ] **Step 1: Create dispatch proxy blueprint (stub for Plan 2)**

Create `ctfapp/blueprints/dispatch/__init__.py`:

```python
from flask import Blueprint

dispatch_bp = Blueprint(
    "dispatch", __name__, url_prefix="/dispatch", template_folder="templates"
)

from . import routes  # noqa: E402, F401
```

Create `ctfapp/blueprints/dispatch/routes.py`:

```python
import requests
from flask import abort, current_app, flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from ctfapp.models.challenge import Challenge
from ctfapp.models.instance import Instance
from ctfapp.services.event_service import get_current_principal

from . import dispatch_bp


@dispatch_bp.route("/instances")
@login_required
def list_instances():
    principal = get_current_principal()
    if not principal:
        flash("Set up your team or solo profile first.", "warning")
        return redirect(url_for("team.create_or_join"))

    instances = Instance.query.filter_by(
        principal_id=principal.id, status="running"
    ).all()
    dynamic_challenges = Challenge.query.filter_by(
        is_dynamic=True, status="visible"
    ).all()
    return render_template(
        "dispatch/instance.html",
        instances=instances,
        dynamic_challenges=dynamic_challenges,
        principal=principal,
    )


@dispatch_bp.route("/spawn/<int:challenge_id>", methods=["POST"])
@login_required
def spawn(challenge_id):
    """Proxy spawn request to dispatch service."""
    principal = get_current_principal()
    if not principal:
        abort(403)

    challenge = Challenge.query.get_or_404(challenge_id)
    if not challenge.is_dynamic:
        abort(400)

    dispatch_url = current_app.config["DISPATCH_INTERNAL_URL"]
    try:
        resp = requests.post(
            f"{dispatch_url}/instances/spawn",
            json={
                "challenge_id": challenge.id,
                "principal_id": principal.id,
                "image": challenge.container_image,
                "port": challenge.container_port,
                "ttl_seconds": current_app.config.get("INSTANCE_TTL_SECONDS", 7200),
            },
            headers={"Authorization": f"Bearer {current_app.config['DISPATCH_ADMIN_TOKEN']}"},
            timeout=30,
        )
        if resp.ok:
            data = resp.json()
            flash(f"Instance spawned: {data.get('subdomain', 'unknown')}", "success")
        else:
            flash(f"Dispatch error: {resp.text}", "danger")
    except requests.RequestException as e:
        flash(f"Cannot reach dispatch service: {e}", "danger")

    return redirect(url_for("dispatch.list_instances"))


@dispatch_bp.route("/destroy/<int:challenge_id>", methods=["POST"])
@login_required
def destroy(challenge_id):
    """Proxy destroy request to dispatch service."""
    principal = get_current_principal()
    if not principal:
        abort(403)

    dispatch_url = current_app.config["DISPATCH_INTERNAL_URL"]
    try:
        resp = requests.delete(
            f"{dispatch_url}/instances/{principal.id}/{challenge_id}",
            headers={"Authorization": f"Bearer {current_app.config['DISPATCH_ADMIN_TOKEN']}"},
            timeout=15,
        )
        if resp.ok:
            flash("Instance destroyed.", "info")
        else:
            flash(f"Dispatch error: {resp.text}", "danger")
    except requests.RequestException as e:
        flash(f"Cannot reach dispatch service: {e}", "danger")

    return redirect(url_for("dispatch.list_instances"))
```

- [ ] **Step 2: Commit**

```bash
git add ctfapp/blueprints/dispatch/
git commit -m "feat: dispatch proxy blueprint — spawn/destroy via dispatch service API"
```

---

## Task 14: Templates

**Files:**
- Create: all template files under `ctfapp/templates/`

- [ ] **Step 1: Create base.html (dark CTF theme)**

```html
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}GrizzHacks8 CTF{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #0d1117; color: #c9d1d9; min-height: 100vh; }
        .navbar { background: #161b22 !important; border-bottom: 1px solid #30363d; }
        .card { background: #161b22; border: 1px solid #30363d; }
        .badge-crypto { background: #7c3aed; }
        .badge-web { background: #2563eb; }
        .badge-pwn { background: #dc2626; }
        .badge-misc { background: #059669; }
        .badge-osint { background: #d97706; }
        .solved { border-left: 4px solid #22c55e; }
        .flag-input { font-family: monospace; }
        a { color: #58a6ff; }
    </style>
    {% block extra_head %}{% endblock %}
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark mb-4">
        <div class="container">
            <a class="navbar-brand fw-bold" href="{{ url_for('challenges.list_challenges') }}">
                GrizzHacks8 CTF
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#nav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="nav">
                <ul class="navbar-nav me-auto">
                    {% if current_user.is_authenticated %}
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('challenges.list_challenges') }}">Challenges</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('scoreboard.index') }}">Scoreboard</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('team.manage') }}">Team</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('dispatch.list_instances') }}">Instances</a></li>
                    {% if current_user.is_admin %}
                    <li class="nav-item"><a class="nav-link text-warning" href="{{ url_for('admin.dashboard') }}">Admin</a></li>
                    {% endif %}
                    {% endif %}
                </ul>
                <ul class="navbar-nav">
                    {% if current_user.is_authenticated %}
                    <li class="nav-item"><span class="nav-link text-muted">{{ current_user.username }}</span></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('auth.logout') }}">Logout</a></li>
                    {% else %}
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('auth.login') }}">Login</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('auth.register') }}">Register</a></li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>

    <main class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
        {% for category, message in messages %}
        <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
            {{ message }}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
        {% endfor %}
        {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </main>

    <footer class="container text-center text-muted mt-5 mb-3">
        <small>GrizzHacks8 CTF &copy; 2025</small>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    {% block extra_js %}{% endblock %}
</body>
</html>
```

- [ ] **Step 2: Create error.html**

```html
{% extends "base.html" %}
{% block title %}Error {{ status_code }}{% endblock %}
{% block content %}
<div class="text-center mt-5">
    <h1 class="display-1">{{ status_code }}</h1>
    <p class="lead">{{ error_message }}</p>
    <a href="{{ url_for('challenges.list_challenges') }}" class="btn btn-primary mt-3">Back to Challenges</a>
</div>
{% endblock %}
```

- [ ] **Step 3: Create index.html**

```html
{% extends "base.html" %}
{% block content %}
<div class="text-center mt-5">
    <h1 class="display-4 fw-bold">GrizzHacks8 CTF</h1>
    <p class="lead">Annual GrizzHacks 8 CTF Side-Event! Crypto, Web, Misc, Pwn & OSINT.</p>
    <div class="mt-4">
        <a href="{{ url_for('auth.register') }}" class="btn btn-primary btn-lg me-2">Register</a>
        <a href="{{ url_for('auth.login') }}" class="btn btn-outline-light btn-lg">Login</a>
    </div>
</div>
{% endblock %}
```

- [ ] **Step 4: Create auth templates**

`ctfapp/templates/auth/login.html`:
```html
{% extends "base.html" %}
{% block title %}Login{% endblock %}
{% block content %}
<div class="row justify-content-center">
    <div class="col-md-5">
        <div class="card p-4">
            <h3 class="mb-3">Login</h3>
            <form method="POST">
                {{ form.hidden_tag() }}
                <div class="mb-3">
                    {{ form.username.label(class="form-label") }}
                    {{ form.username(class="form-control") }}
                </div>
                <div class="mb-3">
                    {{ form.password.label(class="form-label") }}
                    {{ form.password(class="form-control") }}
                </div>
                {{ form.submit(class="btn btn-primary w-100") }}
            </form>
            <p class="mt-3 text-center"><a href="{{ url_for('auth.register') }}">Don't have an account? Register</a></p>
        </div>
    </div>
</div>
{% endblock %}
```

`ctfapp/templates/auth/register.html`:
```html
{% extends "base.html" %}
{% block title %}Register{% endblock %}
{% block content %}
<div class="row justify-content-center">
    <div class="col-md-5">
        <div class="card p-4">
            <h3 class="mb-3">Register</h3>
            <form method="POST">
                {{ form.hidden_tag() }}
                <div class="mb-3">
                    {{ form.username.label(class="form-label") }}
                    {{ form.username(class="form-control") }}
                </div>
                <div class="mb-3">
                    {{ form.email.label(class="form-label") }}
                    {{ form.email(class="form-control") }}
                </div>
                <div class="mb-3">
                    {{ form.password.label(class="form-label") }}
                    {{ form.password(class="form-control") }}
                </div>
                <div class="mb-3">
                    {{ form.confirm_password.label(class="form-label") }}
                    {{ form.confirm_password(class="form-control") }}
                </div>
                <div class="mb-3">
                    <label class="form-label">Play Mode</label>
                    <div class="form-check">
                        {{ form.mode(class="form-check-input") }}
                    </div>
                </div>
                {{ form.submit(class="btn btn-primary w-100") }}
            </form>
            <p class="mt-3 text-center"><a href="{{ url_for('auth.login') }}">Already registered? Login</a></p>
        </div>
    </div>
</div>
{% endblock %}
```

- [ ] **Step 5: Create challenges templates**

`ctfapp/templates/challenges/list.html`:
```html
{% extends "base.html" %}
{% block title %}Challenges{% endblock %}
{% block content %}
<h2 class="mb-4">Challenges</h2>
{% for category, chals in categories.items() %}
<h4 class="mt-4">
    <span class="badge badge-{{ category }}">{{ category | upper }}</span>
</h4>
<div class="row g-3">
    {% for chal in chals %}
    <div class="col-md-4">
        <div class="card p-3 h-100 {{ 'solved' if chal.id in solved_ids }}">
            <h5>
                {{ chal.title }}
                {% if chal.id in solved_ids %}<span class="badge bg-success">Solved</span>{% endif %}
            </h5>
            <p class="text-muted mb-2">{{ chal.points }} pts &middot; {{ chal.solve_count }} solves</p>
            <a href="{{ url_for('challenges.detail', slug=chal.slug) }}" class="btn btn-sm btn-outline-light mt-auto">View</a>
        </div>
    </div>
    {% endfor %}
</div>
{% endfor %}
{% endblock %}
```

`ctfapp/templates/challenges/detail.html`:
```html
{% extends "base.html" %}
{% block title %}{{ challenge.title }}{% endblock %}
{% block content %}
<div class="row">
    <div class="col-md-8">
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb">
                <li class="breadcrumb-item"><a href="{{ url_for('challenges.list_challenges') }}">Challenges</a></li>
                <li class="breadcrumb-item active">{{ challenge.title }}</li>
            </ol>
        </nav>
        <div class="card p-4">
            <h3>{{ challenge.title }}
                <span class="badge badge-{{ challenge.category_slug }}">{{ challenge.category_slug | upper }}</span>
                <span class="badge bg-secondary">{{ challenge.points }} pts</span>
            </h3>
            <div class="mt-3">{{ challenge.description_md }}</div>

            {% if challenge.files %}
            <div class="mt-3">
                <strong>Files:</strong>
                {% for f in challenge.files %}
                <a href="/static/uploads/{{ f.storage_path }}" class="badge bg-dark">{{ f.filename }}</a>
                {% endfor %}
            </div>
            {% endif %}

            {% if solved %}
            <div class="alert alert-success mt-4">
                Solved for {{ solved.points_awarded }} points!
            </div>
            {% else %}
            <form method="POST" class="mt-4">
                {{ form.hidden_tag() }}
                <div class="input-group">
                    {{ form.flag(class="form-control flag-input", placeholder="GRIZZ{...}") }}
                    {{ form.submit(class="btn btn-primary") }}
                </div>
                {% if retry_after > 0 %}
                <small class="text-danger">Locked out. Retry in {{ retry_after }}s.</small>
                {% endif %}
            </form>
            {% endif %}
        </div>
    </div>
    <div class="col-md-4">
        <div class="card p-3">
            <h6>Stats</h6>
            <p>Solves: {{ challenge.solve_count }}</p>
            <p>Category: {{ challenge.category_slug | upper }}</p>
        </div>
    </div>
</div>
{% endblock %}
```

- [ ] **Step 6: Create scoreboard template**

`ctfapp/templates/scoreboard/index.html`:
```html
{% extends "base.html" %}
{% block title %}Scoreboard{% endblock %}
{% block content %}
<h2 class="mb-3">Scoreboard</h2>
<div class="mb-3">
    <a href="?filter=all" class="btn btn-sm {{ 'btn-primary' if filter_kind == 'all' else 'btn-outline-light' }}">All</a>
    <a href="?filter=team" class="btn btn-sm {{ 'btn-primary' if filter_kind == 'team' else 'btn-outline-light' }}">Teams</a>
    <a href="?filter=solo" class="btn btn-sm {{ 'btn-primary' if filter_kind == 'solo' else 'btn-outline-light' }}">Solo</a>
</div>
<table class="table table-dark table-striped">
    <thead>
        <tr><th>#</th><th>Name</th><th>Type</th><th>Score</th><th>Last Solve</th></tr>
    </thead>
    <tbody>
        {% for p in principals %}
        <tr>
            <td>{{ loop.index }}</td>
            <td>{{ p.display_name }}</td>
            <td><span class="badge {{ 'bg-info' if p.kind == 'team' else 'bg-secondary' }}">{{ p.kind }}</span></td>
            <td><strong>{{ p.score_total }}</strong></td>
            <td>{{ p.last_solve_at.strftime('%H:%M:%S') if p.last_solve_at else '-' }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endblock %}
```

- [ ] **Step 7: Create team templates**

`ctfapp/templates/team/create.html`:
```html
{% extends "base.html" %}
{% block title %}Team{% endblock %}
{% block content %}
<div class="row justify-content-center">
    <div class="col-md-5">
        <div class="card p-4 mb-4">
            <h4>Create a Team</h4>
            <form method="POST" action="{{ url_for('team.create_team') }}">
                {{ create_form.hidden_tag() }}
                <div class="mb-3">
                    {{ create_form.name.label(class="form-label") }}
                    {{ create_form.name(class="form-control") }}
                </div>
                {{ create_form.submit(class="btn btn-primary w-100") }}
            </form>
        </div>
        <div class="card p-4">
            <h4>Join a Team</h4>
            <form method="POST" action="{{ url_for('team.join_team') }}">
                {{ join_form.hidden_tag() }}
                <div class="mb-3">
                    {{ join_form.join_token.label(class="form-label") }}
                    {{ join_form.join_token(class="form-control font-monospace") }}
                </div>
                {{ join_form.submit(class="btn btn-outline-light w-100") }}
            </form>
        </div>
    </div>
</div>
{% endblock %}
```

`ctfapp/templates/team/manage.html`:
```html
{% extends "base.html" %}
{% block title %}Team: {{ team.name }}{% endblock %}
{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card p-4">
            <h3>{{ team.name }}</h3>
            <p>Join Token: <code>{{ team.join_token }}</code></p>
            <p>Members: {{ team.member_count }} / {{ team.max_size }}</p>
            <table class="table table-dark table-sm mt-3">
                <thead><tr><th>Username</th><th>Role</th><th>Joined</th></tr></thead>
                <tbody>
                {% for m in members %}
                <tr>
                    <td>{{ m.user.username }}</td>
                    <td><span class="badge {{ 'bg-warning' if m.role == 'captain' else 'bg-secondary' }}">{{ m.role }}</span></td>
                    <td>{{ m.joined_at.strftime('%Y-%m-%d %H:%M') }}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endblock %}
```

- [ ] **Step 8: Create admin templates**

`ctfapp/templates/admin/dashboard.html`:
```html
{% extends "base.html" %}
{% block title %}Admin Dashboard{% endblock %}
{% block content %}
<h2>Admin Dashboard</h2>
<div class="row g-3 mt-3">
    {% for label, count in stats.items() %}
    <div class="col-md-2">
        <div class="card p-3 text-center">
            <h4>{{ count }}</h4>
            <small class="text-muted">{{ label | title }}</small>
        </div>
    </div>
    {% endfor %}
</div>

<div class="row mt-4">
    <div class="col-md-6">
        <div class="card p-3">
            <h5>Quick Actions</h5>
            <a href="{{ url_for('admin.challenges') }}" class="btn btn-outline-light btn-sm me-2">Manage Challenges</a>
            <a href="{{ url_for('admin.users') }}" class="btn btn-outline-light btn-sm me-2">Manage Users</a>
            <a href="{{ url_for('admin.event_log') }}" class="btn btn-outline-light btn-sm me-2">Event Log</a>
            <form method="POST" action="{{ url_for('admin.freeze_scoreboard') }}" class="d-inline">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button class="btn btn-warning btn-sm">Toggle Scoreboard Freeze</button>
            </form>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card p-3">
            <h5>Manual Score Adjustment</h5>
            <form method="POST" action="{{ url_for('admin.adjust_score') }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <div class="row g-2">
                    <div class="col-3"><input name="principal_id" type="number" class="form-control form-control-sm" placeholder="Principal ID"></div>
                    <div class="col-3"><input name="delta" type="number" class="form-control form-control-sm" placeholder="+/- pts"></div>
                    <div class="col-4"><input name="reason" type="text" class="form-control form-control-sm" placeholder="Reason"></div>
                    <div class="col-2"><button class="btn btn-primary btn-sm w-100">Apply</button></div>
                </div>
            </form>
        </div>
    </div>
</div>

<h5 class="mt-4">Recent Events</h5>
<table class="table table-dark table-sm">
    <thead><tr><th>Type</th><th>Severity</th><th>User</th><th>Time</th></tr></thead>
    <tbody>
    {% for e in recent_events %}
    <tr class="{{ 'table-danger' if e.severity == 'CRITICAL' else 'table-warning' if e.severity == 'WARNING' else '' }}">
        <td>{{ e.type }}</td>
        <td>{{ e.severity }}</td>
        <td>{{ e.actor_user_id or '-' }}</td>
        <td>{{ e.created_at.strftime('%H:%M:%S') }}</td>
    </tr>
    {% endfor %}
    </tbody>
</table>
{% endblock %}
```

`ctfapp/templates/admin/challenges.html`:
```html
{% extends "base.html" %}
{% block title %}Admin: Challenges{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-3">
    <h3>Challenges</h3>
    <a href="{{ url_for('admin.create_challenge') }}" class="btn btn-primary">+ New Challenge</a>
</div>
<table class="table table-dark table-striped">
    <thead><tr><th>Title</th><th>Category</th><th>Points</th><th>Status</th><th>Solves</th><th>Actions</th></tr></thead>
    <tbody>
    {% for c in challenges %}
    <tr>
        <td>{{ c.title }}</td>
        <td><span class="badge badge-{{ c.category_slug }}">{{ c.category_slug }}</span></td>
        <td>{{ c.points }}</td>
        <td>{{ c.status }}</td>
        <td>{{ c.solve_count }}</td>
        <td>
            <a href="{{ url_for('admin.edit_challenge', chal_id=c.id) }}" class="btn btn-sm btn-outline-light">Edit</a>
            <form method="POST" action="{{ url_for('admin.toggle_challenge', chal_id=c.id) }}" class="d-inline">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button class="btn btn-sm {{ 'btn-success' if c.status == 'hidden' else 'btn-warning' }}">
                    {{ 'Show' if c.status == 'hidden' else 'Hide' }}
                </button>
            </form>
        </td>
    </tr>
    {% endfor %}
    </tbody>
</table>
{% endblock %}
```

`ctfapp/templates/admin/challenge_form.html`:
```html
{% extends "base.html" %}
{% block title %}{{ 'Edit' if editing else 'New' }} Challenge{% endblock %}
{% block content %}
<div class="row justify-content-center">
    <div class="col-md-8">
        <div class="card p-4">
            <h3>{{ 'Edit' if editing else 'New' }} Challenge</h3>
            <form method="POST">
                {{ form.hidden_tag() }}
                <div class="row">
                    <div class="col-md-8 mb-3">
                        {{ form.title.label(class="form-label") }}
                        {{ form.title(class="form-control") }}
                    </div>
                    <div class="col-md-4 mb-3">
                        {{ form.slug.label(class="form-label") }}
                        {{ form.slug(class="form-control") }}
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-4 mb-3">
                        {{ form.category_slug.label(class="form-label") }}
                        {{ form.category_slug(class="form-select") }}
                    </div>
                    <div class="col-md-4 mb-3">
                        {{ form.points.label(class="form-label") }}
                        {{ form.points(class="form-control") }}
                    </div>
                    <div class="col-md-4 mb-3">
                        {{ form.status.label(class="form-label") }}
                        {{ form.status(class="form-select") }}
                    </div>
                </div>
                <div class="mb-3">
                    {{ form.description_md.label(class="form-label") }}
                    {{ form.description_md(class="form-control", rows=8) }}
                </div>
                <div class="mb-3 form-check">
                    {{ form.is_dynamic(class="form-check-input") }}
                    {{ form.is_dynamic.label(class="form-check-label") }}
                </div>
                <div class="row">
                    <div class="col-md-8 mb-3">
                        {{ form.container_image.label(class="form-label") }}
                        {{ form.container_image(class="form-control") }}
                    </div>
                    <div class="col-md-4 mb-3">
                        {{ form.container_port.label(class="form-label") }}
                        {{ form.container_port(class="form-control") }}
                    </div>
                </div>
                {{ form.submit(class="btn btn-primary") }}
            </form>
        </div>
    </div>
</div>
{% endblock %}
```

`ctfapp/templates/admin/users.html`:
```html
{% extends "base.html" %}
{% block title %}Admin: Users{% endblock %}
{% block content %}
<h3>Users</h3>
<table class="table table-dark table-striped">
    <thead><tr><th>Username</th><th>Email</th><th>Admin</th><th>State</th><th>Registered</th><th>Actions</th></tr></thead>
    <tbody>
    {% for u in users %}
    <tr>
        <td>{{ u.username }}</td>
        <td>{{ u.email }}</td>
        <td>{{ 'Yes' if u.is_admin else 'No' }}</td>
        <td>{{ u.state }}</td>
        <td>{{ u.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
        <td>
            <form method="POST" action="{{ url_for('admin.toggle_admin', user_id=u.id) }}" class="d-inline">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button class="btn btn-sm btn-outline-warning">Toggle Admin</button>
            </form>
            <form method="POST" action="{{ url_for('admin.ban_user', user_id=u.id) }}" class="d-inline">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button class="btn btn-sm {{ 'btn-danger' if u.state == 'active' else 'btn-success' }}">
                    {{ 'Ban' if u.state == 'active' else 'Unban' }}
                </button>
            </form>
        </td>
    </tr>
    {% endfor %}
    </tbody>
</table>
{% endblock %}
```

`ctfapp/templates/admin/event_log.html`:
```html
{% extends "base.html" %}
{% block title %}Admin: Event Log{% endblock %}
{% block content %}
<h3>Event Log</h3>
<div class="mb-3">
    <a href="?severity=all" class="btn btn-sm {{ 'btn-primary' if severity == 'all' else 'btn-outline-light' }}">All</a>
    <a href="?severity=CRITICAL" class="btn btn-sm btn-outline-danger">Critical</a>
    <a href="?severity=WARNING" class="btn btn-sm btn-outline-warning">Warning</a>
    <a href="?severity=INFO" class="btn btn-sm btn-outline-info">Info</a>
</div>
<table class="table table-dark table-sm">
    <thead><tr><th>ID</th><th>Type</th><th>Severity</th><th>Actor</th><th>Principal</th><th>Challenge</th><th>Time</th></tr></thead>
    <tbody>
    {% for e in events.items %}
    <tr class="{{ 'table-danger' if e.severity == 'CRITICAL' else 'table-warning' if e.severity == 'WARNING' else '' }}">
        <td>{{ e.id }}</td>
        <td>{{ e.type }}</td>
        <td>{{ e.severity }}</td>
        <td>{{ e.actor_user_id or '-' }}</td>
        <td>{{ e.principal_id or '-' }}</td>
        <td>{{ e.challenge_id or '-' }}</td>
        <td>{{ e.created_at.strftime('%Y-%m-%d %H:%M:%S') }}</td>
    </tr>
    {% endfor %}
    </tbody>
</table>
{% if events.has_prev or events.has_next %}
<nav>
    <ul class="pagination pagination-sm">
        {% if events.has_prev %}
        <li class="page-item"><a class="page-link" href="?page={{ events.prev_num }}&severity={{ severity }}">Prev</a></li>
        {% endif %}
        {% if events.has_next %}
        <li class="page-item"><a class="page-link" href="?page={{ events.next_num }}&severity={{ severity }}">Next</a></li>
        {% endif %}
    </ul>
</nav>
{% endif %}
{% endblock %}
```

- [ ] **Step 9: Create dispatch instance template**

`ctfapp/templates/dispatch/instance.html`:
```html
{% extends "base.html" %}
{% block title %}Instances{% endblock %}
{% block content %}
<h2>Challenge Instances</h2>

{% if instances %}
<h5 class="mt-4">Active Instances</h5>
<table class="table table-dark">
    <thead><tr><th>Challenge</th><th>URL</th><th>Expires</th><th>Actions</th></tr></thead>
    <tbody>
    {% for inst in instances %}
    <tr>
        <td>{{ inst.challenge.title }}</td>
        <td><a href="https://{{ inst.subdomain }}.chal.grizzhacks8ctf.us" target="_blank">{{ inst.subdomain }}.chal.grizzhacks8ctf.us</a></td>
        <td>{{ inst.expires_at.strftime('%H:%M:%S') }}</td>
        <td>
            <form method="POST" action="{{ url_for('dispatch.destroy', challenge_id=inst.challenge_id) }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button class="btn btn-sm btn-danger">Destroy</button>
            </form>
        </td>
    </tr>
    {% endfor %}
    </tbody>
</table>
{% endif %}

{% if dynamic_challenges %}
<h5 class="mt-4">Available Dynamic Challenges</h5>
<div class="row g-3">
    {% for chal in dynamic_challenges %}
    <div class="col-md-4">
        <div class="card p-3">
            <h6>{{ chal.title }} <span class="badge badge-{{ chal.category_slug }}">{{ chal.category_slug }}</span></h6>
            <p class="text-muted">{{ chal.points }} pts</p>
            <form method="POST" action="{{ url_for('dispatch.spawn', challenge_id=chal.id) }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button class="btn btn-sm btn-primary">Spawn Instance</button>
            </form>
        </div>
    </div>
    {% endfor %}
</div>
{% else %}
<p class="text-muted mt-4">No dynamic challenges available.</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 10: Commit**

```bash
git add ctfapp/templates/
git commit -m "feat: all templates — dark CTF theme, auth, challenges, scoreboard, team, admin, dispatch"
```

---

## Task 15: Infrastructure Stubs

**Files:**
- Create: `.env.example`
- Create: `start.sh`
- Modify: `Dockerfile`

- [ ] **Step 1: Create .env.example**

```bash
# Flask
SECRET_KEY=change-me-in-production
ADMIN_KEY=change-me-admin-key
APP_ENV=development

# Database
DATABASE_URL=postgresql://ctf:ctfpass@localhost:5432/ctfdb

# Redis
REDIS_URL=redis://localhost:6379/0

# Rate limiting
RATELIMIT_STORAGE_URI=redis://localhost:6379/1

# Dispatch
DISPATCH_INTERNAL_URL=http://localhost:5001
DISPATCH_ADMIN_TOKEN=change-me-dispatch-token

# Email (Mailtrap)
MAILTRAP_API_KEY=
MAIL_SENDER=no-reply@grizzhacks8ctf.us

# Proxy (production)
# TRUST_PROXY=true
# SESSION_COOKIE_SECURE=true
# ENABLE_HSTS=true
```

- [ ] **Step 2: Create start.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "[*] Running database migrations..."
flask db upgrade

echo "[*] Starting Gunicorn..."
exec gunicorn wsgi:app \
    --bind 0.0.0.0:5000 \
    --workers "${GUNICORN_WORKERS:-4}" \
    --timeout 120 \
    --access-logfile - \
    --error-logfile -
```

- [ ] **Step 3: Create Dockerfile**

```dockerfile
FROM python:3.13-slim

WORKDIR /app

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY . .

RUN chmod +x start.sh

EXPOSE 5000

CMD ["./start.sh"]
```

- [ ] **Step 4: Create mail_service.py stub**

```python
import requests
from flask import current_app


def send_email(to: str, subject: str, body_html: str) -> bool:
    """Send email via Mailtrap API."""
    api_key = current_app.config.get("MAILTRAP_API_KEY")
    sender = current_app.config.get("MAIL_SENDER", "no-reply@grizzhacks8ctf.us")

    if not api_key:
        current_app.logger.warning("MAILTRAP_API_KEY not set, skipping email")
        return False

    resp = requests.post(
        "https://send.api.mailtrap.io/api/send",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "from": {"email": sender, "name": "GrizzHacks8 CTF"},
            "to": [{"email": to}],
            "subject": subject,
            "html": body_html,
        },
        timeout=10,
    )
    return resp.ok
```

- [ ] **Step 5: Add requests to dependencies**

Add `"requests>=2.31.0"` to `pyproject.toml` dependencies list (used by dispatch proxy and mail service).

- [ ] **Step 6: Commit**

```bash
git add .env.example start.sh Dockerfile ctfapp/services/mail_service.py pyproject.toml
git commit -m "feat: infrastructure stubs — Dockerfile, start.sh, .env.example, mail service"
```

---

## Task 16: Database Migrations Setup

**Files:**
- Run flask-migrate init and first migration

- [ ] **Step 1: Initialize migrations**

Run:
```bash
cd /home/supasuge/CTF-THM-HTB/Grizzhacks8-CTF/CTF_UI
export FLASK_APP=wsgi.py
export DATABASE_URL=sqlite:///ctfapp.db
uv run flask db init
```
Expected: `migrations/` directory created

- [ ] **Step 2: Generate initial migration**

Run:
```bash
uv run flask db migrate -m "initial schema"
```
Expected: Migration file created under `migrations/versions/`

- [ ] **Step 3: Apply migration**

Run:
```bash
uv run flask db upgrade
```
Expected: Tables created in SQLite

- [ ] **Step 4: Commit**

```bash
git add migrations/
git commit -m "feat: initial database migration — all tables"
```

---

## Task 17: Smoke Test — Run the App

- [ ] **Step 1: Start the app locally**

Run:
```bash
cd /home/supasuge/CTF-THM-HTB/Grizzhacks8-CTF/CTF_UI
export FLASK_APP=wsgi.py
export APP_ENV=development
uv run flask run --debug
```
Expected: App starts on http://localhost:5000

- [ ] **Step 2: Test pages load**

Run:
```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/auth/register
curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/auth/login
curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/scoreboard/
```
Expected: 200 for register/login, 200 for scoreboard

- [ ] **Step 3: Run full test suite**

Run:
```bash
uv run pytest tests/ -v
```
Expected: All tests pass

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat: GrizzHacks8 CTF core platform — MVP complete"
```
