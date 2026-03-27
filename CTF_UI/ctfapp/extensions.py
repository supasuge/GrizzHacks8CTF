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
