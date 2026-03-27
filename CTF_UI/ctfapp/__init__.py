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
        from .headers import register_security_headers
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
