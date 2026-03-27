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
