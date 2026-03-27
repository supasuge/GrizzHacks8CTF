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
