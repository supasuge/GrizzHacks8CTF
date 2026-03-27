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
