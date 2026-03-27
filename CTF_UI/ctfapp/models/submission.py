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
