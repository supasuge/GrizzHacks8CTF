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
