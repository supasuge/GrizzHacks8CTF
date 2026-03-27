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
