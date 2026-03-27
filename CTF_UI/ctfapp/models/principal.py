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
