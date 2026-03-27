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
