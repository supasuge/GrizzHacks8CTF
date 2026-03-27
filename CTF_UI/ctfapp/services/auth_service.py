from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from ctfapp.extensions import db
from ctfapp.models.principal import Principal
from ctfapp.models.user import User
from ctfapp.services.flag_engine import generate_flags_for_principal

ph = PasswordHasher()


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def register_user(
    username: str,
    email: str,
    password: str,
    mode: str = "solo",
) -> User:
    """Register a new user and create their solo principal if mode=solo."""
    user = User(
        username=username,
        email=email.lower().strip(),
        password_hash=hash_password(password),
    )
    db.session.add(user)
    db.session.flush()

    if mode == "solo":
        principal = Principal(kind="solo", user_id=user.id)
        db.session.add(principal)
        db.session.flush()
        generate_flags_for_principal(principal)

    db.session.commit()
    return user
