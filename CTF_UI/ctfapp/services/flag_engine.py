import hmac
import hashlib

from flask import current_app

from ctfapp.extensions import db, get_redis
from ctfapp.models.submission import TeamFlag


def derive_flag(admin_key: bytes, team_secret: bytes, challenge_id: int) -> str:
    """Derive a per-principal, per-challenge flag using HMAC-SHA3-256."""
    msg = team_secret + challenge_id.to_bytes(4, "big")
    digest = hmac.new(admin_key, msg, hashlib.sha3_256).hexdigest()
    return f"GRIZZ{{{digest[:32]}}}"


def verify_flag(
    submitted: str,
    admin_key: bytes,
    team_secret: bytes,
    challenge_id: int,
) -> bool:
    """Constant-time verify a submitted flag against the derived expected value."""
    expected = derive_flag(admin_key, team_secret, challenge_id)
    return hmac.compare_digest(submitted.strip(), expected)


def generate_flags_for_principal(principal) -> list[TeamFlag]:
    """Pre-generate flags for all visible challenges for a principal.

    Stores in DB (TeamFlag) and Redis (HSET team_flags:<principal_id>).
    """
    from ctfapp.models.challenge import Challenge

    admin_key = current_app.config["ADMIN_KEY"]
    challenges = Challenge.query.filter_by(status="visible").all()
    created = []

    for chal in challenges:
        flag_value = derive_flag(admin_key, principal.team_secret, chal.id)

        existing = TeamFlag.query.filter_by(
            principal_id=principal.id, challenge_id=chal.id
        ).first()
        if existing:
            existing.flag_value = flag_value
        else:
            tf = TeamFlag(
                principal_id=principal.id,
                challenge_id=chal.id,
                flag_value=flag_value,
            )
            db.session.add(tf)
            created.append(tf)

    db.session.flush()

    # Mirror to Redis
    try:
        r = get_redis()
        key = f"team_flags:{principal.id}"
        pipe = r.pipeline()
        for chal in challenges:
            flag_value = derive_flag(admin_key, principal.team_secret, chal.id)
            pipe.hset(key, str(chal.id), flag_value)
        pipe.execute()
    except Exception:
        pass  # Redis optional — DB is source of truth

    return created


def generate_flags_for_challenge(challenge) -> None:
    """When admin adds a new challenge, generate flags for all existing principals."""
    from ctfapp.models.principal import Principal

    admin_key = current_app.config["ADMIN_KEY"]
    principals = Principal.query.filter_by(active=True).all()

    for principal in principals:
        flag_value = derive_flag(admin_key, principal.team_secret, challenge.id)
        existing = TeamFlag.query.filter_by(
            principal_id=principal.id, challenge_id=challenge.id
        ).first()
        if not existing:
            db.session.add(
                TeamFlag(
                    principal_id=principal.id,
                    challenge_id=challenge.id,
                    flag_value=flag_value,
                )
            )

    db.session.flush()

    # Mirror to Redis
    try:
        r = get_redis()
        pipe = r.pipeline()
        for principal in principals:
            flag_value = derive_flag(admin_key, principal.team_secret, challenge.id)
            pipe.hset(f"team_flags:{principal.id}", str(challenge.id), flag_value)
        pipe.execute()
    except Exception:
        pass


def get_flag_for_principal(principal_id: int, challenge_id: int) -> str | None:
    """Lookup flag from Redis (fast) or DB (fallback)."""
    try:
        r = get_redis()
        flag = r.hget(f"team_flags:{principal_id}", str(challenge_id))
        if flag:
            return flag
    except Exception:
        pass

    tf = TeamFlag.query.filter_by(
        principal_id=principal_id, challenge_id=challenge_id
    ).first()
    return tf.flag_value if tf else None
