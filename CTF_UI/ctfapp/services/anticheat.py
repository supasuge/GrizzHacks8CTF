import hmac

from flask import current_app

from ctfapp.models.submission import TeamFlag
from ctfapp.secure_log import write_event


def check_flag_sharing(
    submitting_principal_id: int,
    challenge_id: int,
    submitted_flag: str,
) -> dict | None:
    """Check if a wrong flag matches another principal's derived flag.

    Returns dict with sharing details if detected, None otherwise.
    """
    other_flags = (
        TeamFlag.query
        .filter_by(challenge_id=challenge_id)
        .filter(TeamFlag.principal_id != submitting_principal_id)
        .all()
    )

    for tf in other_flags:
        if hmac.compare_digest(submitted_flag.strip(), tf.flag_value):
            write_event(
                event_type="FLAG_SHARE_DETECTED",
                severity="CRITICAL",
                principal_id=submitting_principal_id,
                challenge_id=challenge_id,
                payload={
                    "shared_from_principal_id": tf.principal_id,
                    "submitting_principal_id": submitting_principal_id,
                },
            )
            return {
                "shared_from_principal_id": tf.principal_id,
                "submitting_principal_id": submitting_principal_id,
            }

    return None


def check_rate_limit(
    principal_id: int, challenge_id: int
) -> tuple[bool, int, int]:
    """Check submission rate limit (3 wrong in window = 30s lockout).

    Returns (allowed, remaining_attempts, retry_after_seconds).
    """
    from ctfapp.extensions import get_redis

    limit = current_app.config.get("FLAG_WRONG_LIMIT", 3)
    lockout = current_app.config.get("FLAG_LOCKOUT_SECONDS", 30)

    try:
        r = get_redis()
    except RuntimeError:
        return True, limit, 0  # No Redis -> allow (dev mode)

    lockout_key = f"lockout:{principal_id}:{challenge_id}"
    counter_key = f"wrong_count:{principal_id}:{challenge_id}"

    # Check lockout
    ttl = r.ttl(lockout_key)
    if ttl and ttl > 0:
        return False, 0, ttl

    # Check counter
    count = int(r.get(counter_key) or 0)
    if count >= limit:
        r.setex(lockout_key, lockout, "1")
        r.delete(counter_key)
        return False, 0, lockout

    return True, limit - count, 0


def record_wrong_attempt(principal_id: int, challenge_id: int) -> None:
    """Increment wrong-attempt counter in Redis."""
    from ctfapp.extensions import get_redis

    lockout = current_app.config.get("FLAG_LOCKOUT_SECONDS", 30)

    try:
        r = get_redis()
        counter_key = f"wrong_count:{principal_id}:{challenge_id}"
        pipe = r.pipeline()
        pipe.incr(counter_key)
        pipe.expire(counter_key, lockout)
        pipe.execute()
    except RuntimeError:
        pass


def clear_attempts(principal_id: int, challenge_id: int) -> None:
    """Clear wrong-attempt counter (called on correct solve)."""
    from ctfapp.extensions import get_redis

    try:
        r = get_redis()
        r.delete(f"wrong_count:{principal_id}:{challenge_id}")
        r.delete(f"lockout:{principal_id}:{challenge_id}")
    except RuntimeError:
        pass
