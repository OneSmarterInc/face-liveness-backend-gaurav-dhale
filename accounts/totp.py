from __future__ import annotations

import hashlib
import logging
import secrets

import pyotp
from django.core.cache import cache

security_logger = logging.getLogger("security")

BACKUP_CODE_COUNT = 10
BACKUP_CODE_LENGTH = 10
BACKUP_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

_TOTP_USED_KEY_PREFIX = "totp:used:"
_TOTP_USED_TTL = 90  # covers valid_window=1 (three 30-second slots)

# No HTTP request is available this deep in the TOTP layer, so the
# request-scoped fields the "verbose" formatter expects are filled with
# placeholders rather than threaded down from the view.
_NO_REQUEST_CONTEXT = {"path": "totp.verify_totp_code", "method": "INTERNAL", "duration": 0.0, "ip": "-"}


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def build_provisioning_uri(secret: str, user_email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=user_email, issuer_name="Korgut Commons")


def verify_totp_code(secret: str, code: str, *, user_id=None) -> bool:
    if not code or not code.isdigit() or len(code) != 6:
        return False

    if user_id is not None:
        replay_key = f"{_TOTP_USED_KEY_PREFIX}{user_id}:{code}"
        if cache.get(replay_key):
            security_logger.warning(
                "TOTP code replay attempt rejected",
                extra={**_NO_REQUEST_CONTEXT, "status": "replay_detected", "user": user_id},
            )
            return False

    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return False

    if user_id is not None:
        cache.set(replay_key, True, timeout=_TOTP_USED_TTL)

    return True


def generate_backup_codes() -> list[str]:
    return [
        "".join(secrets.choice(BACKUP_CODE_ALPHABET) for _ in range(BACKUP_CODE_LENGTH))
        for _ in range(BACKUP_CODE_COUNT)
    ]


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()
