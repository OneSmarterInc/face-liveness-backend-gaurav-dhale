from __future__ import annotations

import hmac
from typing import Optional

from django.utils import timezone

from identity_verification.models import IdentityVerificationSession
from .exceptions import IdentityVerificationError


class SessionValidationError(IdentityVerificationError):
    """Raised when a verification session cannot be used."""

    pass


class SessionService:
    """
    Handles all verification-session related validation.

    This service intentionally contains no serializer logic and no
    liveness logic. It only answers one question:

        "Is this verification session still valid?"

    The caller (serializer/view/liveness engine) can safely assume that
    a returned session is usable.
    """

    TERMINAL_STATES = {
        IdentityVerificationSession.Status.COMPLETED,
        IdentityVerificationSession.Status.CANCELED,
        IdentityVerificationSession.Status.FAILED,
        IdentityVerificationSession.Status.EXPIRED,
    }

    @classmethod
    def get_session(cls, session: IdentityVerificationSession) -> IdentityVerificationSession:
        """
        Basic object validation.
        """
        if session is None:
            raise SessionValidationError("Verification session does not exist.")

        return session

    @classmethod
    def validate_nonce(
        cls,
        session: IdentityVerificationSession,
        session_nonce: str,
    ) -> None:
        """
        Constant-time nonce verification.
        """
        if not hmac.compare_digest(
            session.session_nonce,
            session_nonce,
        ):
            raise SessionValidationError("Invalid session nonce.")

    @classmethod
    def validate_expiry(
        cls,
        session: IdentityVerificationSession,
    ) -> None:
        """
        Reject expired sessions.
        """
        if session.expires_at <= timezone.now():
            raise SessionValidationError(
                "Verification session has expired."
            )

    @classmethod
    def validate_status(
        cls,
        session: IdentityVerificationSession,
    ) -> None:
        """
        Reject sessions that already reached a terminal state.
        """
        if session.status in cls.TERMINAL_STATES:
            raise SessionValidationError(
                f"Session is already {session.status}."
            )

        if session.consumed_at is not None:
            raise SessionValidationError(
                "Verification session has already been consumed."
            )

    @classmethod
    def validate_timestamps(
        cls,
        session: IdentityVerificationSession,
        started_at,
        completed_at,
    ) -> None:
        """
        Validate client timestamps against the issued session.
        """

        now = timezone.now()

        if completed_at < started_at:
            raise SessionValidationError(
                "Completion time must be after start time."
            )

        if started_at < session.created_at:
            raise SessionValidationError(
                "Verification started before the session was issued."
            )

        if completed_at > session.expires_at:
            raise SessionValidationError(
                "Verification completed after the session expired."
            )

        #
        # Small tolerance for client clock drift.
        #
        if completed_at > now + timezone.timedelta(minutes=1):
            raise SessionValidationError(
                "Completion timestamp is outside the acceptable clock window."
            )

    @classmethod
    def validate(
        cls,
        *,
        session: IdentityVerificationSession,
        session_nonce: str,
        started_at,
        completed_at,
    ) -> IdentityVerificationSession:
        """
        Complete session validation pipeline.

        Order matters:
            1. object exists
            2. nonce
            3. expiry
            4. state
            5. timestamps
        """

        cls.get_session(session)

        cls.validate_nonce(
            session=session,
            session_nonce=session_nonce,
        )

        cls.validate_expiry(session)

        cls.validate_status(session)

        cls.validate_timestamps(
            session=session,
            started_at=started_at,
            completed_at=completed_at,
        )

        return session