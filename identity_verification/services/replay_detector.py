from __future__ import annotations

import hashlib
import json
import logging
from datetime import timedelta

from django.utils import timezone

from identity_verification.models import IdentityVerificationResult
from .exceptions import IdentityVerificationError

security_logger = logging.getLogger("security")

# No HTTP request is available this deep in the pipeline, so the
# request-scoped fields the "verbose" formatter expects are filled with
# placeholders rather than threaded down from the view.
_NO_REQUEST_CONTEXT = {"path": "identity_verification.services.replay_detector", "method": "INTERNAL", "duration": 0.0, "ip": "-"}


class ReplayDetectionError(IdentityVerificationError):
    """
    Raised when duplicated evidence or replayed submissions
    are detected.
    """

    pass


class ReplayDetector:
    """
    Detect replay attacks using submitted liveness evidence.

    Responsibilities
    ----------------
    • Generate deterministic evidence fingerprint
    • Prevent reuse of verification session
    • Detect duplicate evidence across recent sessions

    This service DOES NOT:

    - determine liveness
    - compare face embeddings
    - write to the database
    """

    REPLAY_LOOKBACK = timedelta(hours=24)

    # -------------------------------------------------------------

    @classmethod
    def validate(
        cls,
        *,
        verification_session,
        payload: dict,
    ) -> dict:

        fingerprint = cls.generate_fingerprint(payload)

        cls._check_session_reuse(
            verification_session,
        )

        replay_detected = cls._is_recent_replay(
            verification_session,
            fingerprint,
        )

        if replay_detected:
            security_logger.warning(
                "Replay attack detected: identical evidence resubmitted",
                extra={
                    **_NO_REQUEST_CONTEXT,
                    "status": "replay_detected",
                    "user": verification_session.account_id,
                },
            )
            raise ReplayDetectionError(
                "Replay attack detected."
            )

        return {
            "fingerprint": fingerprint,
            "replay_detected": False,
        }

    # -------------------------------------------------------------

    @staticmethod
    def generate_fingerprint(
        payload: dict,
    ) -> str:
        """
        Produce a deterministic fingerprint from replay-relevant
        evidence only.
        """

        evidence = {
            "challenge_sequence": payload.get(
                "challenge_sequence"
            ),
            "challenge_events": payload.get(
                "challenge_events"
            ),
            "telemetry": payload.get(
                "telemetry"
            ),
            "capture": payload.get(
                "capture"
            ),
        }

        serialized = json.dumps(
            evidence,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

    # -------------------------------------------------------------

    @staticmethod
    def _check_session_reuse(
        verification_session,
    ) -> None:
        """
        A verification session can only be consumed once.
        """

        if verification_session.consumed_at is not None:
            security_logger.warning(
                "Replay attack detected: already-consumed session reused",
                extra={
                    **_NO_REQUEST_CONTEXT,
                    "status": "session_reuse",
                    "user": verification_session.account_id,
                },
            )
            raise ReplayDetectionError(
                "Verification session has already been used."
            )

    # -------------------------------------------------------------

    @classmethod
    def _is_recent_replay(
        cls,
        verification_session,
        fingerprint: str,
    ) -> bool:
        """
        Check whether identical evidence has been submitted
        recently by another session.
        """

        since = timezone.now() - cls.REPLAY_LOOKBACK

        return IdentityVerificationResult.objects.filter(
            evidence_fingerprint=fingerprint,
            received_at__gte=since,
        ).exclude(
            session=verification_session,
        ).exists()