from __future__ import annotations

from collections import defaultdict

from .exceptions import IdentityVerificationError


class ChallengeValidationError(IdentityVerificationError):
    """Raised when challenge evidence is invalid."""

    pass


class ChallengeValidator:
    """
    Validates that the client actually executed the challenge sequence
    issued by the backend.

    Responsibilities
    ----------------
    • Challenge sequence integrity
    • Event structure
    • Challenge ordering
    • Duplicate detection
    • Timestamp consistency
    • Completion status

    NOTE:
    This validator DOES NOT determine whether the user actually turned
    left/right/blinked correctly. That belongs to LivenessEngine.
    """

    REQUIRED_EVENT_FIELDS = (
        "challenge",
        "started_at",
        "completed_at",
    )

    # ------------------------------------------------------------------ #

    @classmethod
    def validate(
        cls,
        *,
        issued_sequence: list[str],
        submitted_sequence: list[str],
        challenge_events: list[dict],
    ) -> dict:
        """
        Main entrypoint.
        """

        cls._validate_sequences(
            issued_sequence,
            submitted_sequence,
        )

        cls._validate_events(
            challenge_events
        )

        cls._validate_event_order(
            issued_sequence,
            challenge_events,
        )

        return cls._build_summary(
            issued_sequence,
            challenge_events,
        )

    # ------------------------------------------------------------------ #

    @classmethod
    def _validate_sequences(
        cls,
        issued,
        submitted,
    ):

        if issued is None:
            raise ChallengeValidationError(
                "Issued challenge sequence is missing."
            )

        if submitted is None:
            raise ChallengeValidationError(
                "Submitted challenge sequence is missing."
            )

        if issued != submitted:
            raise ChallengeValidationError(
                "Challenge sequence mismatch."
            )

    # ------------------------------------------------------------------ #

    @classmethod
    def _validate_events(
        cls,
        events,
    ):

        if not isinstance(events, list):
            raise ChallengeValidationError(
                "Challenge events must be an array."
            )

        if len(events) == 0:
            raise ChallengeValidationError(
                "Challenge events are missing."
            )

        seen = set()

        for index, event in enumerate(events):

            for field in cls.REQUIRED_EVENT_FIELDS:

                if field not in event:
                    raise ChallengeValidationError(
                        f"Challenge event {index} missing '{field}'."
                    )

            challenge = event["challenge"]

            if challenge in seen:
                raise ChallengeValidationError(
                    f"Duplicate challenge '{challenge}'."
                )

            seen.add(challenge)

            started = event["started_at"]
            completed = event["completed_at"]

            if completed < started:
                raise ChallengeValidationError(
                    f"Challenge '{challenge}' completed before it started."
                )

    # ------------------------------------------------------------------ #

    @classmethod
    def _validate_event_order(
        cls,
        issued_sequence,
        events,
    ):

        submitted = [
            e["challenge"]
            for e in events
        ]

        if submitted != issued_sequence:
            raise ChallengeValidationError(
                "Challenge execution order does not match issued order."
            )

    # ------------------------------------------------------------------ #

    @classmethod
    def _build_summary(
        cls,
        sequence,
        events,
    ):

        durations = {}
        total_duration = 0

        chronological = True

        previous_completed = None

        for event in events:

            duration = (
                event["completed_at"]
                - event["started_at"]
            ).total_seconds()

            durations[event["challenge"]] = duration

            total_duration += duration

            if previous_completed is not None:

                if event["started_at"] < previous_completed:
                    chronological = False

            previous_completed = event["completed_at"]

        completed = {
            event["challenge"]
            for event in events
        }

        missing = [
            challenge
            for challenge in sequence
            if challenge not in completed
        ]

        return {
            "challenge_count": len(events),
            "completed_count": len(completed),
            "missing_challenges": missing,
            "durations": durations,
            "total_duration_seconds": total_duration,
            "chronological": chronological,
            "sequence": sequence,
        }