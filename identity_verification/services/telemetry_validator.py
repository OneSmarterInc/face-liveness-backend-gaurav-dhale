from __future__ import annotations

from collections import Counter
from statistics import mean

from .exceptions import IdentityVerificationError


class TelemetryValidationError(IdentityVerificationError):
    """Raised when telemetry evidence is invalid."""

    pass


class TelemetryValidator:
    """
    Validates raw telemetry sent by the frontend.

    This service validates only the structure and consistency of the
    telemetry evidence. It does NOT decide whether liveness passed.

    Responsibilities:
        • Required fields
        • Data types
        • Timestamp ordering
        • Face continuity
        • Duplicate timestamps
        • Basic motion consistency
    """

    REQUIRED_FIELDS = (
        "t",
        "yaw",
        "pitch",
        "roll",
        "ear_left",
        "ear_right",
        "face_detected",
    )

    MIN_FRAME_COUNT = 20
    MAX_FRAME_COUNT = 5000

    MAX_ABS_YAW = 90.0
    MAX_ABS_PITCH = 90.0
    MAX_ABS_ROLL = 180.0

    MAX_TIMESTAMP_GAP_MS = 1500

    MIN_FACE_VISIBLE_RATIO = 0.80

    # ---------------------------------------------------------

    @classmethod
    def validate(cls, telemetry: list[dict]) -> dict:
        """
        Main validation entrypoint.

        Returns a telemetry summary which can later be reused by
        the liveness engine instead of recalculating statistics.
        """

        cls._validate_root(telemetry)
        cls._validate_required_fields(telemetry)
        cls._validate_types(telemetry)
        cls._validate_timestamps(telemetry)
        cls._validate_ranges(telemetry)
        cls._validate_face_presence(telemetry)

        return cls._build_summary(telemetry)

    # ---------------------------------------------------------

    @classmethod
    def _validate_root(cls, telemetry):

        if telemetry is None:
            raise TelemetryValidationError(
                "Telemetry is missing."
            )

        if not isinstance(telemetry, list):
            raise TelemetryValidationError(
                "Telemetry must be an array."
            )

        if len(telemetry) < cls.MIN_FRAME_COUNT:
            raise TelemetryValidationError(
                "Insufficient telemetry frames."
            )

        if len(telemetry) > cls.MAX_FRAME_COUNT:
            raise TelemetryValidationError(
                "Telemetry exceeds maximum allowed size."
            )

    # ---------------------------------------------------------

    @classmethod
    def _validate_required_fields(cls, telemetry):

        for index, frame in enumerate(telemetry):

            for field in cls.REQUIRED_FIELDS:

                if field not in frame:
                    raise TelemetryValidationError(
                        f"Telemetry frame {index} missing '{field}'."
                    )

    # ---------------------------------------------------------

    @classmethod
    def _validate_types(cls, telemetry):

        bool_fields = {
            "face_detected",
        }

        numeric_fields = {
            "t",
            "yaw",
            "pitch",
            "roll",
            "ear_left",
            "ear_right",
        }

        for index, frame in enumerate(telemetry):

            for field in numeric_fields:

                if not isinstance(frame[field], (int, float)):
                    raise TelemetryValidationError(
                        f"Telemetry frame {index} field '{field}' must be numeric."
                    )

            for field in bool_fields:

                if not isinstance(frame[field], bool):
                    raise TelemetryValidationError(
                        f"Telemetry frame {index} field '{field}' must be boolean."
                    )

    # ---------------------------------------------------------

    @classmethod
    def _validate_timestamps(cls, telemetry):

        timestamps = [frame["t"] for frame in telemetry]

        duplicates = [
            value
            for value, count in Counter(timestamps).items()
            if count > 1
        ]

        if duplicates:
            raise TelemetryValidationError(
                "Duplicate telemetry timestamps detected."
            )

        previous = None

        for value in timestamps:

            if previous is not None:

                if value <= previous:
                    raise TelemetryValidationError(
                        "Telemetry timestamps are not strictly increasing."
                    )

                if value - previous > cls.MAX_TIMESTAMP_GAP_MS:
                    raise TelemetryValidationError(
                        "Large telemetry timestamp gap detected."
                    )

            previous = value

    # ---------------------------------------------------------

    @classmethod
    def _validate_ranges(cls, telemetry):

        for index, frame in enumerate(telemetry):

            yaw = frame["yaw"]
            pitch = frame["pitch"]
            roll = frame["roll"]

            if abs(yaw) > cls.MAX_ABS_YAW:
                raise TelemetryValidationError(
                    f"Telemetry frame {index} contains invalid yaw."
                )

            if abs(pitch) > cls.MAX_ABS_PITCH:
                raise TelemetryValidationError(
                    f"Telemetry frame {index} contains invalid pitch."
                )

            if abs(roll) > cls.MAX_ABS_ROLL:
                raise TelemetryValidationError(
                    f"Telemetry frame {index} contains invalid roll."
                )

    # ---------------------------------------------------------

    @classmethod
    def _validate_face_presence(cls, telemetry):

        detected = sum(
            1
            for frame in telemetry
            if frame["face_detected"]
        )

        ratio = detected / len(telemetry)

        if ratio < cls.MIN_FACE_VISIBLE_RATIO:
            raise TelemetryValidationError(
                "Face was not visible for sufficient duration."
            )

    # ---------------------------------------------------------

    @classmethod
    def _build_summary(cls, telemetry):

        yaw = [f["yaw"] for f in telemetry]
        pitch = [f["pitch"] for f in telemetry]
        roll = [f["roll"] for f in telemetry]

        detected = sum(
            1
            for frame in telemetry
            if frame["face_detected"]
        )

        return {
            "frame_count": len(telemetry),
            "face_visible_ratio": detected / len(telemetry),
            "yaw_min": min(yaw),
            "yaw_max": max(yaw),
            "pitch_min": min(pitch),
            "pitch_max": max(pitch),
            "roll_min": min(roll),
            "roll_max": max(roll),
            "avg_yaw": mean(yaw),
            "avg_pitch": mean(pitch),
            "avg_roll": mean(roll),
            "start_timestamp": telemetry[0]["t"],
            "end_timestamp": telemetry[-1]["t"],
            "duration_ms": telemetry[-1]["t"] - telemetry[0]["t"],
        }