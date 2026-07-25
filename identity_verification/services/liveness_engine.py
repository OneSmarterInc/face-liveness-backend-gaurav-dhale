from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Dict, List

from .exceptions import IdentityVerificationError

from statistics import median, variance

class LivenessDecisionError(IdentityVerificationError):
    """Raised when liveness evaluation cannot be completed."""
    pass

@dataclass
class QualityMetrics:
    motion_score: float
    stability_score: float
    confidence: float

@dataclass
class ChallengeResult:
    challenge: str
    passed: bool
    score: float
    reason: str
    quality: QualityMetrics

from django.conf import settings


class LivenessEngine:
    """
    Server-side liveness evaluation engine.
    """

    #
    # Motion thresholds (degrees)
    #

    LEFT_YAW = settings.IDENTITY_VERIFICATION["yaw"]["left"]
    RIGHT_YAW = settings.IDENTITY_VERIFICATION["yaw"]["right"]
    CENTER_YAW = settings.IDENTITY_VERIFICATION["yaw"]["center"]

    #
    # Blink threshold
    #

    BLINK_EAR = settings.IDENTITY_VERIFICATION["blink"]["ear_threshold"]

    #
    # Hold still thresholds
    #

    HOLD_STILL_MAX_YAW_RANGE = settings.IDENTITY_VERIFICATION["hold_still"]["max_yaw_range"]
    HOLD_STILL_MAX_PITCH_RANGE = settings.IDENTITY_VERIFICATION["hold_still"]["max_pitch_range"]

    #
    # Minimum global score
    #

    PASS_SCORE = settings.IDENTITY_VERIFICATION["liveness"]["minimum_score"]

    # ------------------------------------------------------------ #

    #
    # Extra time (ms) added on each side of a challenge's own
    # started_at/completed_at window before slicing telemetry.
    #
    CHALLENGE_PADDING_MS = {
        "turn_left": 400,
        "turn_right": 400,
        "blink": 400,
        "center_face": 0,
        "hold_still": 0,
    }

    @classmethod
    def _get_frames_for_challenge(
        cls,
        telemetry: List[dict],
        challenge_events: List[dict],
        challenge: str,
        session_started_at=None,
    ) -> List[dict]:

        index = next(
            (
                i
                for i, e in enumerate(challenge_events)
                if e.get("challenge") == challenge
            ),
            None,
        )

        if index is None:
            return []
        
        

        event = challenge_events[index]

        start_dt = event["started_at"]
        end_dt = event["completed_at"]

        padding = timedelta(
            milliseconds=cls.CHALLENGE_PADDING_MS.get(challenge, 0)
        )

        start_dt = start_dt - padding
        end_dt = end_dt + padding
 
        if index > 0:
            previous_event = challenge_events[index - 1]
            start_dt = max(start_dt, previous_event["started_at"])

        if index < len(challenge_events) - 1:
            next_event = challenge_events[index + 1]
            end_dt = min(end_dt, next_event["completed_at"])

        if session_started_at is not None:
            start = (start_dt - session_started_at).total_seconds() * 1000
            end = (end_dt - session_started_at).total_seconds() * 1000
        else:
            start, end = start_dt, end_dt

        frames = [
            frame
            for frame in telemetry
            if start <= frame["t"] <= end
        ]

        return cls._normalize_frames(frames)
    
    @classmethod
    def _median_filter(
        cls,
        values: List[float],
    ) -> List[float]:

        if len(values) < 3:
            return values

        filtered = [values[0]]

        for i in range(1, len(values) - 1):
            filtered.append(
                median(
                    [
                        values[i - 1],
                        values[i],
                        values[i + 1],
                    ]
                )
            )

        filtered.append(values[-1])

        return filtered


    # ------------------------------------------------------------ #

    @classmethod
    def _normalize_frames(
        cls,
        frames: List[dict],
    ) -> List[dict]:

        cleaned = []

        for frame in frames:

            yaw = frame.get("yaw")
            pitch = frame.get("pitch")
            roll = frame.get("roll")
            t = frame.get("t")

            if (
                yaw is None
                or pitch is None
                or roll is None
                or t is None
            ):
                continue

            if not (
                -90 <= yaw <= 90
                and -90 <= pitch <= 90
                and -90 <= roll <= 90
            ):
                continue

            corrected = frame.copy()

            corrected["yaw"] = -yaw

            cleaned.append(corrected)

        if not cleaned:
            return []

        cleaned.sort(
            key=lambda frame: frame["t"]
        )

        unique = []
        seen = set()

        for frame in cleaned:

            ts = frame["t"]

            if ts in seen:
                continue

            seen.add(ts)
            unique.append(frame)

        if len(unique) < 3:
            return unique

        yaw = cls._median_filter(
            [f["yaw"] for f in unique]
        )

        pitch = cls._median_filter(
            [f["pitch"] for f in unique]
        )

        roll = cls._median_filter(
            [f["roll"] for f in unique]
        )

        for i, frame in enumerate(unique):

            frame["yaw"] = yaw[i]
            frame["pitch"] = pitch[i]
            frame["roll"] = roll[i]

        return unique
    
    @classmethod
    def _clamp(
        cls,
        value: float,
        minimum: float = 0.0,
        maximum: float = 1.0,
    ) -> float:
        return max(minimum, min(value, maximum))


    # ------------------------------------------------------------ #

    @classmethod
    def _calculate_motion_score(
        cls,
        actual_rotation: float,
        required_rotation: float,
    ) -> float:

        if required_rotation <= 0:
            return 0.0

        return cls._clamp(
            actual_rotation / required_rotation
        )


    # ------------------------------------------------------------ #

    @classmethod
    def _calculate_stability_score(
        cls,
        telemetry: List[dict],
    ) -> float:

        if len(telemetry) < 2:
            return 1.0

        yaw = [frame["yaw"] for frame in telemetry]
        pitch = [frame["pitch"] for frame in telemetry]
        roll = [frame["roll"] for frame in telemetry]

        try:

            total_variance = (
                variance(yaw)
                + variance(pitch)
                + variance(roll)
            ) / 3.0

        except Exception:
            total_variance = 0.0

        return cls._clamp(
            1.0 - (total_variance / 25.0)
        )


    # ------------------------------------------------------------ #

    @classmethod
    def _calculate_center_score(
        cls,
        telemetry: List[dict],
    ) -> float:

        if not telemetry:
            return 0.0

        deviation = (
            sum(abs(frame["yaw"]) for frame in telemetry)
            / len(telemetry)
        )

        return cls._clamp(
            1.0 - (
                deviation /
                max(cls.CENTER_YAW, 1)
            )
        )


    # ------------------------------------------------------------ #

    @classmethod
    def _calculate_blink_score(
        cls,
        telemetry: List[dict],
    ) -> float:

        if not telemetry:
            return 0.0

        ear_values = [
            (
                frame["ear_left"]
                + frame["ear_right"]
            ) / 2
            for frame in telemetry
        ]

        minimum = min(ear_values)
        maximum = max(ear_values)

        depth = maximum - minimum

        return cls._clamp(
            depth / cls.BLINK_EAR
        )


    # ------------------------------------------------------------ #

    @classmethod
    def _calculate_hold_still_score(
        cls,
        telemetry: List[dict],
    ) -> float:

        if len(telemetry) < 2:
            return 1.0

        deltas = []

        for previous, current in zip(
            telemetry,
            telemetry[1:],
        ):

            deltas.append(
                abs(current["yaw"] - previous["yaw"])
            )

            deltas.append(
                abs(current["pitch"] - previous["pitch"])
            )

            deltas.append(
                abs(current["roll"] - previous["roll"])
            )

        average_delta = (
            sum(deltas)
            / len(deltas)
        )

        threshold = max(
            settings.IDENTITY_VERIFICATION[
                "hold_still"
            ]["max_frame_delta_yaw"],
            1,
        )

        return cls._clamp(
            1.0 - (
                average_delta /
                threshold
            )
        )


    # ------------------------------------------------------------ #

    @classmethod
    def _calculate_confidence(
        cls,
        motion_score: float,
        stability_score: float,
    ) -> float:

        return round(
            (
                motion_score * 0.6
                + stability_score * 0.4
            ),
            3,
        )

    # ------------------------------------------------------------ #

    @classmethod
    def _validate_turn(
        cls,
        telemetry: List[dict],
        *,
        threshold: float,
        direction: str,
    ) -> ChallengeResult:

        if len(telemetry) < 3:
            return ChallengeResult(
                challenge=f"turn_{direction}",
                passed=False,
                score=0.0,
                reason="Insufficient telemetry.",
            )

        yaw = [frame["yaw"] for frame in telemetry]

        state = "WAITING"
        reached = 0

        for value in yaw:

            if state == "WAITING":

                if abs(value) <= cls.CENTER_YAW:
                    state = "MOVING"

            elif state == "MOVING":

                if direction == "left":

                    if value <= threshold:
                        state = "TARGET_REACHED"
                        reached = 1

                else:

                    if value >= threshold:
                        state = "TARGET_REACHED"
                        reached = 1

            elif state == "TARGET_REACHED":

                if direction == "left":

                    if value <= threshold:
                        reached += 1

                else:

                    if value >= threshold:
                        reached += 1

        passed = reached >= settings.IDENTITY_VERIFICATION[
            "turn"
        ]["minimum_stable_frames"]

        required_rotation = abs(threshold)

        actual_rotation = abs(
            min(yaw) if direction == "left" else max(yaw)
        )

        rotation_score = cls._clamp(
            actual_rotation / (required_rotation * 1.5)
        )


        minimum_frames = settings.IDENTITY_VERIFICATION[
            "turn"
        ]["minimum_stable_frames"]

        hold_score = cls._clamp(
            reached / (minimum_frames * 2)
        )

        stability_score = cls._calculate_stability_score(
            telemetry,
        )

        confidence = round(
            (
                rotation_score * 0.50
                + hold_score * 0.30
                + stability_score * 0.20
            ),
            3,
        )


        return ChallengeResult(
            challenge=f"turn_{direction}",
            passed=passed,
            score=confidence,
            reason=(
                f"{direction.capitalize()} turn detected."
                if passed
                else f"Invalid {direction} turn."
            ),
            quality=QualityMetrics(
                motion_score=round(rotation_score, 3),
                stability_score=round(stability_score, 3),
                confidence=confidence,
            ),
        )


    # ------------------------------------------------------------ #

    @classmethod
    def _validate_center(
        cls,
        telemetry: List[dict],
    ) -> ChallengeResult:

        consecutive = 0
        maximum = 0

        for frame in telemetry:

            if abs(frame["yaw"]) <= cls.CENTER_YAW:

                consecutive += 1
                maximum = max(maximum, consecutive)

            else:

                consecutive = 0

        required = settings.IDENTITY_VERIFICATION[
            "center_face"
        ]["minimum_consecutive_frames"]

        motion_score = cls._calculate_center_score(
            telemetry,
        )

        stability_score = cls._calculate_stability_score(
            telemetry,
        )

        confidence = cls._calculate_confidence(
            motion_score,
            stability_score,
        )

        center_frames = sum(
            1 for frame in telemetry
            if abs(frame["yaw"]) <= cls.CENTER_YAW
        )

        ratio = (
            center_frames / len(telemetry)
            if telemetry else 0.0
        )

        passed = (
            ratio >= 0.80
            and maximum >= 4
        )


        return ChallengeResult(
            challenge="center_face",
            passed=passed,
            score=confidence,
            reason=(
                "Face centered."
                if passed
                else "Face not centered."
            ),
            quality=QualityMetrics(
                motion_score=round(motion_score, 3),
                stability_score=round(stability_score, 3),
                confidence=confidence,
            ),
        )


    # ------------------------------------------------------------ #

    @classmethod
    def _validate_blink(
        cls,
        telemetry: List[dict],
    ) -> ChallengeResult:

        OPEN = 0
        CLOSED = 1
        OPEN_AGAIN = 2

        state = OPEN

        for frame in telemetry:

            closed = (
                frame["ear_left"] < cls.BLINK_EAR
                and frame["ear_right"] < cls.BLINK_EAR
            )

            if state == OPEN:

                if closed:
                    state = CLOSED

            elif state == CLOSED:

                if not closed:
                    state = OPEN_AGAIN
                    break

        passed = state == OPEN_AGAIN

        motion_score = cls._calculate_blink_score(
            telemetry,
        )

        stability_score = 1.0

        confidence = cls._calculate_confidence(
            motion_score,
            stability_score,
        )

        return ChallengeResult(
            challenge="blink",
            passed=passed,
            score=confidence,
            reason=(
                "Blink detected."
                if passed
                else "Blink not detected."
            ),
            quality=QualityMetrics(
                motion_score=round(motion_score, 3),
                stability_score=1.0,
                confidence=confidence,
            ),
        )


    # ------------------------------------------------------------ #

    @classmethod
    def _validate_hold_still(
        cls,
        telemetry: List[dict],
    ) -> ChallengeResult:

        if len(telemetry) < 2:
            return ChallengeResult(
                challenge="hold_still",
                passed=False,
                score=0.0,
                reason="Insufficient telemetry.",
                quality=QualityMetrics(
                    motion_score=0.0,
                    stability_score=0.0,
                    confidence=0.0,
                ),
            )

        max_yaw_delta = settings.IDENTITY_VERIFICATION[
            "hold_still"
        ]["max_frame_delta_yaw"]

        max_pitch_delta = settings.IDENTITY_VERIFICATION[
            "hold_still"
        ]["max_frame_delta_pitch"]

        max_roll_delta = settings.IDENTITY_VERIFICATION[
            "hold_still"
        ]["max_frame_delta_roll"]

        yaw_violations = 0
        pitch_violations = 0
        roll_violations = 0

        max_actual_yaw_delta = 0.0
        max_actual_pitch_delta = 0.0
        max_actual_roll_delta = 0.0

        for previous, current in zip(
            telemetry,
            telemetry[1:],
        ):

            yaw_delta = abs(current["yaw"] - previous["yaw"])
            pitch_delta = abs(current["pitch"] - previous["pitch"])
            roll_delta = abs(current["roll"] - previous["roll"])

            max_actual_yaw_delta = max(
                max_actual_yaw_delta,
                yaw_delta,
            )

            max_actual_pitch_delta = max(
                max_actual_pitch_delta,
                pitch_delta,
            )

            max_actual_roll_delta = max(
                max_actual_roll_delta,
                roll_delta,
            )

            if yaw_delta > max_yaw_delta:
                yaw_violations += 1

            if pitch_delta > max_pitch_delta:
                pitch_violations += 1

            if roll_delta > max_roll_delta:
                roll_violations += 1

        total_pairs = max(len(telemetry) - 1, 1)

        allowed_violations = max(
            1,
            int(total_pairs * 0.10),
        )

        passed = (
            yaw_violations <= allowed_violations
            and pitch_violations <= allowed_violations
            and roll_violations <= allowed_violations
        )

        motion_score = cls._calculate_hold_still_score(
            telemetry,
        )

        stability_score = cls._calculate_stability_score(
            telemetry,
        )

        confidence = cls._calculate_confidence(
            motion_score,
            stability_score,
        )

        return ChallengeResult(
            challenge="hold_still",
            passed=passed,
            score=confidence,
            reason=(
                "Stable pose."
                if passed
                else "Too much movement."
            ),
            quality=QualityMetrics(
                motion_score=round(motion_score, 3),
                stability_score=round(stability_score, 3),
                confidence=confidence,
            ),
        )

    @classmethod
    def evaluate(
        cls,
        *,
        telemetry: List[dict],
        telemetry_summary: Dict,
        challenge_summary: Dict,
        replay_result: Dict,
        challenge_events: List[dict],
        session_started_at=None,
    ) -> Dict:

        if replay_result["replay_detected"]:
            return {
                "passed": False,
                "score": 0.0,
                "reason": "Replay detected.",
                "challenge_results": [],
                "metrics": telemetry_summary,
            }

        results = []

        for challenge in challenge_summary["sequence"]:

            frames = cls._get_frames_for_challenge(
                telemetry,
                challenge_events,
                challenge,
                session_started_at=session_started_at,
            )

            if not frames:
                results.append(
                    ChallengeResult(
                        challenge=challenge,
                        passed=False,
                        score=0.0,
                        reason="No telemetry for challenge.",
                        quality=QualityMetrics(
                            motion_score=0.0,
                            stability_score=0.0,
                            confidence=0.0,
                        ),
                    )
                )
                continue

            if challenge == "turn_left":
                results.append(
                    cls._evaluate_left(frames)
                )

            elif challenge == "turn_right":
                results.append(
                    cls._evaluate_right(frames)
                )

            elif challenge == "center_face":
                results.append(
                    cls._evaluate_center(frames)
                )

            elif challenge == "blink":
                results.append(
                    cls._evaluate_blink(frames)
                )

            elif challenge == "hold_still":
                results.append(
                    cls._evaluate_hold_still(frames)
                )

        score = (
            sum(r.score for r in results)
            / len(results)
        ) if results else 0.0

        passed = (
            score >= cls.PASS_SCORE
            and all(r.passed for r in results)
        )

        res = {
            "passed": passed,
            "score": round(score, 3),
            "reason": (
                "Liveness verified."
                if passed
                else "Challenge requirements not satisfied."
            ),
            "challenge_results": [
                {
                    "challenge": r.challenge,
                    "passed": r.passed,
                    "score": round(r.score, 3),
                    "reason": r.reason,
                }
                for r in results
            ],
            "metrics": telemetry_summary,
        }
        print(res)

        return res

    # ------------------------------------------------------------ #

    @classmethod
    def _evaluate_left(
        cls,
        telemetry,
    ):
        return cls._validate_turn(
            telemetry,
            threshold=cls.LEFT_YAW,
            direction="left",
        )

    # ------------------------------------------------------------ #

    @classmethod
    def _evaluate_right(
        cls,
        telemetry,
    ):
        return cls._validate_turn(
            telemetry,
            threshold=cls.RIGHT_YAW,
            direction="right",
        )

    # ------------------------------------------------------------ #

    @classmethod
    def _evaluate_center(
        cls,
        telemetry,
    ):
        return cls._validate_center(
            telemetry,
        )

    # ------------------------------------------------------------ #

    @classmethod
    def _evaluate_blink(
        cls,
        telemetry,
    ):
        return cls._validate_blink(
            telemetry,
        )

    # ------------------------------------------------------------ #

    @classmethod
    def _evaluate_hold_still(
        cls,
        telemetry,
    ):
        return cls._validate_hold_still(
            telemetry,
        )