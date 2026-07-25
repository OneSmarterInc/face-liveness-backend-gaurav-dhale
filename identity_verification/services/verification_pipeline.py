from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List

from django.utils import timezone
from rest_framework.exceptions import ValidationError

from .challenge_validator import ChallengeValidator
from .exceptions import IdentityVerificationError
from .liveness_engine import LivenessEngine
from .replay_detector import ReplayDetector
from .session_service import SessionService
from .telemetry_validator import TelemetryValidator
from .verification_context import (
    VerificationContext,
)


# ==========================================================
# Base Pipeline Stage
# ==========================================================


class PipelineStage:
    """
    Base class for every verification pipeline stage.
    """

    name = "PipelineStage"

    def execute(
        self,
        context: VerificationContext,
    ) -> VerificationContext:
        raise NotImplementedError


# ==========================================================
# Session Validation
# ==========================================================


class SessionValidationStage(PipelineStage):

    name = "SessionValidation"

    def execute(
        self,
        context: VerificationContext,
    ) -> VerificationContext:

        SessionService.validate(
            session=context.session,
            session_nonce=context.session_payload["session_nonce"],
            started_at=context.session_payload["started_at"],
            completed_at=context.session_payload["completed_at"],
        )

        return context


# ==========================================================
# Telemetry Validation
# ==========================================================


class TelemetryValidationStage(PipelineStage):

    name = "TelemetryValidation"

    def execute(
        self,
        context: VerificationContext,
    ) -> VerificationContext:

        context.telemetry_summary = (
            TelemetryValidator.validate(
                context.telemetry
            )
        )

        return context


# ==========================================================
# Challenge Validation
# ==========================================================


class ChallengeValidationStage(PipelineStage):

    name = "ChallengeValidation"

    def execute(
        self,
        context: VerificationContext,
    ) -> VerificationContext:

        context.challenge_summary = (
            ChallengeValidator.validate(
                issued_sequence=context.session.challenge_sequence,
                submitted_sequence=context.challenge_sequence,
                challenge_events=context.challenge_events,
            )
        )

        return context


# ==========================================================
# Replay Detection
# ==========================================================


class ReplayDetectionStage(PipelineStage):

    name = "ReplayDetection"

    def execute(
        self,
        context: VerificationContext,
    ) -> VerificationContext:

        context.replay_result = (
            ReplayDetector.validate(
                verification_session=context.session,
                payload=context.payload,
            )
        )

        return context


# ==========================================================
# Liveness Evaluation
# ==========================================================


class LivenessStage(PipelineStage):

    name = "Liveness"

    def execute(
        self,
        context: VerificationContext,
    ) -> VerificationContext:

        context.liveness_result = (
            LivenessEngine.evaluate(
                telemetry=context.telemetry,
                telemetry_summary=context.telemetry_summary,
                challenge_summary=context.challenge_summary,
                replay_result=context.replay_result,
                challenge_events=context.challenge_events,
                session_started_at=context.session_payload["started_at"],
            )
        )

        return context


# ==========================================================
# Pipeline
# ==========================================================


@dataclass
class IdentityVerificationPipeline:
    """
    Coordinates the complete verification process.

    The pipeline itself contains no business logic.

    Each stage enriches the shared VerificationContext.
    """

    context: VerificationContext

    def __post_init__(self):

        self.context.initialize()

        self.stages: List[PipelineStage] = [

            SessionValidationStage(),

            TelemetryValidationStage(),

            ChallengeValidationStage(),

            ReplayDetectionStage(),

            LivenessStage(),

            #
            # Phase C
            #
            # ImageDecoderStage()
            # FaceAlignmentStage()
            # EmbeddingStage()
            # SimilarityStage()
            #
            # Phase D
            #
            # PersistenceStage()
            # AuditStage()
            #
        ]

    # ------------------------------------------------------

    def execute(
        self,
    ) -> VerificationContext:

        try:

            for stage in self.stages:

                # Record which stage is running and when it started.
                # If anything below raises, we know exactly where it
                # failed without relying on local variables — this is
                # also invaluable for audit logs.
                self.context.current_stage = stage.name
                self.context.stage_started_at = timezone.now()

                self.context = stage.execute(
                    self.context
                )

                duration_ms = (
                    timezone.now() - self.context.stage_started_at
                ).total_seconds() * 1000

                self.context.audit_data[stage.name] = {
                    "duration_ms": round(duration_ms, 2),
                }

            return self.context

        except IdentityVerificationError as exc:

            self.context.add_error(str(exc))

            raise ValidationError(
                {
                    "stage": self.context.current_stage,
                    "detail": str(exc),
                }
            )