from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from identity_verification.models import (
    FaceEmbedding,
    IdentityVerificationResult,
    IdentityVerificationSession,
)


@dataclass
class VerificationContext:
    """
    Shared state for the entire identity verification pipeline.

    Every stage receives the same context instance, enriches it,
    and passes it to the next stage.

    No stage should return large dictionaries or tuples.
    The context is the single source of truth throughout the
    verification lifecycle.
    """

    # ==========================================================
    # Inputs
    # ==========================================================

    session: IdentityVerificationSession
    payload: Dict[str, Any]

    # ==========================================================
    # Raw Payload Sections
    # ==========================================================

    session_payload: Dict[str, Any] = field(default_factory=dict)
    client: Dict[str, Any] = field(default_factory=dict)
    camera: Dict[str, Any] = field(default_factory=dict)
    detector: Dict[str, Any] = field(default_factory=dict)

    challenge_sequence: List[str] = field(default_factory=list)
    challenge_events: List[Dict[str, Any]] = field(default_factory=list)

    telemetry: List[Dict[str, Any]] = field(default_factory=list)
    capture: Dict[str, Any] = field(default_factory=dict)

    # ==========================================================
    # Validation Results (Phase B)
    # ==========================================================

    telemetry_summary: Dict[str, Any] = field(default_factory=dict)
    challenge_summary: Dict[str, Any] = field(default_factory=dict)
    replay_result: Dict[str, Any] = field(default_factory=dict)
    liveness_result: Dict[str, Any] = field(default_factory=dict)

    # ==========================================================
    # Recognition (Phase C)
    # ==========================================================

    decoded_image: Optional[Any] = None
    aligned_face: Optional[Any] = None

    embedding: Optional[List[float]] = None
    stored_embedding: Optional[FaceEmbedding] = None

    similarity_score: Optional[float] = None
    similarity_result: Dict[str, Any] = field(default_factory=dict)

    # ==========================================================
    # Quality Assessment (Phase C)
    # ==========================================================

    image_quality_score: Optional[float] = None
    quality_result: Dict[str, Any] = field(default_factory=dict)

    # ==========================================================
    # Persistence
    # ==========================================================

    verification_result: Optional[IdentityVerificationResult] = None

    # ==========================================================
    # Pipeline Metadata
    # ==========================================================

    # Name of the stage currently executing. The pipeline sets this
    # before running each stage, so a failure always tells you exactly
    # where it happened without relying on local variables or stack
    # inspection.
    current_stage: Optional[str] = None

    # Timestamp the currently executing stage started at. The pipeline
    # uses this to compute each stage's duration for audit_data.
    stage_started_at: Optional[datetime] = None

    # ==========================================================
    # Audit
    # ==========================================================

    audit_data: Dict[str, Any] = field(default_factory=dict)

    # ==========================================================
    # Cryptographic Proof
    # ==========================================================

    proof: Optional[Any] = None

    # ==========================================================
    # Errors
    # ==========================================================

    errors: List[str] = field(default_factory=list)

    # ==========================================================
    # Convenience Methods
    # ==========================================================

    def initialize(self) -> None:
        """
        Populate frequently accessed payload sections.

        This should be called once by the pipeline immediately
        after the serializer has validated the payload.
        """

        self.session_payload = self.payload.get("session", {})
        self.client = self.payload.get("client", {})
        self.camera = self.payload.get("camera", {})
        self.detector = self.payload.get("detector", {})

        self.challenge_sequence = self.payload.get(
            "challenge_sequence",
            [],
        )

        self.challenge_events = self.payload.get(
            "challenge_events",
            [],
        )

        self.telemetry = self.payload.get(
            "telemetry",
            [],
        )

        self.capture = self.payload.get(
            "capture",
            {},
        )

    def add_error(self, message: str) -> None:
        """Append a pipeline error."""

        self.errors.append(message)

    @property
    def has_errors(self) -> bool:
        """Return True if any pipeline stage recorded an error."""

        return bool(self.errors)

    @property
    def replay_detected(self) -> bool:
        return self.replay_result.get(
            "replay_detected",
            False,
        )

    @property
    def liveness_passed(self) -> bool:
        return self.liveness_result.get(
            "passed",
            False,
        )

    @property
    def recognition_passed(self) -> bool:
        return self.similarity_result.get(
            "passed",
            False,
        )

    @property
    def overall_passed(self) -> bool:
        """
        Final verification decision.

        During Phase B this depends only on liveness.

        During Phase C it automatically becomes:

            liveness_passed
            AND
            recognition_passed
        """

        if self.similarity_result:
            return (
                self.liveness_passed
                and self.recognition_passed
            )

        return self.liveness_passed