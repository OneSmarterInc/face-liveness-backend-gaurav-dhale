from __future__ import annotations

import json
from dataclasses import asdict
from typing import Optional, TypedDict

from rest_framework.exceptions import NotFound

from accounts.models import Account
from identity_verification.crypto import aes_gcm
from identity_verification.crypto.canonical import canonical_bytes
from identity_verification.models import (
    FaceEmbedding,
    FaceVerificationLog,
    IdentityVerificationSession,
)

from .audit_service import AuditService
from .embedding_service import EmbeddingResult, EmbeddingService
from .exceptions import IdentityVerificationError
from .face_alignment import AlignmentService
from .image_decoder import ImageDecoder
from .quality_service import QualityService
from .similarity_score import SimilarityService
from .verification_context import VerificationContext


class RecognitionError(IdentityVerificationError):
    """Raised for recognition-flow failures that aren't specific to one stage."""


class NoRegisteredFaceError(RecognitionError):
    """Raised when verify() is called but the account has no active FaceEmbedding."""


class VerificationOutcome(TypedDict):
    passed: bool
    similarity_score: float
    reason: str
    log_id: int


class RecognitionService:
    "The orchestrator"

    # ------------------------------------------------------------------
    # Shared: session ownership + the Alignment -> Quality -> Embedding chain
    # ------------------------------------------------------------------

    @staticmethod
    def _get_owned_session(account: Account, session_id) -> IdentityVerificationSession:
        try:
            return IdentityVerificationSession.objects.get(id=session_id, account=account)
        except IdentityVerificationSession.DoesNotExist as exc:
            raise NotFound("Verification session not found.") from exc

        # NOTE: this only checks ownership, not session status. If
        # registration/verification should be gated on the session
        # having already passed Phase B liveness, add that check here
        # — this is the single place it belongs.

    @classmethod
    def _extract_embedding(
        cls,
        context: VerificationContext,
        base64_image: str,
    ) -> tuple[VerificationContext, EmbeddingResult]:

        decoded = ImageDecoder.decode(base64_image)
        context.decoded_image = decoded.frame

        alignment = AlignmentService.align(decoded.frame)
        context.aligned_face = alignment.aligned_face

        quality = QualityService.assess(
            alignment.aligned_face,
            rotation_angle=alignment.rotation_angle,
        )
        context.quality_result = asdict(quality)

        if not quality.passed:
            raise RecognitionError(
                f"Image quality is insufficient: {', '.join(quality.warnings)}"
            )

        embedding_result = EmbeddingService.embed(alignment.aligned_face)
        context.embedding = embedding_result.embedding.tolist()

        return context, embedding_result

    # ------------------------------------------------------------------
    # Encryption helpers (RecognitionService only — no other service
    # in this package is allowed to touch aes_gcm)
    # ------------------------------------------------------------------

    @staticmethod
    def _encrypt_embedding(account: Account, embedding: list, model_name: str, model_version: str) -> bytes:
        plaintext = json.dumps(embedding).encode("utf-8")
        associated_data = canonical_bytes(
            {"account_id": account.id, "model_name": model_name, "model_version": model_version}
        )
        envelope = aes_gcm.encrypt(plaintext, associated_data=associated_data)
        return json.dumps(envelope).encode("utf-8")

    @staticmethod
    def _decrypt_embedding(face_embedding: FaceEmbedding) -> list:
        envelope = json.loads(bytes(face_embedding.embedding).decode("utf-8"))
        associated_data = canonical_bytes(
            {
                "account_id": face_embedding.user_id,
                "model_name": face_embedding.model_name,
                "model_version": face_embedding.model_version,
            }
        )
        plaintext = aes_gcm.decrypt(envelope, associated_data=associated_data)
        return json.loads(plaintext.decode("utf-8"))

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    @classmethod
    def register(cls, *, account: Account, session_id, base64_image: str) -> FaceEmbedding:
        session = cls._get_owned_session(account, session_id)

        context = VerificationContext(session=session, payload={})

        try:
            context, embedding_result = cls._extract_embedding(context, base64_image)
        except IdentityVerificationError as exc:
            AuditService.registration_failed(account_id=account.id, reason=str(exc))
            raise

        encrypted = cls._encrypt_embedding(
            account,
            context.embedding,
            embedding_result.model_name,
            embedding_result.model_version,
        )

        # Only one active embedding per account at a time — a new
        # registration supersedes the old one rather than stacking up.
        FaceEmbedding.objects.filter(user=account, is_active=True).update(is_active=False)

        face_embedding = FaceEmbedding.objects.create(
            user=account,
            embedding=encrypted,
            model_name=embedding_result.model_name,
            model_version=embedding_result.model_version,
            embedding_dimension=embedding_result.dimension,
            is_active=True,
        )

        AuditService.registration_succeeded(
            account_id=account.id,
            embedding_id=face_embedding.id,
            quality=context.quality_result,
        )

        return face_embedding

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    @classmethod
    def verify(
        cls,
        *,
        account: Account,
        session_id,
        base64_image: str,
        reason: str = "VERIFY",
        ip_address: Optional[str] = None,
        device: str = "",
    ) -> VerificationOutcome:
        session = cls._get_owned_session(account, session_id)

        stored = FaceEmbedding.objects.filter(user=account, is_active=True).first()
        if stored is None:
            raise NoRegisteredFaceError("No registered face exists for this account.")

        context = VerificationContext(session=session, payload={})
        context.stored_embedding = stored

        try:
            context, embedding_result = cls._extract_embedding(context, base64_image)
        except IdentityVerificationError as exc:
            AuditService.verification_attempt(
                account_id=account.id, passed=False, score=None, reason=reason
            )
            raise

        stored_vector = cls._decrypt_embedding(stored)

        similarity = SimilarityService.compare(context.embedding, stored_vector)
        context.similarity_result = asdict(similarity)

        # This flow only runs behind IsIdentityStudent-gated,
        # authenticated endpoints tied to a session that already went
        # through Phase B liveness, so we mirror that session's own
        # completed/failed status here rather than re-deriving a
        # liveness verdict — RecognitionService judges recognition
        # only, never liveness.
        session_passed_liveness = session.status == IdentityVerificationSession.Status.COMPLETED

        verification_log = FaceVerificationLog.objects.create(
            user=account,
            reason=reason,
            similarity_score=similarity.score,
            passed=similarity.passed,
            ip_address=ip_address,
            device=device,
            liveness_score=1.0 if session_passed_liveness else 0.0,
            liveness_passed=session_passed_liveness,
            challenge_sequence=session.challenge_sequence,
            detector_provider="insightface",
            detector_version=embedding_result.model_version,
        )

        AuditService.verification_attempt(
            account_id=account.id,
            passed=similarity.passed,
            score=similarity.score,
            reason=reason,
        )

        return VerificationOutcome(
            passed=similarity.passed,
            similarity_score=similarity.score,
            reason=reason,
            log_id=verification_log.id,
        )