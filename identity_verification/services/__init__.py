from __future__ import annotations

import random
from typing import Tuple

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import NotFound

from accounts.models import Account
from identity_verification.crypto import aes_gcm
from identity_verification.crypto.canonical import canonical_bytes
from identity_verification.crypto.proof_tokens import (
    build_current_head,
    sha3_256_hex,
    sign_proof_record,
)
from identity_verification.models import (
    IdentityVerificationProof,
    IdentityVerificationResult,
    IdentityVerificationSession,
)
from identity_verification.serializers import IdentityCompletionSerializer

from .verification_context import VerificationContext
from .verification_pipeline import IdentityVerificationPipeline

CHALLENGE_SEQUENCE = [
    "center_face",
    "turn_left",
    "turn_right",
    "blink",
    "hold_still",
]


# ==========================================================
# Session creation
# ==========================================================

import secrets
def create_identity_session(account: Account) -> IdentityVerificationSession:

    ttl_seconds = int(
        getattr(settings, "IDENTITY_SESSION_TTL_SECONDS", 300)
    )

    challenge_sequence = CHALLENGE_SEQUENCE.copy()
    secrets.SystemRandom().shuffle(challenge_sequence)
    # random.shuffle(challenge_sequence)

    return IdentityVerificationSession.objects.create(
        account=account,
        challenge_sequence=challenge_sequence,
        expires_at=(
            timezone.now()
            + timezone.timedelta(seconds=ttl_seconds)
        ),
    )


# ==========================================================
# Persistence helpers
#
# These are intentionally *not* part of complete_identity_session
# itself — they exist so that function stays a pure orchestrator.
# Each one does exactly one thing after the pipeline has already
# decided pass/fail.
# ==========================================================


def _persist_result(
    *,
    context: VerificationContext,
) -> Tuple[IdentityVerificationResult, str, str]:
    """
    Encrypt + hash the verified evidence and store it as an immutable
    IdentityVerificationResult row.

    The pipeline (specifically LivenessEngine, the only component
    allowed to decide the verdict) has already populated
    context.liveness_result by the time this runs. This function does
    not re-derive or second-guess that decision — it only persists it.

    Returns (result, payload_hash, previous_head) so the caller can
    build the proof / hash-chain head without re-deriving anything.
    """

    session = context.session

    final_liveness_result = (
        IdentityVerificationResult.FinalResult.PASSED
        if context.overall_passed
        else IdentityVerificationResult.FinalResult.FAILED
    )

    failure_reason = (
        ""
        if context.overall_passed
        else context.liveness_result.get("reason", "")
    )

    started_at = context.session_payload["started_at"]
    completed_at = context.session_payload["completed_at"]

    canonical_payload = {
        "session_id": str(session.id),
        "student_code": session.student_code,
        # The issued sequence is the authoritative one — it is what
        # was signed into the session at creation time.
        "challenge_sequence": session.challenge_sequence,
        "challenge_results": context.liveness_result.get(
            "challenge_results",
            [],
        ),
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "detector_provider": context.detector["provider"],
        "platform": context.client["platform"],
        "app_version": context.client["app_version"],
        "final_liveness_result": final_liveness_result,
        "failure_reason": failure_reason,
    }

    plaintext = canonical_bytes(canonical_payload)
    payload_hash = sha3_256_hex(plaintext)

    associated_data = canonical_bytes(
        {
            "session_id": str(session.id),
            "student_code": session.student_code,
        }
    )
    encrypted_payload = aes_gcm.encrypt(
        plaintext,
        associated_data=associated_data,
    )

    previous_head = session.current_head or session.previous_head or ""

    result = IdentityVerificationResult.objects.create(
        session=session,
        encrypted_payload=encrypted_payload,
        detector_provider=context.detector["provider"],
        platform=context.client["platform"],
        app_version=context.client["app_version"],
        final_liveness_result=final_liveness_result,
        failure_reason=failure_reason,
        started_at=started_at,
        completed_at=completed_at,
        payload_hash=payload_hash,

        evidence_fingerprint=context.replay_result["fingerprint"],
        replay_detected=context.replay_result["replay_detected"],
    )

    return result, payload_hash, previous_head


def _generate_proof(
    *,
    session: IdentityVerificationSession,
    result: IdentityVerificationResult,
    payload_hash: str,
    previous_head: str,
) -> Tuple[IdentityVerificationProof, str]:
    """Sign the hash-chained proof record for this result."""

    current_head = build_current_head(
        previous_head,
        payload_hash,
        str(session.id),
    )

    proof_payload = sign_proof_record(
        student_code=session.student_code,
        verification_record_hash=payload_hash,
        current_head=current_head,
        challenge=",".join(session.challenge_sequence),
    )

    proof = IdentityVerificationProof.objects.create(
        session=session,
        result=result,
        student_code=proof_payload["student_code"],
        verification_record_hash=proof_payload["verification_record_hash"],
        current_head=proof_payload["current_head"],
        freshness_timestamp=proof_payload["freshness_timestamp"],
        challenge=proof_payload["challenge"],
        signing_epoch=proof_payload["epoch"],
        signature=proof_payload["signature"],
        authority_identifier=proof_payload["authority_identifier"],
    )

    return proof, current_head


# ==========================================================
# Orchestrator
# ==========================================================


from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import NotFound


def complete_identity_session(
    *,
    account: Account,
    session_id,
    payload: dict,
) -> Tuple[
    IdentityVerificationSession,
    IdentityVerificationResult,
    IdentityVerificationProof,
]:
    """
    Orchestrates the complete Phase B verification flow.

        Load + Lock Session
            -> Serializer
            -> VerificationContext
            -> IdentityVerificationPipeline
            -> Persist Result
            -> Generate Proof
            -> Consume Session
            -> Return

    All validation is delegated to either the serializer or the pipeline.
    This function only orchestrates the flow.
    """

    with transaction.atomic():


        try:
            session = (
                IdentityVerificationSession.objects
                .select_for_update()
                .get(
                    id=session_id,
                    account=account,
                )
            )
        except IdentityVerificationSession.DoesNotExist as exc:
            raise NotFound("Verification session not found.") from exc


        if session.consumed_at:
            raise serializers.ValidationError(
                {"session": "Verification session has already been consumed."}
            )

        if session.status in (
            IdentityVerificationSession.Status.COMPLETED,
            IdentityVerificationSession.Status.FAILED,
        ):
            raise serializers.ValidationError(
                {"session": "Verification session has already been completed."}
            )

        if session.expires_at <= timezone.now():
            session.status = IdentityVerificationSession.Status.EXPIRED
            session.save(update_fields=["status"])

            raise serializers.ValidationError(
                {"session": "Verification session has expired."}
            )


        serializer = IdentityCompletionSerializer(
            data=payload,
            context={"session": session},
        )
        serializer.is_valid(raise_exception=True)

        # Count only valid completion attempts.
        session.attempt_count += 1
        session.save(update_fields=["attempt_count"])

        context = VerificationContext(
            session=session,
            payload=serializer.validated_data,
        )

        context = IdentityVerificationPipeline(
            context=context,
        ).execute()

        result, payload_hash, previous_head = _persist_result(
            context=context,
        )

        proof, current_head = _generate_proof(
            session=session,
            result=result,
            payload_hash=payload_hash,
            previous_head=previous_head,
        )


        session.status = (
            IdentityVerificationSession.Status.COMPLETED
            if result.final_liveness_result
            == IdentityVerificationResult.FinalResult.PASSED
            else IdentityVerificationSession.Status.FAILED
        )

        session.started_at = result.started_at
        session.completed_at = result.completed_at
        session.consumed_at = timezone.now()
        session.previous_head = previous_head
        session.current_head = current_head

        session.save(
            update_fields=[
                "status",
                "started_at",
                "completed_at",
                "consumed_at",
                "previous_head",
                "current_head",
            ]
        )

        return session, result, proof