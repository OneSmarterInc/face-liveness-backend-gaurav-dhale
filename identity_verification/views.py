from __future__ import annotations

import logging

from django.db import transaction
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import IsTOTPEnrolled
from identity_verification.models import DeviceBiometricPreference
from identity_verification.permissions import IsIdentityStudent
from identity_verification.serializers import (
    DeviceBiometricPreferenceSerializer,
    IdentitySessionDetailSerializer,
    IdentitySessionSerializer,
    RegisterFaceSerializer,
    VerifyFaceSerializer,
)
from identity_verification.services import complete_identity_session, create_identity_session
from identity_verification.services.exceptions import IdentityVerificationError
from identity_verification.services.recognition_service import RecognitionService

app_logger = logging.getLogger("app")
security_logger = logging.getLogger("security")


def _get_client_ip(request) -> str:
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _log_extra(request, *, response_status, user=None, duration: float = 0.0) -> dict:
    """Build the `extra` dict required by the app/security "verbose" formatter."""
    return {
        "path": request.path,
        "method": request.method,
        "status": response_status,
        "duration": duration,
        "ip": _get_client_ip(request),
        "user": user if user is not None else getattr(request.user, "id", "anonymous"),
    }


class IdentitySessionCreateView(APIView):
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated, IsTOTPEnrolled, IsIdentityStudent]
    throttle_scope = "identity"

    def post(self, request):
        if request.content_type and not request.content_type.startswith("application/json"):
            return Response({"detail": "Only application/json is accepted."}, status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)
        session = create_identity_session(request.user.account)
        app_logger.info(
            "Identity verification session created",
            extra=_log_extra(request, response_status=status.HTTP_201_CREATED),
        )
        return Response(IdentitySessionSerializer(session).data, status=status.HTTP_201_CREATED)


class IdentitySessionDetailView(APIView):
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated, IsTOTPEnrolled, IsIdentityStudent]
    throttle_scope = "identity"

    def get(self, request, session_id):
        try:
            session = request.user.account.identity_sessions.get(id=session_id)
        except Exception:  # noqa: BLE001
            return Response({"detail": "Verification session not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(IdentitySessionDetailSerializer(session).data, status=status.HTTP_200_OK)


class IdentitySessionCompleteView(APIView):
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated, IsTOTPEnrolled, IsIdentityStudent]
    throttle_scope = "identity"

    def post(self, request, session_id):
        if request.content_type and not request.content_type.startswith("application/json"):
            return Response({"detail": "Only application/json is accepted."}, status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)
        try:
            session, result, proof = complete_identity_session(
                account=request.user.account,
                session_id=session_id,
                payload=dict(request.data),
            )
        except ValidationError as exc:
            security_logger.warning(
                "Identity verification session completion rejected",
                extra=_log_extra(request, response_status=status.HTTP_400_BAD_REQUEST),
            )
            return Response(exc.detail, status=status.HTTP_400_BAD_REQUEST)

        if result.final_liveness_result == "passed":
            app_logger.info(
                "Identity verification passed",
                extra=_log_extra(request, response_status=status.HTTP_200_OK),
            )
        else:
            security_logger.warning(
                "Identity verification failed liveness check",
                extra=_log_extra(request, response_status=status.HTTP_200_OK),
            )

        response_proof = {
            "verification_record_hash": proof.verification_record_hash,
            "current_head": proof.current_head,
            "freshness_timestamp": proof.freshness_timestamp,
            "challenge": proof.challenge,
            "epoch": proof.signing_epoch,
            "signature": proof.signature,
        }
        return Response(
            {
                "session_id": str(session.id),
                "status": session.status,
                "liveness_result": result.final_liveness_result,
                "profile_status": "active_liveness_passed" if result.final_liveness_result == "passed" else result.final_liveness_result,
                "proof": response_proof,
            },
            status=status.HTTP_200_OK,
        )


class RegisterFaceView(APIView):
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated, IsTOTPEnrolled, IsIdentityStudent]
    throttle_scope = "identity"

    def post(self, request):
        if request.content_type and not request.content_type.startswith("application/json"):
            return Response({"detail": "Only application/json is accepted."}, status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)

        serializer = RegisterFaceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            face_embedding = RecognitionService.register(
                account=request.user.account,
                session_id=serializer.validated_data["session_id"],
                base64_image=serializer.validated_data["capture"]["image"],
            )
        except IdentityVerificationError as exc:
            security_logger.warning(
                "Face registration rejected",
                extra=_log_extra(request, response_status=status.HTTP_400_BAD_REQUEST),
            )
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        app_logger.info(
            "Face registered",
            extra=_log_extra(request, response_status=status.HTTP_201_CREATED),
        )
        return Response(
            {
                "embedding_id": face_embedding.id,
                "model_name": face_embedding.model_name,
                "model_version": face_embedding.model_version,
                "created_at": face_embedding.created_at,
            },
            status=status.HTTP_201_CREATED,
        )


class VerifyFaceView(APIView):
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated, IsTOTPEnrolled, IsIdentityStudent]
    throttle_scope = "identity"

    def post(self, request):
        if request.content_type and not request.content_type.startswith("application/json"):
            return Response({"detail": "Only application/json is accepted."}, status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)

        serializer = VerifyFaceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            outcome = RecognitionService.verify(
                account=request.user.account,
                session_id=serializer.validated_data["session_id"],
                base64_image=serializer.validated_data["capture"]["image"],
                reason=serializer.validated_data["reason"],
                ip_address=_get_client_ip(request),
                device=request.META.get("HTTP_USER_AGENT", ""),
            )
        except IdentityVerificationError as exc:
            security_logger.warning(
                "Face verification errored",
                extra=_log_extra(request, response_status=status.HTTP_400_BAD_REQUEST),
            )
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        if outcome["passed"]:
            app_logger.info(
                "Face verification passed",
                extra=_log_extra(request, response_status=status.HTTP_200_OK),
            )
        else:
            security_logger.warning(
                "Face verification failed",
                extra=_log_extra(request, response_status=status.HTTP_200_OK),
            )

        return Response(
            {
                "passed": outcome["passed"],
                "similarity_score": outcome["similarity_score"],
                "reason": outcome["reason"],
            },
            status=status.HTTP_200_OK,
        )


class DeviceBiometricPreferenceView(APIView):
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated, IsTOTPEnrolled, IsIdentityStudent]
    throttle_scope = "identity"

    def post(self, request):
        if request.content_type and not request.content_type.startswith("application/json"):
            return Response({"detail": "Only application/json is accepted."}, status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)
        serializer = DeviceBiometricPreferenceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            preference, _ = DeviceBiometricPreference.objects.update_or_create(
                account=request.user.account,
                defaults=serializer.validated_data,
            )
        app_logger.info(
            "Device biometric preference updated",
            extra=_log_extra(request, response_status=status.HTTP_200_OK),
        )
        return Response(
            {
                "status": preference.status,
                "platform": preference.platform,
                "app_version": preference.app_version,
                "updated_at": preference.updated_at,
            },
            status=status.HTTP_200_OK,
        )