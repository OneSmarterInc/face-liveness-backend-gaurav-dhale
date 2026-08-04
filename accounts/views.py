from __future__ import annotations

import logging

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.db_utils import run_with_retry
from accounts.mfa import (
    clear_totp_failures,
    create_mfa_session,
    get_user_id_from_mfa_token,
    invalidate_mfa_session,
    is_totp_throttled,
    record_totp_failure,
)
from accounts.models import TOTPBackupCode, TOTPDevice
from accounts.serializers import (
    EnrollVerifySerializer,
    LoginSerializer,
    RegisterSerializer,
    VerifyTOTPSerializer,
    serialize_user,
)
from accounts.totp import (
    build_provisioning_uri,
    generate_backup_codes,
    generate_totp_secret,
    hash_backup_code,
    verify_totp_code,
)

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


def _user_has_confirmed_totp(user: User) -> bool:
    return TOTPDevice.objects.filter(user=user, confirmed_at__isnull=False).exists()


class RegisterView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "auth"

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = run_with_retry(serializer.save)
        
        refresh = RefreshToken.for_user(user)

        app_logger.info(
            "Account registered",
            extra=_log_extra(request, response_status=status.HTTP_201_CREATED, user=user.id),
        )

        return Response(
            {
                "message": "Account created. Complete TOTP enrollment to finish setup.",
                "must_enroll_totp": True,
                "access": str(refresh.access_token),
                "user": serialize_user(user),
            },
            status=status.HTTP_201_CREATED,
        )
    

from identity_verification.models import FaceEmbedding

def _get_next_authentication_step(user: User) -> str:
    face_registered = FaceEmbedding.objects.filter(
        user=user.account, is_active=True
    ).exists()

    return (
        "FACE_VERIFICATION"
        if face_registered
        else "FACE_REGISTRATION"
    )

class LoginView(APIView):

    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "auth"

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(
            request,
            username=serializer.validated_data["email"],
            password=serializer.validated_data["password"],
        )

        if user is None or not user.is_active:
            security_logger.warning(
                "Failed login attempt",
                extra=_log_extra(
                    request,
                    response_status=status.HTTP_401_UNAUTHORIZED,
                    user=serializer.validated_data["email"],
                ),
            )
            return Response({"detail": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)

        if _user_has_confirmed_totp(user):
            mfa_token = create_mfa_session(user.id)
            app_logger.info(
                "Login step 1 succeeded, TOTP challenge issued",
                extra=_log_extra(request, response_status=status.HTTP_200_OK, user=user.id),
            )
            return Response(
                {
                    "must_enroll_totp": False,
                    "mfa_token": mfa_token,
                    "totp_required": True,
                    "expires_in": 300,
                },
                status=status.HTTP_200_OK,
            )

        refresh = RefreshToken.for_user(user)
        app_logger.info(
            "Login succeeded, TOTP enrollment still required",
            extra=_log_extra(request, response_status=status.HTTP_200_OK, user=user.id),
        )
        next_step = _get_next_authentication_step(user)
        return Response(
            {
                "must_enroll_totp": True,
                "access": str(refresh.access_token),
                "user": serialize_user(user),
                "next_step": next_step,
            },
            status=status.HTTP_200_OK,
        )


class TOTPEnrollView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if _user_has_confirmed_totp(user):
            return Response({"detail": "TOTP is already enrolled."}, status=status.HTTP_400_BAD_REQUEST)

        device = TOTPDevice.objects.filter(user=user).first()
        if device is None:
            secret = generate_totp_secret()
            run_with_retry(lambda: TOTPDevice.objects.create(user=user, secret=secret))
        else:
            secret = device.secret

        app_logger.info(
            "TOTP enrollment started",
            extra=_log_extra(request, response_status=status.HTTP_200_OK, user=user.id),
        )

        return Response(
            {"secret": secret, "provisioning_uri": build_provisioning_uri(secret, user.email)},
            status=status.HTTP_200_OK,
        )


class TOTPVerifyEnrollmentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = EnrollVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"].strip()

        try:
            device = request.user.totp_device
        except TOTPDevice.DoesNotExist:
            return Response({"detail": "TOTP enrollment has not been started."}, status=status.HTTP_400_BAD_REQUEST)

        if device.confirmed_at:
            return Response({"detail": "TOTP is already enrolled."}, status=status.HTTP_400_BAD_REQUEST)

        if not verify_totp_code(device.secret, code):
            security_logger.warning(
                "Invalid TOTP code during enrollment",
                extra=_log_extra(request, response_status=status.HTTP_400_BAD_REQUEST, user=request.user.id),
            )
            return Response({"detail": "Invalid TOTP code."}, status=status.HTTP_400_BAD_REQUEST)

        backup_codes = generate_backup_codes()

        def _confirm():
            with transaction.atomic():
                device.confirmed_at = timezone.now()
                device.save(update_fields=["confirmed_at"])
                TOTPBackupCode.objects.filter(user=request.user).delete()
                TOTPBackupCode.objects.bulk_create(
                    [TOTPBackupCode(user=request.user, code_hash=hash_backup_code(c)) for c in backup_codes]
                )

        run_with_retry(_confirm)

        app_logger.info(
            "TOTP enrollment confirmed",
            extra=_log_extra(request, response_status=status.HTTP_200_OK, user=request.user.id),
        )

        return Response({"backup_codes": backup_codes}, status=status.HTTP_200_OK)


class TOTPLoginVerifyView(APIView):
    """Step 2 of login: exchange mfa_token + TOTP/backup code for real tokens."""

    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "auth"

    def post(self, request):
        serializer = VerifyTOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        mfa_token = serializer.validated_data["mfa_token"].strip()
        code = serializer.validated_data["code"].strip().upper()

        user_id = get_user_id_from_mfa_token(mfa_token)
        if not user_id:
            security_logger.warning(
                "TOTP login attempted with expired or invalid mfa_token",
                extra=_log_extra(request, response_status=status.HTTP_401_UNAUTHORIZED, user="anonymous"),
            )
            return Response(
                {"detail": "Session expired or invalid. Please log in again."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if is_totp_throttled(user_id):
            security_logger.warning(
                "TOTP login throttled after repeated failures",
                extra=_log_extra(request, response_status=status.HTTP_429_TOO_MANY_REQUESTS, user=user_id),
            )
            return Response(
                {"detail": "Too many incorrect attempts. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        try:
            user = User.objects.get(id=user_id)
            device = user.totp_device
        except (User.DoesNotExist, TOTPDevice.DoesNotExist):
            return Response({"detail": "TOTP is not enrolled."}, status=status.HTTP_400_BAD_REQUEST)

        if not device.confirmed_at:
            return Response({"detail": "TOTP is not enrolled."}, status=status.HTTP_400_BAD_REQUEST)

        is_valid = False
        used_backup_code = None

        if code.isdigit() and len(code) == 6:
            is_valid = verify_totp_code(device.secret, code, user_id=user.id)

        if not is_valid and len(code) == 10:
            code_hash = hash_backup_code(code)
            used_backup_code = TOTPBackupCode.objects.filter(
                user=user, code_hash=code_hash, used_at__isnull=True
            ).first()
            is_valid = used_backup_code is not None

        if not is_valid:
            record_totp_failure(user_id)
            security_logger.warning(
                "Invalid TOTP or backup code at login",
                extra=_log_extra(request, response_status=status.HTTP_400_BAD_REQUEST, user=user_id),
            )
            return Response({"detail": "Invalid TOTP or backup code."}, status=status.HTTP_400_BAD_REQUEST)

        def _mark_used():
            with transaction.atomic():
                if used_backup_code:
                    used_backup_code.used_at = timezone.now()
                    used_backup_code.save(update_fields=["used_at"])
                else:
                    device.last_used_at = timezone.now()
                    device.save(update_fields=["last_used_at"])

        run_with_retry(_mark_used)

        clear_totp_failures(user_id)
        invalidate_mfa_session(mfa_token)

        refresh = RefreshToken.for_user(user)

        app_logger.info(
            "Login completed (TOTP verified)",
            extra=_log_extra(request, response_status=status.HTTP_200_OK, user=user.id),
        )

        next_step = _get_next_authentication_step(user)

        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": serialize_user(user),
                "next_step": next_step,
            },
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"detail": "refresh is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            run_with_retry(RefreshToken(refresh_token).blacklist)
        except Exception:
            security_logger.warning(
                "Logout attempted with invalid or already-blacklisted refresh token",
                extra=_log_extra(request, response_status=status.HTTP_400_BAD_REQUEST, user=request.user.id),
            )
            return Response({"detail": "Invalid or already-blacklisted refresh token."}, status=status.HTTP_400_BAD_REQUEST)

        app_logger.info(
            "User logged out",
            extra=_log_extra(request, response_status=status.HTTP_205_RESET_CONTENT, user=request.user.id),
        )

        return Response(status=status.HTTP_205_RESET_CONTENT)


class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(serialize_user(request.user), status=status.HTTP_200_OK)