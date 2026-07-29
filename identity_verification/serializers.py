from __future__ import annotations

import hmac
from typing import Any, Dict, List

from django.utils import timezone
from rest_framework import serializers

from identity_verification.models import (
    DeviceBiometricPreference,
    FaceVerificationLog,
    IdentityVerificationResult,
    IdentityVerificationSession,
)

CURRENT_SCHEMA_VERSION = 1

SUPPORTED_PLATFORMS = [
    "android",
    "ios",
    "web",
]

SUPPORTED_DETECTORS = [
    "MediaPipe",
]

SUPPORTED_CHALLENGES = [
    "center_face",
    "turn_left",
    "turn_right",
    "blink",
    "hold_still",
]

BANNED_FIELDS = {
    "file",
    "files",
    "photo",
    "photos",
    "video",
    "videos",
    "frame",
    "frames",
    "raw_detection",
    "raw_detections",
    "face_geometry",
    "landmarks",
    "face",
    "faces",
    "embedding",
    "biometric_template",
    "face_template",
    "device_biometric_id",
}



class IdentitySessionSerializer(serializers.ModelSerializer):
    session_id = serializers.UUIDField(source="id", read_only=True)

    class Meta:
        model = IdentityVerificationSession
        fields = ["session_id", "expires_at", "challenge_sequence", "session_nonce", "status"]


class IdentitySessionDetailSerializer(serializers.ModelSerializer):
    session_id = serializers.UUIDField(source="id", read_only=True)

    class Meta:
        model = IdentityVerificationSession
        fields = ["session_id", "expires_at", "challenge_sequence", "status", "started_at", "completed_at"]


class ChallengeResultSerializer(serializers.Serializer):
    challenge = serializers.ChoiceField(choices=SUPPORTED_CHALLENGES)
    passed = serializers.BooleanField()
    completed_at = serializers.DateTimeField()

    def to_internal_value(self, data):
        if isinstance(data, dict):
            unexpected = set(data.keys()) - {"challenge", "passed", "completed_at"}
            banned = sorted(set(data.keys()) & BANNED_FIELDS)
            if banned:
                raise serializers.ValidationError({"biometric_payload": f"Raw biometric/media fields are not accepted: {', '.join(banned)}"})
            if unexpected:
                raise serializers.ValidationError({"unexpected_fields": sorted(unexpected)})
        return super().to_internal_value(data)


class DeviceBiometricPreferenceSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=DeviceBiometricPreference.Status.choices)
    platform = serializers.ChoiceField(choices=["ios", "android", "web"])
    app_version = serializers.CharField(max_length=80)

    def validate(self, attrs):
        unexpected = set(self.initial_data.keys()) - set(self.fields.keys())
        banned = sorted((set(self.initial_data.keys()) | unexpected) & BANNED_FIELDS)
        if banned:
            raise serializers.ValidationError({"biometric_payload": f"Biometric data fields are not accepted: {', '.join(banned)}"})
        if unexpected:
            raise serializers.ValidationError({"unexpected_fields": sorted(unexpected)})
        return attrs


# ----------------------------------------------------------------------
# Session
# ----------------------------------------------------------------------

class SessionSerializer(serializers.Serializer):
    session_nonce = serializers.CharField(max_length=128)
    verification_id = serializers.UUIDField(required=False, allow_null=True)
    started_at = serializers.DateTimeField()
    completed_at = serializers.DateTimeField()


# ----------------------------------------------------------------------
# Client
# ----------------------------------------------------------------------

class ClientSerializer(serializers.Serializer):
    platform = serializers.ChoiceField(SUPPORTED_PLATFORMS)
    app_version = serializers.CharField(max_length=40)
    browser = serializers.CharField(max_length=120)
    os = serializers.CharField(max_length=120)


# ----------------------------------------------------------------------
# Camera
# ----------------------------------------------------------------------

class CameraResolutionSerializer(serializers.Serializer):
    width = serializers.IntegerField(min_value=1)
    height = serializers.IntegerField(min_value=1)


class CameraSerializer(serializers.Serializer):
    resolution = CameraResolutionSerializer()
    fps = serializers.FloatField(min_value=1)


# ----------------------------------------------------------------------
# Detector
# ----------------------------------------------------------------------

class DetectorSerializer(serializers.Serializer):
    provider = serializers.ChoiceField(SUPPORTED_DETECTORS)
    version = serializers.CharField(max_length=40)


# ----------------------------------------------------------------------
# Challenge
# ----------------------------------------------------------------------

class ChallengeEventSerializer(serializers.Serializer):
    challenge = serializers.ChoiceField(SUPPORTED_CHALLENGES)
    started_at = serializers.DateTimeField()
    completed_at = serializers.DateTimeField()

    def validate(self, attrs):
        if attrs["completed_at"] < attrs["started_at"]:
            raise serializers.ValidationError(
                "completed_at must be after started_at."
            )
        return attrs


# ----------------------------------------------------------------------
# Telemetry
# ----------------------------------------------------------------------

class TelemetrySerializer(serializers.Serializer):
    t = serializers.IntegerField(min_value=0)

    yaw = serializers.FloatField(min_value=-90, max_value=90)
    pitch = serializers.FloatField(min_value=-90, max_value=90)
    roll = serializers.FloatField(min_value=-180, max_value=180)

    ear_left = serializers.FloatField(min_value=0, max_value=1)
    ear_right = serializers.FloatField(min_value=0, max_value=1)

    face_detected = serializers.BooleanField()

    face_confidence = serializers.FloatField(
        min_value=0,
        max_value=1,
        required=False,
        default=1,
    )


# ----------------------------------------------------------------------
# Capture
# ----------------------------------------------------------------------

class CaptureSerializer(serializers.Serializer):
    frame_timestamp = serializers.DateTimeField()

    quality_score = serializers.FloatField(
        min_value=0,
        max_value=100,
    )

    sharpness = serializers.FloatField(min_value=0)

    brightness = serializers.FloatField(
        min_value=0,
        max_value=255,
    )

    image = serializers.CharField()


# ----------------------------------------------------------------------
# Final Payload
# ----------------------------------------------------------------------

class IdentityCompletionSerializer(serializers.Serializer):
    schema_version = serializers.IntegerField(default=CURRENT_SCHEMA_VERSION)

    session = SessionSerializer()

    client = ClientSerializer()

    camera = CameraSerializer()

    detector = DetectorSerializer()

    challenge_sequence = serializers.ListField(
        child=serializers.ChoiceField(SUPPORTED_CHALLENGES),
        allow_empty=False,
    )

    challenge_events = ChallengeEventSerializer(many=True)

    telemetry = TelemetrySerializer(
        many=True,
        allow_empty=False,
    )

    capture = CaptureSerializer()

    # --------------------------------------------------

    def validate(self, attrs):

        unexpected = set(self.initial_data.keys()) - set(self.fields.keys())

        banned = sorted(
            set(self.initial_data.keys()) & BANNED_FIELDS
        )

        if banned:
            raise serializers.ValidationError(
                {
                    "biometric_payload":
                        f"Raw biometric fields are not accepted: {', '.join(banned)}"
                }
            )

        if unexpected:
            raise serializers.ValidationError(
                {
                    "unexpected_fields": sorted(unexpected)
                }
            )

        if attrs["schema_version"] != CURRENT_SCHEMA_VERSION:
            raise serializers.ValidationError(
                {
                    "schema_version":
                        "Unsupported payload schema."
                }
            )

        return attrs



class FaceCaptureSerializer(serializers.Serializer):
    image = serializers.CharField()


class RegisterFaceSerializer(serializers.Serializer):
    session_id = serializers.UUIDField()
    capture = FaceCaptureSerializer()

    def validate(self, attrs):
        unexpected = set(self.initial_data.keys()) - set(self.fields.keys())
        if unexpected:
            raise serializers.ValidationError({"unexpected_fields": sorted(unexpected)})
        return attrs


class VerifyFaceSerializer(serializers.Serializer):
    session_id = serializers.UUIDField()
    capture = FaceCaptureSerializer()
    reason = serializers.ChoiceField(
        choices=FaceVerificationLog.VERIFICATION_REASON_CHOICES,
        default="VERIFY",
    )

    def validate(self, attrs):
        unexpected = set(self.initial_data.keys()) - set(self.fields.keys())
        if unexpected:
            raise serializers.ValidationError({"unexpected_fields": sorted(unexpected)})
        return attrs