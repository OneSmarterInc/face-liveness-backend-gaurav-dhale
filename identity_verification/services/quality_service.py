from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

import cv2
import numpy as np

from .exceptions import IdentityVerificationError


class QualityAssessmentError(IdentityVerificationError):
    """
    Raised when the *input* to quality assessment is malformed.

    This is NOT raised when quality is simply low — that's a normal
    outcome and shows up as QualityResult.passed = False.
    """


@dataclass
class QualityResult:
    passed: bool
    overall_score: float
    blur_score: float
    brightness_score: float
    contrast_score: float
    pose_score: float
    warnings: List[str] = field(default_factory=list)


class QualityService:


    MIN_BLUR = 60.0  # variance of Laplacian; below this, image is soft
    MIN_BRIGHTNESS = 40.0
    MAX_BRIGHTNESS = 220.0
    MIN_CONTRAST = 20.0
    MAX_ROLL_DEGREES = 25.0

    @classmethod
    def assess(cls, aligned_face: np.ndarray, *, rotation_angle: float = 0.0) -> QualityResult:
        if aligned_face is None or aligned_face.size == 0:
            raise QualityAssessmentError(
                "No aligned face was provided for quality assessment."
            )

        gray = cv2.cvtColor(aligned_face, cv2.COLOR_BGR2GRAY)

        blur_score = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        brightness_score = float(gray.mean())
        contrast_score = float(gray.std())
        pose_score = float(abs(rotation_angle))

        warnings: List[str] = []

        if blur_score < cls.MIN_BLUR:
            warnings.append("image_too_blurry")
        if not (cls.MIN_BRIGHTNESS <= brightness_score <= cls.MAX_BRIGHTNESS):
            warnings.append("poor_lighting")
        if contrast_score < cls.MIN_CONTRAST:
            warnings.append("low_contrast")
        if pose_score > cls.MAX_ROLL_DEGREES:
            warnings.append("excessive_pose_angle")

        passed = not warnings

        # Rough composite score for logging/analytics, not a calibrated
        # probability. Tune weights once real accept/reject data exists.
        overall_score = round(
            max(0.0, min(100.0, (blur_score / 2) + contrast_score - pose_score)),
            2,
        )

        return QualityResult(
            passed=passed,
            overall_score=overall_score,
            blur_score=round(blur_score, 2),
            brightness_score=round(brightness_score, 2),
            contrast_score=round(contrast_score, 2),
            pose_score=round(pose_score, 2),
            warnings=warnings,
        )