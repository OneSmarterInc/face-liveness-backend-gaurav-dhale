from __future__ import annotations

from dataclasses import dataclass
from typing import List

import numpy as np

from .exceptions import IdentityVerificationError

try:
    from insightface.app import FaceAnalysis
    from insightface.utils import face_align
except ImportError:  # pragma: no cover
    FaceAnalysis = None
    face_align = None


ALIGNED_FACE_SIZE = 112


class FaceAlignmentError(IdentityVerificationError):
    """Raised when no usable, single face can be aligned from a frame."""


class NoFaceDetectedError(FaceAlignmentError):
    pass


class MultipleFacesDetectedError(FaceAlignmentError):
    pass


@dataclass
class AlignmentResult:
    aligned_face: np.ndarray
    face_bbox: List[float]
    landmarks: List[List[float]]
    rotation_angle: float
    detection_score: float
    face_count: int


class _DetectorSingleton:

    _instance = None

    @classmethod
    def get(cls):
        if cls._instance is None:
            if FaceAnalysis is None:
                raise FaceAlignmentError(
                    "insightface is not installed; face alignment is unavailable."
                )
            app = FaceAnalysis(
                name="buffalo_l",
                allowed_modules=["detection", "landmark_2d_106"],
            )

            app.prepare(ctx_id=-1, det_size=(640, 640))
            cls._instance = app
        return cls._instance


class AlignmentService:


    @classmethod
    def align(cls, frame: np.ndarray, *, allow_multiple: bool = False) -> AlignmentResult:
        if frame is None or frame.size == 0:
            raise FaceAlignmentError("No frame was provided for alignment.")

        detector = _DetectorSingleton.get()
        faces = detector.get(frame)

        if not faces:
            raise NoFaceDetectedError("No face was detected in the image.")

        if len(faces) > 1 and not allow_multiple:
            raise MultipleFacesDetectedError(
                "Multiple faces were detected; exactly one is required."
            )


        face = max(
            faces,
            key=lambda f: (f.bbox[2] - f.bbox[0]) * (f.bbox[3] - f.bbox[1]),
        )

        keypoints = face.kps
        aligned_face = face_align.norm_crop(
            frame,
            landmark=keypoints,
            image_size=ALIGNED_FACE_SIZE,
        )

        return AlignmentResult(
            aligned_face=aligned_face,
            face_bbox=[float(v) for v in face.bbox],
            landmarks=[[float(x), float(y)] for x, y in keypoints],
            rotation_angle=cls._estimate_roll(keypoints),
            detection_score=float(face.det_score),
            face_count=len(faces),
        )

    @staticmethod
    def _estimate_roll(keypoints) -> float:
        """Rough in-plane rotation from the two eye keypoints, in degrees."""
        left_eye, right_eye = keypoints[0], keypoints[1]
        dy = right_eye[1] - left_eye[1]
        dx = right_eye[0] - left_eye[0]
        return float(np.degrees(np.arctan2(dy, dx)))