from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from .exceptions import IdentityVerificationError

try:
    from insightface.model_zoo.arcface_onnx import ArcFaceONNX
except ImportError:
    ArcFaceONNX = None


MODEL_NAME = "w600k_r50"
MODEL_VERSION = "insightface-buffalo_l"
EMBEDDING_DIMENSION = 512


class EmbeddingError(IdentityVerificationError):
    """Raised when a face embedding cannot be produced."""


@dataclass
class EmbeddingResult:
    embedding: np.ndarray
    model_name: str
    model_version: str
    dimension: int


class _RecognitionModelSingleton:
    """Lazily loads the ArcFace recognition model exactly once per process."""

    _instance = None

    @classmethod
    def get(cls):
        if cls._instance is None:
            if ArcFaceONNX is None:
                raise EmbeddingError(
                    "insightface is not installed; embedding is unavailable."
                )

            model_path = getattr(settings, "IDENTITY_ARCFACE_MODEL_PATH", "")
            if not model_path:
                raise ImproperlyConfigured(
                    "IDENTITY_ARCFACE_MODEL_PATH is required for face embedding "
                    "(path to the w600k_r50 ArcFace ONNX weights)."
                )

            model = ArcFaceONNX(model_path)
            model.prepare(ctx_id=-1)
            cls._instance = model
        return cls._instance


class EmbeddingService:


    MODEL_NAME = MODEL_NAME
    MODEL_VERSION = MODEL_VERSION

    @classmethod
    def embed(cls, aligned_face: np.ndarray) -> EmbeddingResult:
        if aligned_face is None or aligned_face.size == 0:
            raise EmbeddingError("No aligned face was provided for embedding.")

        model = _RecognitionModelSingleton.get()

        raw_embedding = model.get_feat(aligned_face)
        vector = np.asarray(raw_embedding, dtype=np.float32).reshape(-1)

        norm = float(np.linalg.norm(vector))
        if norm == 0:
            raise EmbeddingError("Embedding model returned an all-zero vector.")

        normalized = vector / norm

        if normalized.shape[0] != EMBEDDING_DIMENSION:
            raise EmbeddingError(
                "Embedding model returned a vector of dimension "
                f"{normalized.shape[0]}, expected {EMBEDDING_DIMENSION}."
            )

        return EmbeddingResult(
            embedding=normalized,
            model_name=MODEL_NAME,
            model_version=MODEL_VERSION,
            dimension=int(normalized.shape[0]),
        )