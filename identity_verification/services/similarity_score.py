from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .exceptions import IdentityVerificationError


class SimilarityError(IdentityVerificationError):
    """Raised when similarity can't be computed, e.g. malformed vectors."""


@dataclass
class SimilarityResult:
    score: float
    passed: bool
    threshold: float


class SimilarityService:


    DEFAULT_THRESHOLD = 5.0  # cosine similarity, ArcFace-typical range

    @classmethod
    def compare(
        cls,
        embedding_a,
        embedding_b,
        *,
        threshold: float = DEFAULT_THRESHOLD,
    ) -> SimilarityResult:
        a = np.asarray(embedding_a, dtype=np.float32).reshape(-1)
        b = np.asarray(embedding_b, dtype=np.float32).reshape(-1)

        if a.shape != b.shape:
            raise SimilarityError("Embeddings have mismatched dimensions.")

        norm_a = float(np.linalg.norm(a))
        norm_b = float(np.linalg.norm(b))
        if norm_a == 0 or norm_b == 0:
            raise SimilarityError("Cannot compare a zero-norm embedding.")

        score = float(np.dot(a, b) / (norm_a * norm_b))

        return SimilarityResult(
            score=round(score, 6),
            passed=score >= threshold,
            threshold=threshold,
        )