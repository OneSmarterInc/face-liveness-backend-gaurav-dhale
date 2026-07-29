from __future__ import annotations

import logging
from typing import Any, Dict, Optional

app_logger = logging.getLogger("app")
security_logger = logging.getLogger("security")


class AuditService:

    @staticmethod
    def registration_succeeded(*, account_id: int, embedding_id: int, quality: Dict[str, Any]) -> None:
        app_logger.info(
            "Face registration succeeded",
            extra={"account": account_id, "embedding_id": embedding_id, "quality": quality},
        )

    @staticmethod
    def registration_failed(*, account_id: int, reason: str) -> None:
        security_logger.warning(
            "Face registration failed",
            extra={"account": account_id, "reason": reason},
        )

    @staticmethod
    def verification_attempt(*, account_id: int, passed: bool, score: Optional[float], reason: str) -> None:
        logger = app_logger if passed else security_logger
        level = logging.INFO if passed else logging.WARNING
        logger.log(
            level,
            "Face verification attempted",
            extra={"account": account_id, "passed": passed, "score": score, "reason": reason},
        )