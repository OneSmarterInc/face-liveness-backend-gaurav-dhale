from __future__ import annotations


class IdentityVerificationError(Exception):
    """
    Base exception for every error raised by a verification pipeline stage.

    Every stage-specific exception (SessionValidationError,
    TelemetryValidationError, ChallengeValidationError, etc.) should
    inherit from this class instead of the bare `Exception`.

    This lets the pipeline catch a single exception type:

        except IdentityVerificationError:

    ...instead of needing to import and list every stage's exception
    class individually. Adding a new stage with its own exception type
    no longer requires touching the pipeline's except clause, as long
    as that exception subclasses IdentityVerificationError.
    """

    pass
