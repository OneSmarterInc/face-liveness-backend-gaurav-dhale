import logging

from django.apps import AppConfig

server_logger = logging.getLogger("server")


class IdentityVerificationConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "identity_verification"

    def ready(self):
        server_logger.info("identity_verification app ready")
