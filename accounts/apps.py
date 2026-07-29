import logging

from django.apps import AppConfig

server_logger = logging.getLogger("server")


class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "accounts"

    def ready(self):
        server_logger.info("accounts app ready")
