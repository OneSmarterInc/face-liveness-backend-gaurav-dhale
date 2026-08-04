import logging
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = Path(BASE_DIR) / "logs"
LOG_DIR.mkdir(exist_ok=True)


class DefaultLogFieldsFilter(logging.Filter):
  
    defaults = {"path": "-", "method": "-", "status": "-", "duration": "-", "ip": "-", "user": "-"}

    def filter(self, record):
        for key, value in self.defaults.items():
            if not hasattr(record, key):
                setattr(record, key, value)
        return True


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,

    "filters": {
        "default_log_fields": {
            "()": "korgut_backend.base.DefaultLogFieldsFilter",
        },
    },

    "formatters": {
        "verbose": {
            "format": "[{levelname}] {asctime} {name} {message} | "
                    "path={path} method={method} status={status} "
                    "duration={duration}s ip={ip} user={user}",
            "style": "{",
        },

        "simple": {
            "format": "[{levelname}] {message}",
            "style": "{",
        },

        "server": {
            "format": "{asctime} {levelname} {filename}:{lineno} {message}",
            "style": "{",
        },
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
        },

        "file_app": {
            "level": "INFO",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "app.log",
            "maxBytes": 5 * 1024 * 1024,  # 5MB
            "backupCount": 5,
            "formatter": "verbose",
            "filters": ["default_log_fields"],
        },

        "file_security": {
            "level": "WARNING",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "security.log",
            "maxBytes": 5 * 1024 * 1024,
            "backupCount": 10,
            "formatter": "verbose",
            "filters": ["default_log_fields"],
        },

        "file_errors": {
            "level": "ERROR",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "errors.log",
            "maxBytes": 10 * 1024 * 1024,
            "backupCount": 10,
            "formatter": "server",
        },

        "file_server": {
            "level": "INFO",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "server.log",
            "maxBytes": 5 * 1024 * 1024,
            "backupCount": 5,
            "formatter": "server",
        },
    },

    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },

        "django.security": {
            "handlers": ["file_security"],
            "level": "WARNING",
            "propagate": False,
        },

        "app": {
            "handlers": ["file_app"],
            "level": "INFO",
            "propagate": False,
        },

        "security": {
            "handlers": ["file_security"],
            "level": "WARNING",
            "propagate": False,
        },

        "errors": {
            "handlers": ["file_errors"],
            "level": "ERROR",
            "propagate": False,
        },

        "server": {                 
            "handlers": ["file_server"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
