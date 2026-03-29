"""JSON structured logging configuration."""
import logging
import sys
from typing import Any

import structlog
from structlog.types import Processor


def get_logger_config() -> dict[str, Any]:
    """Get the logging configuration."""
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processor": structlog.processors.JSONRenderer(),
                "foreign_pre_chain": [
                    structlog.stdlib.ExtraAdder(),
                    structlog.stdlib.add_log_level,
                    structlog.stdlib.add_logger_name,
                ],
            },
            "text": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processor": structlog.dev.ConsoleRenderer(),
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "stream": sys.stdout,
                "formatter": "json",
            },
        },
        "root": {
            "level": "DEBUG",
            "handlers": ["console"],
        },
        "loggers": {
            "netra": {
                "level": "DEBUG",
                "propagate": False,
            },
        },
    }


def setup_logging(log_format: str = "json", log_level: str = "INFO") -> None:
    """Configure structured logging for the application.

    Args:
        log_format: Output format ('json' or 'text')
        log_level: Minimum log level to display
    """
    # Configure structlog processors
    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.UnicodeDecoder(),
    ]

    if log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper())
        ),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure standard logging
    logging_config = get_logger_config()
    logging_config["handlers"]["console"]["formatter"] = log_format
    logging_config["root"]["level"] = log_level
    logging_config["loggers"]["netra"]["level"] = log_level

    logging.config.dictConfig(logging_config)


def get_logger(name: str = "netra") -> Any:
    """Get a structured logger instance.

    Args:
        name: Logger name (defaults to 'netra')

    Returns:
        A structlog logger instance
    """
    return structlog.get_logger(name)
