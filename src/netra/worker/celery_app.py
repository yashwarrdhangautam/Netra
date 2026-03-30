"""Celery worker configuration with Beat scheduler."""
from celery import Celery
from celery.schedules import crontab

from netra.core.config import settings

celery_app = Celery(
    "netra",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    task_soft_time_limit=3600,
    task_time_limit=3700,
    broker_connection_retry_on_startup=True,
    result_expires=3600,
)

# Celery Beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    "cleanup-expired-tokens": {
        "task": "netra.worker.tasks.cleanup_expired_tokens",
        "schedule": crontab(hour=0, minute=0),  # Daily at midnight
    },
    "generate-compliance-reports": {
        "task": "netra.worker.tasks.generate_compliance_reports",
        "schedule": crontab(day_of_week=0, hour=2, minute=0),  # Weekly Sunday 2am
    },
}