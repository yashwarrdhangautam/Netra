"""Celery beat schedule additions for NETRA-BB."""

from celery.schedules import crontab

BB_BEAT_SCHEDULE = {
    "bb-resync-all-active-programs": {
        "task": "netra.resync_all_active_programs",
        "schedule": crontab(hour=2, minute=0),
    },
    "bb-ingest-hacktivity-daily": {
        "task": "netra.ingest_hacktivity_daily",
        "schedule": crontab(hour=3, minute=0),
    },
    "bb-ingest-advisories-daily": {
        "task": "netra.ingest_advisories_daily",
        "schedule": crontab(hour=3, minute=20),
    },
    "bb-ingest-writeups-hourly": {
        "task": "netra.ingest_public_writeups",
        "schedule": crontab(minute=15),
    },
    "bb-ingest-public-signatures-daily": {
        "task": "netra.ingest_public_signatures",
        "schedule": crontab(hour=4, minute=0),
    },
    "reclaim-stale-scans": {
        "task": "netra.reclaim_stale_scans",
        "schedule": 300.0,
    },
    "bb-export-submissions-graphify": {
        "task": "netra.export_bugbounty_submissions",
        "schedule": crontab(hour=3, minute=0),
    },
}
