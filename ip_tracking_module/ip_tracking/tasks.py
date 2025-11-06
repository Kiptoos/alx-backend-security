
from datetime import timedelta

from celery import shared_task
from django.utils import timezone
from django.db.models import Count

from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ["/admin", "/login"]


@shared_task
def detect_suspicious_ips():
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    recent_logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    high_volume = (
        recent_logs.values("ip_address")
        .annotate(request_count=Count("id"))
        .filter(request_count__gt=100)
    )

    for entry in high_volume:
        ip = entry["ip_address"]
        count = entry["request_count"]
        SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            reason=f"High volume: {count} requests in the last hour.",
        )

    sensitive_hits = recent_logs.filter(path__in=SENSITIVE_PATHS).values(
        "ip_address"
    ).distinct()

    for entry in sensitive_hits:
        ip = entry["ip_address"]
        SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            reason="Accessed sensitive paths (/admin or /login) in the last hour.",
        )

    return {
        "high_volume_count": high_volume.count(),
        "sensitive_hit_count": sensitive_hits.count(),
    }
