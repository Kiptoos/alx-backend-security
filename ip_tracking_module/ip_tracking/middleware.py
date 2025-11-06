
import logging
from datetime import timedelta

import requests
from django.http import HttpResponseForbidden
from django.core.cache import cache

from .models import RequestLog, BlockedIP

logger = logging.getLogger(__name__)


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def geolocate_ip(ip):
    if not ip:
        return None, None

    cache_key = f"geo:{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached.get("country"), cached.get("city")

    country = None
    city = None

    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            country = data.get("country_name")
            city = data.get("city")
    except Exception as exc:
        logger.warning("Geolocation lookup failed for %s: %s", ip, exc)

    cache.set(cache_key, {"country": country, "city": city}, timeout=int(timedelta(hours=24).total_seconds()))
    return country, city


class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = get_client_ip(request)

        if ip and BlockedIP.objects.filter(ip_address=ip).exists():
            logger.info("Blocked request from blacklisted IP %s", ip)
            return HttpResponseForbidden("Forbidden: Your IP has been blocked.")

        response = self.get_response(request)

        try:
            country, city = geolocate_ip(ip)
            RequestLog.objects.create(
                ip_address=ip or "",
                path=request.path,
                country=country,
                city=city,
            )
        except Exception as exc:
            logger.error("Failed to log request for IP %s: %s", ip, exc)

        return response
