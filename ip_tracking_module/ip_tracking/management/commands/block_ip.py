from django.core.management.base import BaseCommand
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = "Add an IP address to the blacklist."

    def add_arguments(self, parser):
        parser.add_argument("ip_address", type=str, help="IP address to block")
        parser.add_argument("--reason", type=str, default="", help="Optional reason for blocking this IP")

    def handle(self, *args, **options):
        ip_address = options["ip_address"]
        reason = options["reason"]
        obj, created = BlockedIP.objects.get_or_create(ip_address=ip_address, defaults={"reason": reason})
        if created:
            self.stdout.write(self.style.SUCCESS(f"Successfully blocked IP {ip_address}"))
        else:
            if reason and obj.reason != reason:
                obj.reason = reason
                obj.save()
            self.stdout.write(self.style.WARNING(f"IP {ip_address} was already blocked."))
