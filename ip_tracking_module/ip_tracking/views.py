
from django.http import HttpResponse, HttpResponseTooManyRequests
from django.views.decorators.csrf import csrf_exempt
from ratelimit.core import is_ratelimited


@csrf_exempt
def login_view(request):
    if request.method != "POST":
        return HttpResponse("Login endpoint (POST only).")

    rate = "10/m" if request.user.is_authenticated else "5/m"

    limited = is_ratelimited(
        request=request,
        group="login",
        key="ip",
        rate=rate,
        method=["POST"],
        increment=True,
    )

    if limited:
        return HttpResponseTooManyRequests("Too many login attempts. Please try later.")

    return HttpResponse("Login attempt processed.")
