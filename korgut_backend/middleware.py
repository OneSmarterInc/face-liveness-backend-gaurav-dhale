import time
import logging

logger = logging.getLogger("app")


class RequestLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start = time.time()

        response = self.get_response(request)

        duration = round(time.time() - start, 3)

        logger.info(
            "API request",
            extra={
                "path": request.path,
                "method": request.method,
                "status": response.status_code,
                "duration": duration,
                "ip": self.get_client_ip(request),
                "user": getattr(request.user, "id", "anonymous"),
            },
        )

        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")