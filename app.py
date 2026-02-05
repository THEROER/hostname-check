import logging

from litestar import Litestar, Request, get

logger = logging.getLogger("hostname-check")


async def log_hostname(request: Request) -> None:
    host_header = request.headers.get("host")
    x_forwarded_host = request.headers.get("x-forwarded-host")
    x_forwarded_proto = request.headers.get("x-forwarded-proto")
    x_forwarded_port = request.headers.get("x-forwarded-port")
    x_real_ip = request.headers.get("x-real-ip")
    forwarded = request.headers.get("forwarded")

    logger.info(
        "host_header=%s x_forwarded_host=%s x_forwarded_proto=%s x_forwarded_port=%s x_real_ip=%s forwarded=%s base_url=%s url=%s client=%s",
        host_header,
        x_forwarded_host,
        x_forwarded_proto,
        x_forwarded_port,
        x_real_ip,
        forwarded,
        request.base_url,
        request.url,
        request.client,
    )


@get("/")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@get("/headers")
async def headers(request: Request) -> dict[str, str]:
    return dict(request.headers)


logging.basicConfig(level=logging.INFO)

app = Litestar(route_handlers=[health, headers], before_request=log_hostname)
