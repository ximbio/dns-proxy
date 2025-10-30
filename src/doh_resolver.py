import base64
import binascii

from fastapi import FastAPI, HTTPException, Response, Request, status
from loguru import logger
import uvicorn

from src.resolver import Resolver
from src.config import settings

app = FastAPI()

DNS_CT = "application/dns-message"

def decode_b64(s: str) -> bytes:
    s = s.strip() + "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s.encode("ascii"))
    except (binascii.Error, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 dns query."
        )


@app.get("/dns-query")
async def get_query(dns: str):
    query = decode_b64(dns)
    response = await app.state.resolver.resolve(query)

    return Response(response, media_type=DNS_CT)


@app.post("/dns-query")
async def post_query(request: Request):
    content_type = request.headers.get("content-type", "").split(";")[0].lower()

    if content_type != DNS_CT:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detial=f"Content-Type must be {DNS_CT}"
        )

    query = await request.body()
    response = await app.state.resolver.resolve(query)

    return Response(response, media_type=DNS_CT)


async def run_doh(resolver: Resolver):
    logger.info(F"Starting DoH resolver at {settings.DOH_HOST}:{settings.DOH_PORT}...")

    app.state.resolver = resolver

    server = uvicorn.Server(
        uvicorn.Config(
            app=app,
            host=settings.DOH_HOST,
            port=settings.DOH_PORT,
            log_level="error"
        )
    )
    
    await server.serve()
