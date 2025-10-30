import asyncio
import ssl
import struct
from functools import partial

from loguru import logger

from src.resolver import Resolver
from src.config import settings

def make_ssl_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_file, key_file)

    return ctx


async def handle_client(resolver: Resolver, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            hdr = await reader.readexactly(2)
            (length,) = struct.unpack("!H", hdr)
            query = await reader.readexactly(length)

            response = await resolver.resolve(query)
            
            writer.write(struct.pack("!H", len(response)) + response)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass 
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def run_dot(resolver: Resolver):
    logger.info(F"Starting DoT resolver at {settings.DOT_HOST}:{settings.DOT_PORT}...")

    server = await asyncio.start_server(
        partial(handle_client, resolver), 
        ssl=make_ssl_context(settings.DOT_CERT_FILE, settings.DOT_KEY_FILE),
        host=settings.DOT_HOST,
        port=settings.DOT_PORT
    )

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        pass
