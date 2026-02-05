import asyncio
import logging
import os
import struct

LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "3000"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("hostname-check")


async def read_varint(reader):
    num = 0
    raw = bytearray()
    for i in range(5):
        b = await reader.readexactly(1)
        raw += b
        val = b[0]
        num |= (val & 0x7F) << (7 * i)
        if not (val & 0x80):
            return num, bytes(raw)
    raise ValueError("VarInt too long")


def read_varint_buf(buf, idx):
    num = 0
    for i in range(5):
        if idx >= len(buf):
            raise ValueError("VarInt truncated")
        b = buf[idx]
        idx += 1
        num |= (b & 0x7F) << (7 * i)
        if not (b & 0x80):
            return num, idx
    raise ValueError("VarInt too long")


def parse_handshake(payload):
    idx = 0
    packet_id, idx = read_varint_buf(payload, idx)
    if packet_id != 0:
        return None
    protocol_version, idx = read_varint_buf(payload, idx)
    host_len, idx = read_varint_buf(payload, idx)
    host = payload[idx : idx + host_len].decode("utf-8", "replace")
    idx += host_len
    port = struct.unpack(">H", payload[idx : idx + 2])[0]
    idx += 2
    next_state, idx = read_varint_buf(payload, idx)
    return protocol_version, host, port, next_state


async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername")
    try:
        length, _length_bytes = await read_varint(reader)
        payload = await reader.readexactly(length)

        info = parse_handshake(payload)
        if info:
            protocol_version, host, port, next_state = info
            host_parts = host.split("\x00")
            host_main = host_parts[0] if host_parts else host
            extra = host_parts[1:] if len(host_parts) > 1 else []
            raw_host_display = host.encode("unicode_escape").decode("ascii")
            logger.info(
                "client=%s host=%s raw_host=%s extra_fields=%s port=%s proto=%s next_state=%s",
                peer,
                host_main,
                raw_host_display,
                extra,
                port,
                protocol_version,
                next_state,
            )
        else:
            logger.info("client=%s first_packet_not_handshake", peer)
    except Exception as exc:
        logger.exception("client=%s error=%s", peer, exc)
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    logger.info("Listening on %s:%s", LISTEN_HOST, LISTEN_PORT)
    async with server:
        await server.serve_forever()


asyncio.run(main())
