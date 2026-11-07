"""Minimal reader for AWS's `application/vnd.amazon.eventstream` framing.

Bedrock Runtime's InvokeModelWithResponseStream does not use plain SSE (`data: ...\\n\\n`
lines) like Anthropic/OpenAI's APIs — each event is a self-describing binary frame:

    total_length(4) | header_length(4) | prelude_crc(4)
    headers (header_length bytes, each: name_len(1) name utf8 | type(1)=7 | value_len(2) value utf8)
    payload (total_length - header_length - 16 bytes)
    message_crc(4)

For Bedrock's chat-completions use, the only header worth reading is `:event-type`; the
payload is itself a JSON object with a base64 `bytes` field holding the actual
Anthropic-Messages-API-shaped chunk — see chat_step()'s bedrock branch for how that's unwrapped.
Checksums are not verified: payload integrity is still protected end-to-end by TLS, and a
corrupt frame simply fails the outer json.loads()/base64 decode instead of silently continuing.
"""
import struct
from typing import AsyncIterator, Optional

_PRELUDE_LEN = 8  # total_length + header_length, before the prelude's own crc


def _parse_headers(buf: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    i = 0
    while i < len(buf):
        name_len = buf[i]
        i += 1
        name = buf[i:i + name_len].decode("utf-8")
        i += name_len
        value_type = buf[i]
        i += 1
        if value_type == 7:  # string
            value_len = struct.unpack(">H", buf[i:i + 2])[0]
            i += 2
            value = buf[i:i + value_len].decode("utf-8")
            i += value_len
        else:
            # Only string-typed headers are used by Bedrock's event-stream responses in
            # practice; anything else is skipped rather than guessed at.
            break
        headers[name] = value
    return headers


async def iter_events(chunks: AsyncIterator[bytes]) -> AsyncIterator[tuple[dict[str, str], bytes]]:
    """Yields (headers, payload_bytes) for each complete frame, buffering across chunk
    boundaries (httpx's aiter_bytes() has no guarantee a frame arrives in one piece)."""
    buf = bytearray()
    async for chunk in chunks:
        buf.extend(chunk)
        while True:
            if len(buf) < _PRELUDE_LEN:
                break
            total_length, header_length = struct.unpack(">II", bytes(buf[:_PRELUDE_LEN]))
            if len(buf) < total_length:
                break  # frame not fully buffered yet
            frame = bytes(buf[:total_length])
            del buf[:total_length]
            headers_start = _PRELUDE_LEN + 4  # + prelude_crc
            headers_end = headers_start + header_length
            payload_end = total_length - 4  # - message_crc
            headers = _parse_headers(frame[headers_start:headers_end])
            payload = frame[headers_end:payload_end]
            yield headers, payload
