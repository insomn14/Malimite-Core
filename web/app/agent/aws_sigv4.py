"""Minimal AWS Signature Version 4 request signer — stdlib only (hashlib/hmac), no botocore.

Scoped to exactly what chat_step()'s bedrock branch needs: signing one
bedrock-runtime InvokeModelWithResponseStream POST request. Not a general-purpose SDK
replacement — e.g. no support for query-string signing, chunked payload signing, or STS
session tokens (the Config tab only collects a static access key id/secret pair).

Reference: https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
"""
import datetime
import hashlib
import hmac
from urllib.parse import quote


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    return _sign(k_service, "aws4_request")


def sign_request(*, method: str, url_path: str, region: str, service: str,
                 access_key_id: str, secret_access_key: str, host: str,
                 body: bytes, extra_headers: dict[str, str]) -> dict[str, str]:
    """Returns the full header dict (including Authorization) for one signed request.

    extra_headers are merged into the canonical request as-is (lowercased by the caller's
    convention here) — pass anything the service itself requires signed, e.g.
    "accept": "application/vnd.amazon.eventstream" for Bedrock's streaming InvokeModel.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    payload_hash = hashlib.sha256(body).hexdigest()

    headers = {"host": host, "x-amz-date": amz_date, **{k.lower(): v for k, v in extra_headers.items()}}
    signed_header_names = sorted(headers.keys())
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in signed_header_names)
    signed_headers = ";".join(signed_header_names)

    canonical_uri = quote(url_path, safe="/-_.~")
    canonical_request = "\n".join([
        method, canonical_uri, "", canonical_headers, signed_headers, payload_hash,
    ])

    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])

    signing_key = _signing_key(secret_access_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return {**{k: v for k, v in extra_headers.items()}, "Host": host,
            "X-Amz-Date": amz_date, "Authorization": authorization}
