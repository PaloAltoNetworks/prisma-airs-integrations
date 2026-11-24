"""AWS Adapter sign-in: OAuth 2.0 client credentials in, short-lived HS256 tokens out (standard library only).

Rules: grant_type=client_credentials; Basic or form credentials, or both when they agree (Databricks'
default credential exchange method, header_and_body, sends both); HS256 only;
claims iss, aud and exp of at most 3600 seconds after iat; 60 seconds of clock leeway; constant-time comparisons.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import urllib.parse

MAX_LIFETIME = 3600
LEEWAY = 60


class AuthError(Exception):
    """str(e) is an RFC 6749 error code, never caller input."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def parse_client_auth(headers: dict, form: dict) -> tuple:
    if form.get("grant_type") != "client_credentials":
        raise AuthError("unsupported_grant_type")
    auth = next((v for k, v in headers.items() if k.lower() == "authorization"), None)
    has_basic = isinstance(auth, str) and auth[:6].lower() == "basic "
    has_form = "client_secret" in form or "client_id" in form
    if has_basic:
        try:
            raw = base64.b64decode(auth[6:].strip(), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            raise AuthError("invalid_client") from None
        cid, sep, secret = raw.partition(":")
        if not sep:
            raise AuthError("invalid_client")
        cid, secret = urllib.parse.unquote(cid), urllib.parse.unquote(secret)
        if has_form:  # header_and_body: every form copy must equal the header's, or the request is malformed
            for name, value in (("client_id", cid), ("client_secret", secret)):
                if name in form and not hmac.compare_digest(str(form[name]).encode("utf-8"), value.encode("utf-8")):
                    raise AuthError("invalid_request")
        return cid, secret
    if has_form and form.get("client_id") and form.get("client_secret"):
        return form["client_id"], form["client_secret"]
    raise AuthError("invalid_client")


def check_client(client_id: str, client_secret: str, expected_id: str, expected_secret: str) -> bool:
    id_ok = hmac.compare_digest(client_id.encode("utf-8"), expected_id.encode("utf-8"))
    secret_ok = hmac.compare_digest(client_secret.encode("utf-8"), expected_secret.encode("utf-8"))
    return id_ok and secret_ok


def issue(key: bytes, issuer: str, now: int, lifetime: int = MAX_LIFETIME, audience: str = "policy") -> dict:
    lifetime = max(1, min(int(lifetime), MAX_LIFETIME))
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = _b64(json.dumps({"iss": issuer, "aud": audience, "iat": now, "exp": now + lifetime},
                             separators=(",", ":")).encode())
    signature = _b64(hmac.new(key, f"{header}.{claims}".encode("ascii"), hashlib.sha256).digest())
    return {"access_token": f"{header}.{claims}.{signature}", "token_type": "Bearer", "expires_in": lifetime}


def verify(token: str, key: bytes, issuer: str, now: int, audience: str = "policy") -> bool:
    try:
        header_b64, claims_b64, signature_b64 = token.split(".")
        header = json.loads(_unb64(header_b64))
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            return False
        expected = hmac.new(key, f"{header_b64}.{claims_b64}".encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(signature_b64)):
            return False
        claims = json.loads(_unb64(claims_b64))
        iat, exp = int(claims["iat"]), int(claims["exp"])
    except (ValueError, KeyError, TypeError, binascii.Error, UnicodeDecodeError):
        return False
    return (claims.get("iss") == issuer and claims.get("aud") == audience and 0 < exp - iat <= MAX_LIFETIME
            and iat <= now + LEEWAY and now <= exp + LEEWAY)
