#!/usr/bin/env python3
"""
Bravo6 API Gateway -- JWT Validation (Microsoft Entra External ID)
=====================================================================
Validates real JWTs issued by the project's Entra External ID (CIAM)
tenant: signature, expiry, issuer, and audience, all checked -- any
failure raises AuthError and the caller must return 401 without doing
anything else (no blocklist check, no quota check, no Cosmos DB write, no
enqueue).

JWKS is fetched via jwt.PyJWKClient, which caches signing keys for
`lifespan` seconds instead of refetching on every request (see
ENTRA_JWKS_CACHE_SECONDS). The client is passed into validate_jwt() as a
parameter specifically so tests can inject a fake one -- a PyJWKClient
subclass that overrides fetch_data() to return a static JWKS built from a
known test key pair -- and exercise valid/expired/malformed/wrong-
audience tokens without any real network call, the same mock-all-outcomes
pattern the OCSP fix used for test_04_ssl_tls.py.
"""
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

import jwt
from jwt import PyJWKClient

logger = logging.getLogger("Bravo6-Gateway.auth")

# PyJWKClient's own signing-key cache lifespan. Long enough that a burst
# of requests doesn't refetch the JWKS document every time; short enough
# that a key rotation on the tenant's side is picked up within an hour
# rather than requiring a redeploy. Entra rotates signing keys
# periodically but infrequently (no fixed published interval), so an
# hour is a reasonable middle ground, not a value derived from a
# documented rotation schedule.
ENTRA_JWKS_CACHE_SECONDS = 3600


@dataclass(frozen=True)
class AuthenticatedUser:
    """subject is the stable per-user identifier (JWT "sub" claim) that
    quota enforcement and the scan-job record's ownership field key off."""
    subject: str
    raw_claims: Dict[str, Any]


class AuthError(Exception):
    """Any JWT validation failure -- missing token, expired, bad
    signature, wrong issuer/audience, malformed. The message is safe to
    log; callers must not echo it back to the client beyond a generic
    401 (no detail on *why* validation failed, to avoid handing an
    attacker a token-forging oracle)."""


def build_jwks_client(jwks_uri: str) -> PyJWKClient:
    """Production JWKS client -- fetches over the network on first use
    (and again after ENTRA_JWKS_CACHE_SECONDS), caching by key id in
    between. This is the one function real request handling calls;
    tests use a fake PyJWKClient subclass instead (see
    test_api_gateway.py's _StaticJWKSClient) so they never hit the
    network."""
    return PyJWKClient(jwks_uri, cache_keys=True, lifespan=ENTRA_JWKS_CACHE_SECONDS)


def extract_bearer_token(authorization_header: Optional[str]) -> str:
    """Raises AuthError if the header is missing or not a Bearer token."""
    if not authorization_header:
        raise AuthError("missing Authorization header")
    parts = authorization_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise AuthError("Authorization header is not a Bearer token")
    return parts[1].strip()


def validate_jwt(
    token: str,
    jwks_client: PyJWKClient,
    issuer: str,
    audience: str,
) -> AuthenticatedUser:
    """Validate token's signature, expiry ("exp", checked by jwt.decode
    itself), issuer, and audience against the tenant's real values.
    Raises AuthError on ANY failure -- caller must treat this as an
    unconditional 401."""
    if not token:
        raise AuthError("missing token")

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as e:
        raise AuthError(f"token validation failed: {e}") from e
    except Exception as e:
        # JWKS fetch/connection failures, malformed-token parsing errors
        # before jwt even gets to signature checking, etc. -- still a 401,
        # not a 500: an unauthenticated caller should never be able to
        # distinguish "your token is bad" from "our auth backend hiccuped".
        raise AuthError(f"could not validate token: {e}") from e

    subject = claims.get("sub")
    if not subject:
        raise AuthError("token has no subject claim")

    return AuthenticatedUser(subject=subject, raw_claims=claims)
