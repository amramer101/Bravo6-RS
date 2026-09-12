#!/usr/bin/env python3
"""
DEFERRED (2026-09-12): moved out of src/report/ -- not part of the active
Report Function. See future-work/auth/README.md for why and how to bring
it back. This directory's report_function_auth_gate.py has the
ownership-check logic that used to wrap handle_status_request()/
handle_result_request() and call into this module. Code below is
unmodified from its last active version.
=====================================================================

Bravo6 Report Function -- JWT Validation (Microsoft Entra External ID)
=====================================================================
Deliberate duplicate of src/api/auth.py, not an import from it: each
Function App (api, worker, report) is deployed as its own independent
zip package (see src/api/function_app.py's comment on why its own
cross-package `from main_scanner import ...` only resolves in a repo
checkout, never in a real deployed package). Every functional line
(imports, constants, AuthenticatedUser, AuthError, build_jwks_client,
extract_bearer_token, validate_jwt) is identical to src/api/auth.py --
only docstrings/comments/the logger name are reworded for this module's
context, so this is not byte-for-byte. Report validates tokens issued by
the same Entra External ID (CIAM) tenant the API Gateway does, against
the same audience (the SPA app registration), so the validation logic
itself must be identical -- vendoring the file is how this project
already handles that constraint elsewhere, not a new pattern introduced
here.

Validates real JWTs: signature, expiry, issuer, and audience, all
checked -- any failure raises AuthError and the caller must return 401
without doing anything else (no Cosmos DB read, no ownership check).
"""
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

import jwt
from jwt import PyJWKClient

logger = logging.getLogger("Bravo6-Report.auth")

# PyJWKClient's own signing-key cache lifespan. Same value as src/api/auth.py
# for the same reasoning: long enough that a burst of requests doesn't
# refetch the JWKS document every time, short enough that a key rotation on
# the tenant's side is picked up within an hour rather than requiring a
# redeploy.
ENTRA_JWKS_CACHE_SECONDS = 3600


@dataclass(frozen=True)
class AuthenticatedUser:
    """subject is the stable per-user identifier (JWT "sub" claim) that
    the ownership check below compares against a scan document's
    user_id field."""
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
    between. Tests use a fake PyJWKClient subclass instead so they never
    hit the network (see test_report_function.py's _StaticJWKSClient)."""
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
