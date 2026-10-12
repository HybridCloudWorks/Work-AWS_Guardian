"""Cognito JWT authentication seam for the API control plane.

The API service (``api.ComplianceApi``) is framework-neutral and authorizes on
an :class:`~ccg.api.AuthenticatedPrincipal`. This module provides the seam that
turns an inbound bearer token into that principal, mapping verified Cognito
claims (``sub`` -> actor, ``cognito:groups`` -> roles) onto it.

Trust boundary / seam design
-----------------------------
Token verification is injected via the :class:`TokenVerifier` protocol so no
live JWKS fetch or key material is hardcoded here. There are two intended
implementations:

* **Production** (not in this file — it is a gate-0.2/live-AWS concern): a
  verifier that validates the **RS256 signature** of the JWT against the Cognito
  User Pool **JWKS** (``https://cognito-idp.<region>.amazonaws.com/<poolId>/.well-known/jwks.json``),
  and checks the standard claims — ``iss`` (matches the pool), ``aud``/``client_id``
  (matches the app client), ``token_use`` (``id`` or ``access`` as required),
  and ``exp``/``nbf`` (not expired, not stale). Any failure raises
  :class:`InvalidTokenError`. No boto3 or network call lives in this module.

* **Tests** (:class:`FakeTokenVerifier` below): a deterministic verifier seeded
  with known tokens -> claims, so authorization tests can exercise valid-claims
  and invalid-token paths without any crypto or network.

Fail-closed posture
--------------------
A missing/malformed ``Authorization`` header, an unverifiable token, or claims
that cannot be mapped to a non-empty actor all resolve to an *unauthenticated*
principal (``authenticated=False``) rather than raising at the HTTP boundary.
The service then rejects it with :class:`~ccg.api.UnauthorizedError`. This keeps
the HTTP adapter uniform (a 403 for every auth failure) and never fails open.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from .api import AuthenticatedPrincipal

#: Cognito group -> CCG role mapping. Groups the API does not recognise are
#: ignored (least privilege: an unknown group grants nothing).
_GROUP_TO_ROLE: Mapping[str, str] = {
    "CCGAdmin": "CCGAdmin",
    "CCGRemediator": "CCGRemediator",
    "CCGViewer": "CCGViewer",
}


class InvalidTokenError(Exception):
    """Raised by a :class:`TokenVerifier` when a token cannot be trusted."""


class TokenVerifier(Protocol):
    """Verifies a bearer token and returns its trusted claims.

    A production implementation validates the RS256 signature against the
    Cognito JWKS and checks ``iss``/``aud``/``token_use``/``exp``. On any
    failure it MUST raise :class:`InvalidTokenError` rather than returning
    partial or unverified claims.
    """

    def verify(self, token: str) -> Mapping[str, object]:
        ...


class PrincipalResolver:
    """Resolves an API Gateway event to an :class:`AuthenticatedPrincipal`.

    Extracts the bearer token from the ``Authorization`` header, delegates
    verification to the injected :class:`TokenVerifier`, and maps the verified
    claims onto a principal. Any failure yields an unauthenticated principal so
    the service fails closed.
    """

    def __init__(self, verifier: TokenVerifier) -> None:
        self._verifier = verifier

    def resolve(self, event: Mapping[str, object]) -> AuthenticatedPrincipal:
        token = self._bearer_token(event)
        if token is None:
            return _unauthenticated()
        try:
            claims = self._verifier.verify(token)
        except InvalidTokenError:
            return _unauthenticated()
        return self._principal_from_claims(claims)

    # callable form so it can be passed where a resolver callable is expected
    def __call__(self, event: Mapping[str, object]) -> AuthenticatedPrincipal:
        return self.resolve(event)

    @staticmethod
    def _bearer_token(event: Mapping[str, object]) -> str | None:
        headers = event.get("headers")
        if not isinstance(headers, Mapping):
            return None
        raw = headers.get("authorization") or headers.get("Authorization")
        if not isinstance(raw, str) or not raw.strip():
            return None
        value = raw.strip()
        if value.lower().startswith("bearer "):
            value = value[len("bearer ") :].strip()
        return value or None

    @staticmethod
    def _principal_from_claims(claims: Mapping[str, object]) -> AuthenticatedPrincipal:
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            return _unauthenticated()
        roles = _roles_from_groups(claims.get("cognito:groups"))
        return AuthenticatedPrincipal(
            actor=subject.strip(),
            roles=frozenset(roles),
            authenticated=True,
        )


def _roles_from_groups(groups: object) -> set[str]:
    if isinstance(groups, str):
        raw_groups: list[str] = [groups]
    elif isinstance(groups, (list, tuple)):
        raw_groups = [str(group) for group in groups]
    else:
        raw_groups = []
    return {_GROUP_TO_ROLE[group] for group in raw_groups if group in _GROUP_TO_ROLE}


def _unauthenticated() -> AuthenticatedPrincipal:
    # A placeholder actor keeps the contract's non-empty invariant; the
    # ``authenticated=False`` flag is what the service rejects on.
    return AuthenticatedPrincipal(actor="anonymous", roles=frozenset(), authenticated=False)


class FakeTokenVerifier(TokenVerifier):
    """Deterministic token verifier for tests (no crypto, no network).

    Seeded with a mapping of opaque token strings to the claims a real Cognito
    verifier would return after validating the signature and standard claims.
    An unknown token raises :class:`InvalidTokenError`, exactly as an invalid
    signature or expired token would in production.
    """

    def __init__(self, tokens: Mapping[str, Mapping[str, object]] | None = None) -> None:
        self._tokens: dict[str, Mapping[str, object]] = dict(tokens or {})

    def add(self, token: str, claims: Mapping[str, object]) -> None:
        self._tokens[token] = dict(claims)

    def verify(self, token: str) -> Mapping[str, object]:
        try:
            return self._tokens[token]
        except KeyError as exc:
            raise InvalidTokenError("token is unknown, expired, or has an invalid signature") from exc
