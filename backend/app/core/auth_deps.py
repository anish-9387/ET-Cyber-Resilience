"""Authentication dependencies for privileged endpoints.

The project had JWT issuance (`/auth/login`) but no dependency that consumed a
token, so no endpoint was actually protected. In particular, response approval
accepted a caller-supplied `approved_by` string, which meant a red-risk
containment action could be requested and self-approved in a single
unauthenticated call.

`require_principal` resolves the bearer token to a real principal. Approval
endpoints must use it rather than trusting a name in the request body.
"""

from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.security import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)


async def require_principal(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Dict[str, Any]:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "This action requires an authenticated approver. "
                "Obtain a token from POST /api/v1/auth/login and send it as "
                "'Authorization: Bearer <token>'."
            ),
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    subject = payload.get("username") or payload.get("sub")
    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token carries no subject",
        )

    return {
        "username": subject,
        "roles": payload.get("roles", []),
        "token_payload": payload,
    }


async def require_approver(
    principal: Dict[str, Any] = Depends(require_principal),
) -> Dict[str, Any]:
    """Principal permitted to approve a gated containment action.

    When `HUMAN_APPROVAL_REQUIRED` is set, approval is restricted to accounts
    holding an explicit role. An operator who can *request* an action must not
    automatically be able to *approve* it.
    """
    if not settings.HUMAN_APPROVAL_REQUIRED:
        return principal

    allowed = {"approver", "soc_lead", "ciso", "admin"}
    roles = {str(r).lower() for r in principal.get("roles", [])}
    if not roles & allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Account '{principal['username']}' is not authorised to approve "
                f"containment actions. Required role: one of {sorted(allowed)}."
            ),
        )
    return principal
