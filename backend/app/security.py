"""Operator authentication for sensitive actions.

Lightweight API-key scheme: operators present ``X-Operator-Token`` and we
resolve it to an operator id via the ZEROTRACE_OPERATOR_KEYS setting. This
is intentionally simple (demo-appropriate) but is the single choke point
every sensitive endpoint goes through, so swapping in OAuth/SSO later only
touches this module.
"""
from __future__ import annotations

from fastapi import Header, HTTPException, status

from app.config import settings


def require_operator(x_operator_token: str | None = Header(default=None)) -> str:
    if not x_operator_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Operator-Token header; this action requires an authorized operator.",
        )
    operator_map = settings.operator_map()
    operator_id = operator_map.get(x_operator_token)
    if operator_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid operator token.",
        )
    return operator_id
