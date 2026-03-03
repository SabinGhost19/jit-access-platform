from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import HTTPException, status
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from .config import Settings


def load_k8s_incluster_or_local() -> None:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


def read_admin_credentials(settings: Settings) -> tuple[str, str]:
    load_k8s_incluster_or_local()
    core_api = client.CoreV1Api()
    try:
        secret = core_api.read_namespaced_secret(
            name=settings.admin_secret_name,
            namespace=settings.admin_secret_namespace,
        )
    except ApiException as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Admin auth secret unavailable: {exc.reason}",
        ) from exc

    data = secret.data or {}
    username_b64 = data.get("username")
    password_b64 = data.get("password")
    if not username_b64 or not password_b64:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Admin secret missing username/password keys",
        )

    username = base64.b64decode(username_b64).decode("utf-8")
    password = base64.b64decode(password_b64).decode("utf-8")
    return username, password


def create_access_token(settings: Settings, subject: str) -> str:
    expire_at = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload: dict[str, Any] = {
        "sub": subject,
        "exp": expire_at,
        "scope": "admin",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algo)


def decode_access_token(settings: Settings, token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algo])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from exc
