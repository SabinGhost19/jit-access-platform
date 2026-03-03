from __future__ import annotations

from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from kubernetes import client
from kubernetes.client.exceptions import ApiException
from pydantic import BaseModel

from .config import Settings, load_settings
from .db import BackendDB
from .security import (
    create_access_token,
    decode_access_token,
    load_k8s_incluster_or_local,
    read_admin_credentials,
)

app = FastAPI(title="JIT Admin API", version="0.1.0")
settings: Settings = load_settings()
db = BackendDB(settings.db_path)


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    accessToken: str
    tokenType: str = "bearer"


class RevokeResponse(BaseModel):
    status: str
    message: str


def _require_admin(auth_header: Annotated[str | None, Header(alias="Authorization")] = None) -> str:
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = auth_header.replace("Bearer ", "", 1)
    payload = decode_access_token(settings, token)
    if payload.get("scope") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient scope")
    return str(payload.get("sub"))


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> LoginResponse:
    admin_user, admin_password = read_admin_credentials(settings)
    if payload.username != admin_user or payload.password != admin_password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(settings, payload.username)
    return LoginResponse(accessToken=token)


@app.get("/api/dashboard")
def dashboard(_: str = Depends(_require_admin)) -> dict[str, int]:
    return db.dashboard_metrics()


@app.get("/api/sessions")
def sessions(_: str = Depends(_require_admin)) -> list[dict[str, str | None]]:
    rows = db.list_sessions()
    return [
        {
            "requestName": row.request_name,
            "requestNamespace": row.request_namespace,
            "identity": row.developer_id,
            "target": row.target_namespace,
            "reason": row.reason,
            "expiresAt": row.expires_at,
            "status": row.status,
        }
        for row in rows
    ]


@app.get("/api/audit")
def audit(query: str | None = None, _: str = Depends(_require_admin)) -> list[dict[str, str | int]]:
    rows = db.list_audit(query=query)
    return [
        {
            "id": row.id,
            "timestamp": row.created_at,
            "identity": row.developer_id,
            "action": row.action,
            "status": row.status,
            "message": row.message,
        }
        for row in rows
    ]


@app.post("/api/sessions/{request_namespace}/{request_name}/revoke", response_model=RevokeResponse)
def revoke_session(
    request_namespace: str,
    request_name: str,
    _: str = Depends(_require_admin),
) -> RevokeResponse:
    binding = db.get_active_binding(request_namespace=request_namespace, request_name=request_name)
    if not binding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active session not found")

    target_namespace, rolebinding_name, developer_id = binding

    load_k8s_incluster_or_local()
    rbac_api = client.RbacAuthorizationV1Api()
    try:
        rbac_api.delete_namespaced_role_binding(
            name=rolebinding_name,
            namespace=target_namespace,
        )
    except ApiException as exc:
        if exc.status != 404:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to revoke rolebinding: {exc.reason}",
            ) from exc

    db.mark_revoked(request_namespace=request_namespace, request_name=request_name)
    db.insert_audit(
        request_namespace=request_namespace,
        request_name=request_name,
        developer_id=developer_id,
        action="KILL_SWITCH_REVOKE",
        status="REVOKED",
        message="RoleBinding removed through API kill switch",
    )

    return RevokeResponse(
        status="REVOKED",
        message="RoleBinding removed and session marked as revoked",
    )
