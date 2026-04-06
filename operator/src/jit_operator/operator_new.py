from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import kopf
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from jit_operator.anti_abuse import AntiAbuseEngine
from jit_operator.audit_db import AuditDB
from jit_operator.config import OperatorSettings, parse_policies, load_settings


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sanitize_name(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in value)[:40].strip("-")


def _load_policies(api: client.CoreV1Api, settings: OperatorSettings) -> Any:
    try:
        config_map = api.read_namespaced_config_map(
            name=settings.policies_configmap_name,
            namespace=settings.request_namespace,
        )
        return parse_policies(config_map.data)
    except ApiException:
        return parse_policies(None)


def _create_service_account(
    core_api: client.CoreV1Api,
    target_namespace: str,
    service_account_name: str,
) -> None:
    body = client.V1ServiceAccount(metadata=client.V1ObjectMeta(name=service_account_name))
    try:
        core_api.create_namespaced_service_account(namespace=target_namespace, body=body)
    except ApiException as error:
        if error.status != 409:
            raise


def _create_role_binding(
    rbac_api: client.RbacAuthorizationV1Api,
    target_namespace: str,
    rolebinding_name: str,
    service_account_name: str,
    requested_role: str,
) -> None:
    rolebinding = client.V1RoleBinding(
        metadata=client.V1ObjectMeta(name=rolebinding_name),
        role_ref=client.V1RoleRef(
            api_group="rbac.authorization.k8s.io",
            kind="ClusterRole",
            name=requested_role,
        ),
        subjects=[
            client.RbacV1Subject(
                kind="ServiceAccount",
                name=service_account_name,
                namespace=target_namespace,
            )
        ],
    )
    try:
        rbac_api.create_namespaced_role_binding(namespace=target_namespace, body=rolebinding)
    except ApiException as error:
        if error.status != 409:
            raise


def _issue_token(
    core_api: client.CoreV1Api,
    target_namespace: str,
    service_account_name: str,
    expiration_seconds: int,
) -> str:
    token_request = {
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": {
            "expirationSeconds": expiration_seconds,
        },
    }
    token = core_api.create_namespaced_service_account_token(
        name=service_account_name,
        namespace=target_namespace,
        body=token_request,
    )
    return token.status.token


def _delete_access_resources(
    core_api: client.CoreV1Api,
    rbac_api: client.RbacAuthorizationV1Api,
    target_namespace: str,
    service_account_name: str | None,
    rolebinding_name: str | None,
) -> None:
    if rolebinding_name:
        try:
            rbac_api.delete_namespaced_role_binding(
                name=rolebinding_name,
                namespace=target_namespace,
            )
        except ApiException as error:
            if error.status != 404:
                raise

    if service_account_name:
        try:
            core_api.delete_namespaced_service_account(
                name=service_account_name,
                namespace=target_namespace,
            )
        except ApiException as error:
            if error.status != 404:
                raise


@kopf.on.startup()
def startup_fn(**_: Any) -> None:
    config.load_incluster_config()


@kopf.on.create("devsecops.licenta.ro", "v1", "jitaccessrequests")
def on_jit_request_create(
    spec: dict[str, Any],
    status: dict[str, Any],
    name: str,
    namespace: str,
    patch: kopf.Patch,
    logger: kopf.Logger,
    **_: Any,
) -> None:
    if status.get("state") == "ACTIVE" and status.get("tokenIssued") is True:
        logger.info("Request %s is already active. Skipping duplicate create processing.", name)
        return

    settings = load_settings()
    core_api = client.CoreV1Api()
    rbac_api = client.RbacAuthorizationV1Api()
    db = AuditDB(settings.db_path)
    policies = _load_policies(core_api, settings)
    anti_abuse = AntiAbuseEngine(policies, db)

    developer_id = spec.get("developerId", "")
    target_namespace = spec.get("targetNamespace", "")
    requested_role = spec.get("requestedRole", "view")
    duration = spec.get("duration", "30m")
    reason = spec.get("reason", "")

    decision = anti_abuse.evaluate(developer_id=developer_id, duration=duration)

    if not decision.approved:
        patch.status["state"] = decision.status
        patch.status["message"] = decision.message
        patch.status["tokenIssued"] = False

        db.upsert_session(
            request_name=name,
            request_namespace=namespace,
            developer_id=developer_id,
            target_namespace=target_namespace,
            requested_role=requested_role,
            requested_duration_minutes=decision.requested_duration_minutes,
            effective_duration_minutes=decision.effective_duration_minutes,
            reason=reason,
            status=decision.status,
            expires_at=None,
            rolebinding_name=None,
            serviceaccount_name=None,
            token_issued=False,
        )
        db.record_audit(
            request_name=name,
            request_namespace=namespace,
            developer_id=developer_id,
            action="REQUEST_REJECTED",
            status=decision.status,
            message=decision.message,
        )
        logger.warning("Request %s rejected: %s", name, decision.message)
        return

    service_account_name = f"jit-{_sanitize_name(developer_id)}-{name}"[:63]
    rolebinding_name = f"jit-rb-{name}"[:63]
    expiration_seconds = decision.effective_duration_minutes * 60
    expires_at = _utc_now() + timedelta(seconds=expiration_seconds)

    _create_service_account(core_api, target_namespace, service_account_name)
    _create_role_binding(
        rbac_api,
        target_namespace,
        rolebinding_name,
        service_account_name,
        requested_role,
    )
    token = _issue_token(
        core_api,
        target_namespace,
        service_account_name,
        expiration_seconds,
    )

    patch.status["state"] = "ACTIVE"
    patch.status["message"] = decision.message
    patch.status["sessionId"] = f"{namespace}:{name}"
    patch.status["temporaryServiceAccount"] = service_account_name
    patch.status["roleBindingName"] = rolebinding_name
    patch.status["temporaryToken"] = token
    patch.status["expiresAt"] = expires_at.isoformat()
    patch.status["tokenIssued"] = True

    db.upsert_session(
        request_name=name,
        request_namespace=namespace,
        developer_id=developer_id,
        target_namespace=target_namespace,
        requested_role=requested_role,
        requested_duration_minutes=decision.requested_duration_minutes,
        effective_duration_minutes=decision.effective_duration_minutes,
        reason=reason,
        status="ACTIVE",
        expires_at=expires_at.isoformat(),
        rolebinding_name=rolebinding_name,
        serviceaccount_name=service_account_name,
        token_issued=True,
    )
    db.record_audit(
        request_name=name,
        request_namespace=namespace,
        developer_id=developer_id,
        action="REQUEST_APPROVED",
        status="ACTIVE",
        message=decision.message,
    )


@kopf.timer("devsecops.licenta.ro", "v1", "jitaccessrequests", interval=30.0)
def gc_expired_sessions(
    spec: dict[str, Any],
    status: dict[str, Any],
    name: str,
    namespace: str,
    patch: kopf.Patch,
    **_: Any,
) -> None:
    state = status.get("state")
    expires_at_raw = status.get("expiresAt")
    if state != "ACTIVE" or not expires_at_raw:
        return

    try:
        expires_at = datetime.fromisoformat(expires_at_raw)
    except ValueError:
        return

    if _utc_now() < expires_at:
        return

    target_namespace = spec.get("targetNamespace", "")
    service_account_name = status.get("temporaryServiceAccount")
    rolebinding_name = status.get("roleBindingName")

    core_api = client.CoreV1Api()
    rbac_api = client.RbacAuthorizationV1Api()
    settings = load_settings()
    db = AuditDB(settings.db_path)

    _delete_access_resources(
        core_api,
        rbac_api,
        target_namespace,
        service_account_name,
        rolebinding_name,
    )

    patch.status["state"] = "EXPIRED"
    patch.status["message"] = "Session expired and resources revoked"
    db.mark_expired(name, namespace)
    db.record_audit(
        request_name=name,
        request_namespace=namespace,
        developer_id=spec.get("developerId", ""),
        action="SESSION_EXPIRED",
        status="EXPIRED",
        message="RoleBinding and ServiceAccount removed by GC",
    )
