from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class AntiAbuseLimits:
    max_active_sessions: int = 1
    cooldown_minutes: int = 15
    max_requests_per_day: int = 5
    max_duration_minutes: int = 120


@dataclass(slots=True)
class SecurityPolicies:
    blocked_users: set[str]
    anti_abuse: AntiAbuseLimits


@dataclass(slots=True)
class OperatorSettings:
    db_path: Path
    policies_configmap_name: str
    request_namespace: str


DEFAULT_POLICIES = SecurityPolicies(
    blocked_users=set(),
    anti_abuse=AntiAbuseLimits(),
)


def load_settings() -> OperatorSettings:
    return OperatorSettings(
        db_path=Path(os.getenv("JIT_AUDIT_DB_PATH", "/data/jit_audit.db")),
        policies_configmap_name=os.getenv("JIT_POLICIES_CONFIGMAP", "jit-security-policies"),
        request_namespace=os.getenv("JIT_REQUEST_NAMESPACE", "default"),
    )


def parse_policies(config_map_data: dict[str, str] | None) -> SecurityPolicies:
    if not config_map_data:
        return DEFAULT_POLICIES

    blocked_users_raw = config_map_data.get("blockedUsers.json", "[]")
    anti_abuse_raw = config_map_data.get("antiAbuse.json", "{}")

    try:
        blocked_users = set(json.loads(blocked_users_raw))
    except json.JSONDecodeError:
        blocked_users = set()

    try:
        anti_abuse_data: dict[str, Any] = json.loads(anti_abuse_raw)
    except json.JSONDecodeError:
        anti_abuse_data = {}

    return SecurityPolicies(
        blocked_users=blocked_users,
        anti_abuse=AntiAbuseLimits(
            max_active_sessions=int(anti_abuse_data.get("maxActiveSessions", 1)),
            cooldown_minutes=int(anti_abuse_data.get("cooldownMinutes", 15)),
            max_requests_per_day=int(anti_abuse_data.get("maxRequestsPerDay", 5)),
            max_duration_minutes=int(anti_abuse_data.get("maxDurationMinutes", 120)),
        ),
    )
