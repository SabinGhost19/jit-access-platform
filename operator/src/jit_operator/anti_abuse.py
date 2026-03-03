from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .audit_db import AuditDB
from .config import SecurityPolicies

_DURATION_PATTERN = re.compile(r"^(?P<value>\d+)(?P<unit>[mh])$")


@dataclass(slots=True)
class AntiAbuseDecision:
    approved: bool
    status: str
    message: str
    requested_duration_minutes: int
    effective_duration_minutes: int


class AntiAbuseEngine:
    def __init__(self, policies: SecurityPolicies, db: AuditDB) -> None:
        self.policies = policies
        self.db = db

    def evaluate(self, developer_id: str, duration: str) -> AntiAbuseDecision:
        requested_duration = parse_duration_minutes(duration)
        effective_duration = min(
            requested_duration,
            self.policies.anti_abuse.max_duration_minutes,
        )

        if developer_id in self.policies.blocked_users:
            return AntiAbuseDecision(
                approved=False,
                status="BLOCKED_BY_POLICY",
                message="User is blacklisted by security policy",
                requested_duration_minutes=requested_duration,
                effective_duration_minutes=effective_duration,
            )

        active_count = self.db.active_sessions_count(developer_id)
        if active_count >= self.policies.anti_abuse.max_active_sessions:
            return AntiAbuseDecision(
                approved=False,
                status="DENIED_CONCURRENT_LIMIT",
                message="Max active sessions limit reached",
                requested_duration_minutes=requested_duration,
                effective_duration_minutes=effective_duration,
            )

        last_ended = self.db.last_ended_session_at(developer_id)
        if last_ended is not None:
            cooldown_end = last_ended + timedelta(
                minutes=self.policies.anti_abuse.cooldown_minutes
            )
            if datetime.now(timezone.utc) < cooldown_end:
                return AntiAbuseDecision(
                    approved=False,
                    status="DENIED_COOLDOWN",
                    message="Cooldown period is active",
                    requested_duration_minutes=requested_duration,
                    effective_duration_minutes=effective_duration,
                )

        day_prefix = datetime.now(timezone.utc).date().isoformat()
        daily_count = self.db.daily_requests_count(developer_id, day_prefix)
        if daily_count >= self.policies.anti_abuse.max_requests_per_day:
            return AntiAbuseDecision(
                approved=False,
                status="DENIED_DAILY_QUOTA",
                message="Daily request quota exceeded",
                requested_duration_minutes=requested_duration,
                effective_duration_minutes=effective_duration,
            )

        capped_message = ""
        if requested_duration > effective_duration:
            capped_message = (
                f" Duration was hard-capped to {effective_duration} minutes by policy."
            )

        return AntiAbuseDecision(
            approved=True,
            status="APPROVED",
            message=f"Request approved.{capped_message}".strip(),
            requested_duration_minutes=requested_duration,
            effective_duration_minutes=effective_duration,
        )


def parse_duration_minutes(duration: str) -> int:
    match = _DURATION_PATTERN.match(duration.strip())
    if not match:
        raise ValueError("Invalid duration format. Use values like 30m or 2h")

    value = int(match.group("value"))
    unit = match.group("unit")

    if unit == "m":
        return value
    return value * 60
