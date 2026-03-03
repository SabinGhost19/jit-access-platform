from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


@dataclass(slots=True)
class SessionRow:
    request_name: str
    namespace: str
    developer_id: str
    target_namespace: str
    status: str
    expires_at: str | None
    rolebinding_name: str | None


class AuditDB:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _init_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS jit_sessions (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  request_name TEXT NOT NULL,
                  request_namespace TEXT NOT NULL,
                  developer_id TEXT NOT NULL,
                  target_namespace TEXT NOT NULL,
                  requested_role TEXT NOT NULL,
                  requested_duration_minutes INTEGER NOT NULL,
                  effective_duration_minutes INTEGER NOT NULL,
                  reason TEXT NOT NULL,
                  status TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  expires_at TEXT,
                  rolebinding_name TEXT,
                  serviceaccount_name TEXT,
                  token_issued INTEGER NOT NULL DEFAULT 0,
                  UNIQUE(request_name, request_namespace)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  request_name TEXT,
                  request_namespace TEXT,
                  developer_id TEXT,
                  action TEXT NOT NULL,
                  status TEXT NOT NULL,
                  message TEXT NOT NULL,
                  created_at TEXT NOT NULL
                )
                """
            )

    def record_audit(
        self,
        *,
        request_name: str,
        request_namespace: str,
        developer_id: str,
        action: str,
        status: str,
        message: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_logs (
                  request_name, request_namespace, developer_id, action, status, message, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_name,
                    request_namespace,
                    developer_id,
                    action,
                    status,
                    message,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def upsert_session(
        self,
        *,
        request_name: str,
        request_namespace: str,
        developer_id: str,
        target_namespace: str,
        requested_role: str,
        requested_duration_minutes: int,
        effective_duration_minutes: int,
        reason: str,
        status: str,
        expires_at: str | None,
        rolebinding_name: str | None,
        serviceaccount_name: str | None,
        token_issued: bool,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO jit_sessions (
                  request_name, request_namespace, developer_id, target_namespace,
                  requested_role, requested_duration_minutes, effective_duration_minutes,
                  reason, status, created_at, expires_at, rolebinding_name,
                  serviceaccount_name, token_issued
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(request_name, request_namespace) DO UPDATE SET
                  status=excluded.status,
                  expires_at=excluded.expires_at,
                  rolebinding_name=excluded.rolebinding_name,
                  serviceaccount_name=excluded.serviceaccount_name,
                  token_issued=excluded.token_issued,
                  effective_duration_minutes=excluded.effective_duration_minutes
                """,
                (
                    request_name,
                    request_namespace,
                    developer_id,
                    target_namespace,
                    requested_role,
                    requested_duration_minutes,
                    effective_duration_minutes,
                    reason,
                    status,
                    datetime.now(timezone.utc).isoformat(),
                    expires_at,
                    rolebinding_name,
                    serviceaccount_name,
                    1 if token_issued else 0,
                ),
            )

    def active_sessions_count(self, developer_id: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM jit_sessions
                WHERE developer_id = ? AND status = 'ACTIVE'
                """,
                (developer_id,),
            ).fetchone()
            return int(row["cnt"]) if row else 0

    def last_ended_session_at(self, developer_id: str) -> datetime | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT expires_at
                FROM jit_sessions
                WHERE developer_id = ? AND status IN ('EXPIRED', 'REVOKED')
                ORDER BY expires_at DESC
                LIMIT 1
                """,
                (developer_id,),
            ).fetchone()
            if not row or not row["expires_at"]:
                return None
            return datetime.fromisoformat(row["expires_at"])

    def daily_requests_count(self, developer_id: str, day_iso_prefix: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM jit_sessions
                WHERE developer_id = ? AND created_at LIKE ?
                """,
                (developer_id, f"{day_iso_prefix}%"),
            ).fetchone()
            return int(row["cnt"]) if row else 0

    def mark_expired(self, request_name: str, request_namespace: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE jit_sessions
                SET status = 'EXPIRED'
                WHERE request_name = ? AND request_namespace = ?
                """,
                (request_name, request_namespace),
            )

    def mark_revoked(self, request_name: str, request_namespace: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE jit_sessions
                SET status = 'REVOKED'
                WHERE request_name = ? AND request_namespace = ?
                """,
                (request_name, request_namespace),
            )

    def list_active_rolebindings(self) -> list[SessionRow]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT request_name, request_namespace, developer_id, target_namespace,
                       status, expires_at, rolebinding_name
                FROM jit_sessions
                WHERE status = 'ACTIVE' AND rolebinding_name IS NOT NULL
                """
            ).fetchall()
            return [
                SessionRow(
                    request_name=row["request_name"],
                    namespace=row["request_namespace"],
                    developer_id=row["developer_id"],
                    target_namespace=row["target_namespace"],
                    status=row["status"],
                    expires_at=row["expires_at"],
                    rolebinding_name=row["rolebinding_name"],
                )
                for row in rows
            ]
