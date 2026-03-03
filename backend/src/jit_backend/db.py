from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


@dataclass(slots=True)
class SessionSummary:
    request_name: str
    request_namespace: str
    developer_id: str
    target_namespace: str
    reason: str
    expires_at: str | None
    status: str


@dataclass(slots=True)
class AuditRow:
    id: int
    created_at: str
    developer_id: str
    action: str
    status: str
    message: str


class BackendDB:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def dashboard_metrics(self) -> dict[str, int]:
        with self._connect() as connection:
            active = connection.execute(
                "SELECT COUNT(*) AS c FROM jit_sessions WHERE status = 'ACTIVE'"
            ).fetchone()["c"]
            total = connection.execute("SELECT COUNT(*) AS c FROM jit_sessions").fetchone()["c"]
            abuse = connection.execute(
                """
                SELECT COUNT(*) AS c
                FROM audit_logs
                WHERE status LIKE 'DENIED_%' OR status = 'BLOCKED_BY_POLICY'
                """
            ).fetchone()["c"]
        return {
            "activeSessions": int(active),
            "totalRequests": int(total),
            "abuseAlerts": int(abuse),
        }

    def list_sessions(self) -> list[SessionSummary]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT request_name, request_namespace, developer_id, target_namespace,
                       reason, expires_at, status
                FROM jit_sessions
                ORDER BY created_at DESC
                """
            ).fetchall()
            return [
                SessionSummary(
                    request_name=row["request_name"],
                    request_namespace=row["request_namespace"],
                    developer_id=row["developer_id"],
                    target_namespace=row["target_namespace"],
                    reason=row["reason"],
                    expires_at=row["expires_at"],
                    status=row["status"],
                )
                for row in rows
            ]

    def list_audit(self, query: str | None = None) -> list[AuditRow]:
        with self._connect() as connection:
            if query:
                rows = connection.execute(
                    """
                    SELECT id, created_at, developer_id, action, status, message
                    FROM audit_logs
                    WHERE developer_id LIKE ? OR action LIKE ? OR message LIKE ?
                    ORDER BY created_at DESC
                    LIMIT 500
                    """,
                    (f"%{query}%", f"%{query}%", f"%{query}%"),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT id, created_at, developer_id, action, status, message
                    FROM audit_logs
                    ORDER BY created_at DESC
                    LIMIT 500
                    """
                ).fetchall()
            return [
                AuditRow(
                    id=int(row["id"]),
                    created_at=row["created_at"],
                    developer_id=row["developer_id"],
                    action=row["action"],
                    status=row["status"],
                    message=row["message"],
                )
                for row in rows
            ]

    def get_active_binding(
        self,
        request_namespace: str,
        request_name: str,
    ) -> tuple[str, str, str] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT target_namespace, rolebinding_name, developer_id
                FROM jit_sessions
                WHERE request_namespace = ? AND request_name = ? AND status = 'ACTIVE'
                """,
                (request_namespace, request_name),
            ).fetchone()
            if not row:
                return None
            return row["target_namespace"], row["rolebinding_name"], row["developer_id"]

    def mark_revoked(self, request_namespace: str, request_name: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE jit_sessions
                SET status = 'REVOKED', expires_at = ?
                WHERE request_namespace = ? AND request_name = ?
                """,
                (datetime.now(timezone.utc).isoformat(), request_namespace, request_name),
            )

    def insert_audit(
        self,
        request_namespace: str,
        request_name: str,
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
